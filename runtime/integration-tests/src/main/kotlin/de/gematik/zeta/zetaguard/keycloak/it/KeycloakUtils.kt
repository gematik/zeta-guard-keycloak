/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import jakarta.ws.rs.core.Response.Status.CONFLICT
import jakarta.ws.rs.core.Response.Status.CREATED
import org.keycloak.admin.client.resource.UsersResource
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.RoleRepresentation
import org.keycloak.representations.idm.UserRepresentation

object KeycloakUtils {
  fun createUser(usersResource: UsersResource, userData: UserData, termsAccepted: Boolean = true) {
    val userRepresentation = createUser(userData)
    val userResponse = usersResource.create(userRepresentation)

    check(userResponse.statusInfo in listOf(CREATED, CONFLICT)) { "Invalid response ${userResponse.statusInfo}" }

    if (termsAccepted) {
      // Remove required actions, terms and conditions in particular
      val userId = usersResource.search(userData.userName)[0].id
      val userResource = usersResource[userId]
      userResource.update(createUser(userData).apply { id = userId })
    }
  }

  private fun createUser(userData: UserData) =
      UserRepresentation().apply {
        isEnabled = true
        firstName = userData.firstName.ifEmpty { "Perry" }
        lastName = userData.lastName.ifEmpty { "Rhodan" }
        email = userData.email
        isEmailVerified = true
        username = userData.userName
        requiredActions = listOf()
        attributes = mapOf("terms_and_conditions" to listOf("4711"))
        credentials =
            listOf(
                CredentialRepresentation().apply {
                  type = CredentialRepresentation.PASSWORD
                  value = userData.password
                }
            )
      }

  fun addRoles(
      userData: UserData,
      usersResource: UsersResource,
      clientId: String,
      realmRoles: List<RoleRepresentation>,
      clientRoles: List<RoleRepresentation>,
  ) {
    val users = usersResource.search(userData.userName)

    if (users.size == 1) {
      val user = users[0]
      val userResource = usersResource[user.id]

      if (realmRoles.isNotEmpty()) {
        userResource.roles().realmLevel().add(realmRoles)
      }

      if (clientRoles.isNotEmpty()) {
        userResource.roles().clientLevel(clientId).add(clientRoles)
      }
    } else {
      error("User not found ${userData.userName}")
    }
  }
}
