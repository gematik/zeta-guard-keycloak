/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.betriebsstaetteArzt
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.hibernate.Hibernate
import org.keycloak.models.jpa.entities.CredentialEntity
import org.keycloak.models.jpa.entities.FederatedIdentityEntity
import org.keycloak.models.jpa.entities.UserAttributeEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.jpa.entities.UserRequiredActionEntity

class SMCBUserDataIT : FunSpec() {
  init {
    val keycloakWebClient = KeycloakWebClient()
    val baseUri = keycloakWebClient.uriBuilder().build().toString()
    val realmUrl = keycloakWebClient.uriBuilder().realmUrl().toString()
    val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
    val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
    val smcbToken =
        smcbTokenGenerator.generateSMCBToken(
            subject = TELEMATIK_ID,
            nonceString = nonce,
            audiences = listOf(baseUri),
            certificateChain = listOf(leafCertificate),
        )

    test("Check stored user data") {
      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt)

      val user = lookupUser(TELEMATIK_ID)

      user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_NAME }.value shouldBe CRT_GEMATIK_LEAF_NAME
      user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_PROFESSION_OID }.value shouldBe betriebsstaetteArzt.id
    }
  }

  private fun lookupUser(@Suppress("SameParameterValue") userName: String): UserEntity {
    val entityClasses =
        arrayOf(
            UserEntity::class.java,
            UserAttributeEntity::class.java,
            UserRequiredActionEntity::class.java,
            CredentialEntity::class.java,
            FederatedIdentityEntity::class.java,
        )

    return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
      val userEntity =
          it.createEntityManager()
              .createQuery("SELECT u FROM UserEntity u WHERE u.username = :userName") //
              .setParameter("userName", userName)
              .singleResult as UserEntity

      userEntity.also { user -> Hibernate.initialize(user.attributes) } // Avoid LazyInitializationException
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
