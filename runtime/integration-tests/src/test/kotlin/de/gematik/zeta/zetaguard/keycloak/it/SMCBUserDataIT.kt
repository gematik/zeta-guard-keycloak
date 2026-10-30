/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
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

import de.gematik.zeta.zetaguard.keycloak.commons.CRT_GEMATIK_LEAF_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.smcbTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SPREE_INTEGRITY_ENABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.lang.System.getenv
import org.hibernate.Hibernate
import org.keycloak.models.jpa.entities.CredentialEntity
import org.keycloak.models.jpa.entities.FederatedIdentityEntity
import org.keycloak.models.jpa.entities.UserAttributeEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.jpa.entities.UserRequiredActionEntity

class SMCBUserDataIT : ZetaGuardFunSpecIT() {
  private val itProviderEnabled = (getenv(ENV_SPREE_INTEGRITY_ENABLED) ?: "false").toBoolean()

  init {
    val nonce = createNonce()
    val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
    val smcbToken =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))

    test("Check stored user data attributes exist") {
      keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = jwt)

      val user = lookupUser(TELEMATIK_ID.toSpicyHash().lowercase())

      if (itProviderEnabled) { // Encrypted values
        user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_NAME }.value.shouldNotBeNull()
        user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_PROFESSION_OID }.value.shouldNotBeNull()
      } else {
        user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_NAME }.value shouldBe CRT_GEMATIK_LEAF_NAME
        user.attributes.first { it.name == ATTRIBUTE_SMCBUSER_PROFESSION_OID }.value shouldBe PROFESSION_OID
      }
    }
  }

  private fun lookupUser(userName: String): UserEntity {
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
}
