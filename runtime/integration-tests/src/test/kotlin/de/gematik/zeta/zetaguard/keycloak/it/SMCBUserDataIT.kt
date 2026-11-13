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
import de.gematik.zeta.zetaguard.keycloak.commons.CRT_GEMATIK_LEAF_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_LAST_ACCESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_COMMON_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_ORGANIZATION_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toLocalDateTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.spree.keycloak.commons.integrityProviderEnabled
import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.maps.shouldContainAll
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.hibernate.Hibernate
import org.keycloak.models.jpa.entities.CredentialEntity
import org.keycloak.models.jpa.entities.FederatedIdentityEntity
import org.keycloak.models.jpa.entities.UserAttributeEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.jpa.entities.UserRequiredActionEntity

class SMCBUserDataIT : ZetaGuardFunSpecIT() {

  init {
    val nonce = createNonce()
    val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
    val smcbToken =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            audiences = smcbTokenAudience,
            subject = smcb.telematikId,
            certificateChain = listOf(smcb.leafCertificate),
        )

    // A_26972-03: Telematik-ID, commonName, professionOID and organizationName of the SM(C)-B certificate are stored as user data
    // and issued as access-token claims (access-token.yaml, A_26589-01)
    test("Check stored user data attributes and access-token claims") {
      val now = currentTime().minusSeconds(1) // Due to truncation
      val accessToken = testExchangeToken(smcbToken, clientAssertion = jwt).second

      accessToken.subject shouldBe smcb.telematikId
      accessToken.otherClaims shouldContainAll
          mapOf(
              CLAIM_PROFESSION_OID to PROFESSION_OID,
              CLAIM_COMMON_NAME to smcb.leafCertificate.rawSubjectAttribute(BCStyle.CN),
              CLAIM_ORGANIZATION_NAME to smcb.leafCertificate.rawSubjectAttribute(BCStyle.O),
          )

      val user = lookupUser(smcb.telematikId.toSpicyHash().lowercase())
      val smcbAttributes =
          listOf(ATTRIBUTE_SMCBUSER_TELEMATIK_ID, ATTRIBUTE_SMCBUSER_NAME, ATTRIBUTE_SMCBUSER_PROFESSION_OID, ATTRIBUTE_SMCBUSER_ORGANISATION)

      if (integrityProviderEnabled) { // Encrypted values
        smcbAttributes.forEach { name -> user.attributes.first { it.name == name }.value.shouldNotBeNull() }
      } else {
        val stored = user.attributes.filter { it.name in smcbAttributes }.associate { it.name to it.value }

        stored shouldContainExactly
            mapOf(
                ATTRIBUTE_SMCBUSER_TELEMATIK_ID to smcb.telematikId,
                ATTRIBUTE_SMCBUSER_NAME to smcb.leafCertificate.rawSubjectAttribute(BCStyle.CN),
                ATTRIBUTE_SMCBUSER_PROFESSION_OID to PROFESSION_OID,
                ATTRIBUTE_SMCBUSER_ORGANISATION to CRT_GEMATIK_LEAF_ORGANISATION,
            )
        stored[ATTRIBUTE_SMCBUSER_NAME] shouldStartWith CRT_GEMATIK_LEAF_NAME
        user.attributes.first { it.name == ATTRIBUTE_USER_LAST_ACCESS }.value.toLocalDateTime() shouldBeAfter now
      }
    }
  }
}

/** The attribute value exactly as encoded in the certificate's subject, without any DN escaping. */
private fun X509Certificate.rawSubjectAttribute(identifier: ASN1ObjectIdentifier): String? =
    JcaX509CertificateHolder(this).subject.getRDNs(identifier).firstOrNull()?.first?.value?.let { (it as ASN1String).string }

fun lookupUser(userName: String): UserEntity {
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
