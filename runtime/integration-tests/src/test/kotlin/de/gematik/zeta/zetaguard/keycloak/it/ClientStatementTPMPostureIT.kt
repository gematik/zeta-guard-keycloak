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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import de.gematik.zeta.zetaguard.keycloak.client_attestation.SIGNATURE_VALIDATION_FAILED
import de.gematik.zeta.zetaguard.keycloak.client_attestation.TPM_DESERIALIZATION_FAILED
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.subjectKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.clientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.reflect.full.declaredMemberProperties
import kotlin.reflect.jvm.isAccessible
import kotlin.reflect.jvm.javaField

class ClientStatementTPMPostureIT : ZetaGuardFunSpecIT() {
  init {
    test("Invalid attestation challenge") { invalidAttestationChallenge(PostureType.TPM) }

    test("Invalid TPM certificate/public key") {
      val nonce = createNonce()
      val invalidCertificate =
          CertificateGenerator(
                  subjectName = leafCertificate.subjectX500Principal.toString(),
                  subjectKeyPair = subjectKeyPair,
                  issuerName = leafCertificate.issuerX500Principal.toString(),
                  issuerKeyPair = subjectKeyPair,
                  isCA = false,
              )
              .buildCertificate()
      val pkidata = clientAssertionTokenGenerator.keys
      val invalidCertificates = listOf(invalidCertificate)
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, pkidata, certificateChain = invalidCertificates, PostureType.TPM).toMutableMap()
      val invalidStatement = clientStatementData(ZETA_CLIENT, nonce, pkidata, invalidCertificates, PostureType.TPM)
      otherClaims[CLAIM_CLIENT_STATEMENT] = invalidStatement

      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldContain "certificate validation failed" }
    }

    test("Invalid Quote signature") {
      val nonce = createNonce()
      val pkidata = clientAssertionTokenGenerator.keys
      val certificates = listOf(leafCertificate, intermediateCertificate)
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, pkidata, certificateChain = certificates, PostureType.TPM)
      val clientStatement = otherClaims[CLAIM_CLIENT_STATEMENT] as ClientStatementData
      val posture = clientStatement.posture as TPMPosture
      val signatureProperty =
          TPMPosture::class.declaredMemberProperties.first { it.name == "tpmQuoteSignature" }.apply { isAccessible = true }.javaField!!
      val wrongSigner = clientAssertionTokenGenerator.keys.keypair.createSignerContext()
      val wrongSignature = wrongSigner.sign(posture.tpmQuote.fromBase64())

      signatureProperty.set(posture, wrongSignature.toBase64())
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldBe SIGNATURE_VALIDATION_FAILED }
    }

    test("Invalid TPM quote data") {
      val nonce = createNonce()
      val pkidata = clientAssertionTokenGenerator.keys
      val certificates = listOf(leafCertificate, intermediateCertificate)
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, pkidata, certificateChain = certificates, PostureType.TPM)
      val clientStatement = otherClaims[CLAIM_CLIENT_STATEMENT] as ClientStatementData
      val posture = clientStatement.posture as TPMPosture
      val invalidQuote = ByteArray(4).also { System.arraycopy(posture.tpmQuote.fromBase64(), 0, it, 0, 4) }
      val quoteProperty = TPMPosture::class.declaredMemberProperties.first { it.name == "tpmQuote" }.apply { isAccessible = true }.javaField!!

      quoteProperty.set(posture, invalidQuote.toBase64())

      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldBe TPM_DESERIALIZATION_FAILED }
    }
  }
}
