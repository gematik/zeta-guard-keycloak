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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType.TPM
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_B
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_ZETA_TEST
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID2
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_DPOP_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_FORBIDDEN
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_GRANT
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.common.util.SecretGenerator
import org.keycloak.events.Errors.INVALID_TOKEN

class ExternalTokenExchangeIT : AbstractTokenExchangeIT() {
  init {
    test("External token exchange with SMC-B token, software attestation, client assertion and DPoP header") {
      val nonce = createNonce()
      // The zeta-client client knows about the JWT public key without client registration, because the key certificate is configured
      // hard-coded in the "jwt.credential.certificate" attribute (See zeta-client.json)
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)
      val (_, newAccessToken, refreshToken) = testExchangeToken(
          smcbToken,
          clientAssertion = jwt,
          requestedClientScope = "$SCOPE_ZETA_TEST $SCOPE_CLIENT_B"
      )

      newAccessToken.scope shouldContain SCOPE_ZETA_TEST
      refreshToken.scope shouldContain SCOPE_ZETA_TEST
    }

    test("MITM: rejected when client_key binding does not match the presented client key") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      // SMC-B attests a foreign client key while the request presents the real client key → MITM client_key swap.
      val foreignClientKeyJkt = PKIData(generateKeyPair()).jwkThumbPrint.toBase64()
      val presentedDpopJkt = DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()
      val smcbToken = createSMCBTokenRaw(nonce, clientKeyJkt = foreignClientKeyJkt, dpopKeyJkt = presentedDpopJkt)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain CLAIM_CLIENT_KEY
      }
    }

    test("MITM: rejected when dpop_key binding does not match the presented DPoP key") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      // SMC-B attests a foreign DPoP key while the request presents the real DPoP key → MITM DPoP swap.
      val presentedClientKeyJkt = clientAssertionTokenGenerator.keys.jwkThumbPrint.toBase64()
      val foreignDpopJkt = PKIData(generateKeyPair()).jwkThumbPrint.toBase64()
      val smcbToken = createSMCBTokenRaw(nonce, clientKeyJkt = presentedClientKeyJkt, dpopKeyJkt = foreignDpopJkt)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain CLAIM_DPOP_KEY
      }
    }

    // ZETAP-2294 temporary disabled TPM attestation
    xtest("External token exchange with SMC-B token, TPM attestation, client assertion and DPoP header") {
      val nonce = createNonce()
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce, postureType = TPM)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt)
    }

    // Replacement while ZETAP-2294 temporary disabled TPM attestation
    test("External token exchange with TPM attestation is rejected") {
      val nonce = createNonce()
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce, postureType = TPM)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.errorDescription shouldBe "Client attestation check not implemented for »TPM« posture type"
      }
    }

    test("Fail, if token is reused") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Token reuse detected"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Telematik ID/subject mismatch") {
      val nonce2 = createNonce()
      val jwt2 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce2)
      val smcbToken2 =
          smcb.smcbTokenGenerator.generateSMCBToken(
              subject = TELEMATIK_ID2,
              nonceString = nonce2,
              audiences = smcbTokenAudience,
              certificateChain = listOf(smcb.leafCertificate),
          )

      testExchangeToken(smcbToken2, clientAssertion = jwt2) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "Invalid subject"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("Missing client_assertion") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = null) {
        it.error shouldBe INVALID_CLIENT
        // AbstractJWTClientValidator#validateClientAssertionParameters
        it.errorDescription shouldBe "client_assertion parameter missing"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Client assertion with invalid typ header is rejected") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)
      val jwt = createClientAssertionWithTyp(nonce = nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_REQUEST
        it.errorDescription shouldContain "Invalid client assertion token type"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("SMC-B token exchange fails without valid nonce") {
      val smcbToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              audiences = smcbTokenAudience,
              subject = smcb.telematikId,
              nonceString = "noncence",
              certificateChain = listOf(smcb.leafCertificate),
          )
      val jws =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = SecretGenerator.getInstance().randomBytes(16).toBase64(),
          )

      testExchangeToken(smcbToken, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain INVALID_NONCE_VALUE
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Nonce is not reusable") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)
      val jws1 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val jws2 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)

      testExchangeToken(smcbToken, clientAssertion = jws1, requestedClientScope = SCOPE_CLIENT_B)
      testExchangeToken(smcbToken, clientAssertion = jws2) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain INVALID_NONCE_VALUE
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("token exchange without explicit audience parameter is denied by OPA") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt, audience = null) {
        it.statusCode shouldBe SC_FORBIDDEN
        it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
        it.errorDescription shouldBe "policy_denied"
      }
    }

    test("raw-JWS helpers produce valid tokens when no extra headers are added (baseline for A_27802-03 negative tests)") {
      val nonce = createNonce()
      val smcbToken = createSMCBTokenWithExtraHeaders(nonce)
      val jwt = createClientAssertionWithExtraHeaders(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt)
    }
  }
}
