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
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID2
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_DPOP_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_JKT
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Duration
import java.util.UUID
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_FORBIDDEN
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time
import org.keycloak.events.Errors.INVALID_TOKEN
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.representations.IDToken
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

class ExternalTokenExchangeIT : ZetaGuardFunSpecIT() {
  init {
    test("External token exchange with SMC-B token, software attestation, client assertion and DPoP header") {
      val nonce = createNonce()
      // The zeta-client client knows about the JWT public key without client registration, because the key certificate is configured
      // hard-coded in the "jwt.credential.certificate" attribute (See zeta-client.json)
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt)
    }

    test("MITM: rejected when client_key binding does not match the presented client key") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      // SMC-B attests a foreign client key while the request presents the real client key → MITM client_key swap.
      val foreignClientKeyJkt = PKIData(generateKeyPair()).jwkThumbPrint.toBase64()
      val presentedDpopJkt = DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()
      val smcbToken = createSMCBTokenRaw(nonce, clientKeyJkt = foreignClientKeyJkt, dpopKeyJkt = presentedDpopJkt)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain CLAIM_CLIENT_KEY
        it.statusCode shouldBe SC_FORBIDDEN
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
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain CLAIM_DPOP_KEY
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("External token exchange with SMC-B token, TPM attestation, client assertion and DPoP header") {
      val nonce = createNonce()
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce, postureType = TPM)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt)
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

    test("External token exchange fails without DPoP token") {
      val nonce = createNonce()
      val jws = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jws, useDPoP = false) {
        it.error shouldBe INVALID_REQUEST
        it.errorDescription shouldBe "DPoP proof is missing"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Missing client_assertion") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = null) {
        it.error shouldBe INVALID_CLIENT
        // AbstractJWTClientValidator#validateClientAssertionParameters
        it.errorDescription shouldBe "Parameter client_assertion_type is missing"
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

    test("External token exchange fails with invalid audience") {
      val nonce = createNonce()
      val jws = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              subject = smcb.telematikId,
              nonceString = nonce,
              audiences = listOf(ZETA_CLIENT),
              certificateChain = listOf(smcb.leafCertificate),
          )

      testExchangeToken(smcbToken, clientAssertion = jws, requestedClientScope = CLIENT_B_SCOPE) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldBe "Expected audience not available in the token"
        it.statusCode shouldBe SC_FORBIDDEN
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
        it.errorDescription shouldBe "Invalid nonce value"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("Nonce is not reusable") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)
      val jws1 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val jws2 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)

      testExchangeToken(smcbToken, clientAssertion = jws1, requestedClientScope = CLIENT_B_SCOPE)
      testExchangeToken(smcbToken, clientAssertion = jws2) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldBe "Invalid nonce value"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("SMC-B token without 'exp' claim is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, withExp = false)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "missing required 'exp'"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("SMC-B token without 'iat' claim is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, withIat = false)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "missing required 'iat'"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("SMC-B token with 'iat' in the future is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, iatOffsetSeconds = Duration.ofHours(1).toSeconds())

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "'iat' is in the future"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("SMC-B token with expired 'exp' is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, expOffsetSeconds = -Duration.ofHours(1).toSeconds())

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "has expired"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("subject_token with base URL as aud is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val baseUrl = keycloakWebClient.uriBuilder().build().toString().let { if (it.endsWith("/")) it else "$it/" }
      val smcbToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              subject = smcb.telematikId,
              audiences = listOf(baseUrl),
              certificateChain = listOf(smcb.leafCertificate),
          )

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.error shouldBe INVALID_TOKEN
        it.statusCode shouldBe SC_FORBIDDEN
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
  }

  /** Builds a client assertion JWT signed with the test keypair, using a custom `typ` header value for negative testing. */
  private fun createClientAssertionWithTyp(tokenType: String = "helloWorld", nonce: String): String {
    val signer = clientAssertionTokenGenerator.keys.keypair.createSignerContext()
    return JWSBuilder()
        .type(tokenType)
        .jsonContent(
            IDToken().apply {
              id(UUID.randomUUID().toString())
              type(TOKEN_TYPE_BEARER)
              issuer(ZETA_CLIENT)
              subject(ZETA_CLIENT)
              issuedFor(ZETA_CLIENT)
              audience(clientAssertionAudience)
              exp(Time.currentTime() + Duration.ofDays(10).toSeconds())
              iat(Time.currentTime().toLong())
              this.nonce = nonce
            }
        )
        .sign(signer)
  }

  /**
   * Builds a raw SMC-B token signed with the test keypair, allowing selective omission or override of the 'iat' and 'exp' claims for negative
   * testing.
   */
  private fun createSMCBTokenRaw(
      nonce: String,
      withExp: Boolean = true,
      withIat: Boolean = true,
      expOffsetSeconds: Long = Duration.ofDays(10).toSeconds(),
      iatOffsetSeconds: Long = 0L,
      clientKeyJkt: String? = null,
      dpopKeyJkt: String? = null,
  ): String {
    val signer = smcb.subjectKeyPair.createSignerContext()

    return JWSBuilder()
        .type(OAuth2Constants.JWT)
        .x5c(listOf(smcb.leafCertificate))
        .jsonContent(
            IDToken().apply {
              id(UUID.randomUUID().toString())
              type(TOKEN_TYPE_BEARER)
              issuer(ZETA_CLIENT)
              issuedFor(CLIENT_C_ID)
              subject(smcb.telematikId)
              audience(*smcbTokenAudience.toTypedArray())
              if (withExp) exp(Time.currentTime() + expOffsetSeconds)
              if (withIat) iat(Time.currentTime() + iatOffsetSeconds)
              this.nonce = nonce
              clientKeyJkt?.let { setOtherClaims(CLAIM_CLIENT_KEY, mapOf(CLAIM_JKT to it)) }
              dpopKeyJkt?.let { setOtherClaims(CLAIM_DPOP_KEY, mapOf(CLAIM_JKT to it)) }
            }
        )
        .sign(signer)
  }
}
