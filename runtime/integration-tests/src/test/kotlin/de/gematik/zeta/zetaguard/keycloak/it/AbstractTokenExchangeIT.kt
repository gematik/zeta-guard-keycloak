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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import arrow.core.getOrElse
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_DPOP_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_JKT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.signData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.time.Duration
import java.util.Base64
import java.util.UUID
import org.keycloak.OAuth2Constants
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.representations.IDToken
import org.keycloak.util.JsonSerialization
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

const val X_CUSTOM_EXT = "x-custom-ext"
const val INVALID_NONCE_VALUE = "Invalid nonce value"

val EXPIRATION = Duration.ofDays(10).toSeconds()

abstract class AbstractTokenExchangeIT : ZetaGuardFunSpecIT() {

  /** Builds a client assertion JWT signed with the test keypair, using a custom `typ` header value for negative testing. */
  protected fun createClientAssertionWithTyp(tokenType: String = "helloWorld", nonce: String): String {
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
              exp(Time.currentTime() + EXPIRATION)
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
  protected fun createSMCBTokenRaw(
      nonce: String,
      withExp: Boolean = true,
      withIat: Boolean = true,
      expOffsetSeconds: Long = EXPIRATION,
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

  protected fun createSMCBTokenWithExtraHeaders(
      nonce: String,
      extraHeaders: Map<String, Any> = emptyMap(),
      algOverride: String? = null,
  ): String {
    val clientKeyJkt = clientAssertionTokenGenerator.keys.jwkThumbPrint.toBase64()
    val dpopKeyJkt = DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()

    val header = buildMap {
      put("alg", algOverride ?: Algorithm.ES256)
      put("typ", OAuth2Constants.JWT)
      put("x5c", listOf(Base64.getEncoder().encodeToString(smcb.leafCertificate.encoded)))
      putAll(extraHeaders)
    }

    val payload =
        IDToken().apply {
          id(UUID.randomUUID().toString())
          type(TOKEN_TYPE_BEARER)
          issuer(ZETA_CLIENT)
          issuedFor(CLIENT_C_ID)
          subject(smcb.telematikId)
          audience(*smcbTokenAudience.toTypedArray())
          exp(Time.currentTime() + EXPIRATION)
          iat(Time.currentTime().toLong())
          this.nonce = nonce
          setOtherClaims(CLAIM_CLIENT_KEY, mapOf(CLAIM_JKT to clientKeyJkt))
          setOtherClaims(CLAIM_DPOP_KEY, mapOf(CLAIM_JKT to dpopKeyJkt))
        }

    return signRawJws(header, payload)
  }

  protected fun createClientAssertionWithExtraHeaders(
      nonce: String,
      extraHeaders: Map<String, Any> = emptyMap(),
  ): String {
    val header = buildMap {
      put("alg", Algorithm.ES256)
      put("typ", OAuth2Constants.JWT)
      putAll(extraHeaders)
    }

    val payload =
        IDToken().apply {
          id(UUID.randomUUID().toString())
          type(TOKEN_TYPE_BEARER)
          issuer(ZETA_CLIENT)
          subject(ZETA_CLIENT)
          issuedFor(ZETA_CLIENT)
          audience(clientAssertionAudience)
          exp(Time.currentTime() + EXPIRATION)
          iat(Time.currentTime().toLong())
          this.nonce = nonce
          createOtherClaims(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys).forEach { (k, v) -> setOtherClaims(k, v) }
        }

    return signRawJws(header, payload, clientAssertionTokenGenerator.keys.keypair)
  }

  protected fun signRawJws(
      header: Map<String, Any>,
      payload: Any,
      keyPair: KeyPair = smcb.subjectKeyPair,
  ): String {
    val encodedHeader = Base64Url.encode(JsonSerialization.writeValueAsBytes(header))
    val encodedPayload = Base64Url.encode(JsonSerialization.writeValueAsBytes(payload))
    val signingInput = "$encodedHeader.$encodedPayload"
    val data = signingInput.toByteArray(StandardCharsets.UTF_8)
    val derSignature = keyPair.private.signData(data).getOrElse { throw it }
    val rawSignature = ECDSAAlgorithm.asn1derToConcatenatedRS(derSignature, ECDSAAlgorithm.getSignatureLength(Algorithm.ES256))

    return "$signingInput.${Base64Url.encode(rawSignature)}"
  }
}
