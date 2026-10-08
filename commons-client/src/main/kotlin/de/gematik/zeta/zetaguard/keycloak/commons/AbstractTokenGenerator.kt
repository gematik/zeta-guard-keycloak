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

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.UUID
import org.keycloak.OAuth2Constants
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.representations.IDToken
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

abstract class AbstractTokenGenerator(subjectKeyPair: KeyPair = generateKeyPair()) {
  val keys = PKIData(subjectKeyPair)

  /**
   * Optional token content/shape. [includeTokenType] and [includeKid] default to `true` (current behavior); the SMC-B subject token opts out of
   * both so it stays compliant with subject-token-smb.yaml (no `payload.typ`, no `header.kid`).
   */
  data class TokenOptions(val otherClaims: Map<String, Any> = mapOf(), val includeTokenType: Boolean = true, val includeKid: Boolean = true)

  protected fun generateToken(
      issuer: String,
      subject: String,
      nonceString: String? = null,
      issuedFor: String,
      audiences: List<String>,
      certificateChain: List<X509Certificate> = listOf(),
      options: TokenOptions = TokenOptions(),
  ): String {
    val signer = keys.keypair.createSignerContext(includeKid = options.includeKid)

    return JWSBuilder()
        .type(OAuth2Constants.JWT)
        .x5c(certificateChain)
        .jsonContent(
            IDToken().apply {
              id(UUID.randomUUID().toString())
              if (options.includeTokenType) type(TOKEN_TYPE_BEARER)
              issuer(issuer)
              issuedFor(issuedFor)
              subject(subject)
              audience(*audiences.toTypedArray())
              expirationDate(Duration.ofDays(10))
              issuedNow()
              options.otherClaims.forEach { setOtherClaims(it.key, it.value) }
              nonce = nonceString
            }
        )
        .sign(signer)
  }
}
