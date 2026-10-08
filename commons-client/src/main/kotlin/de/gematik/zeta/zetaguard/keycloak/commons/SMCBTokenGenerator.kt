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

import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_DPOP_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_JKT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import java.security.KeyPair
import java.security.cert.X509Certificate

class SMCBTokenGenerator(subjectKeyPair: KeyPair) : AbstractTokenGenerator(subjectKeyPair) {
  // SMC-B-signed key bindings. Wired once by the test layer to the keys actually presented in the exchange.
  var defaultClientKeyJkt: String? = null
  var defaultDpopKeyJkt: String? = null

  /**
   * Generate SMC-B-like token including x5c certificate header.
   *
   * According to https://github.com/gematik/zeta/blob/main/src/schemas/smb-id-token-jwt.yaml
   */
  fun generateSMCBToken(
      issuer: String = ZETA_CLIENT,
      subject: String,
      nonceString: String,
      issuedFor: String = CLIENT_C_ID,
      audiences: List<String> = listOf(ZETA_CLIENT),
      certificateChain: List<X509Certificate>,
  ) =
      generateToken(
          issuer,
          subject,
          nonceString,
          issuedFor,
          audiences,
          certificateChain,
          TokenOptions(
              // Emit the key bindings only when wired; for a custom per-token binding use createSMCBTokenRaw.
              otherClaims =
                  buildMap {
                    defaultClientKeyJkt?.let { put(CLAIM_CLIENT_KEY, mapOf(CLAIM_JKT to it)) }
                    defaultDpopKeyJkt?.let { put(CLAIM_DPOP_KEY, mapOf(CLAIM_JKT to it)) }
                  },
              // subject-token-smb.yaml forbids `payload.typ` and `header.kid` — omit both.
              includeTokenType = false,
              includeKid = false,
          ),
      )
}
