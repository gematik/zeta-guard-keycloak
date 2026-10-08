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

import de.gematik.zeta.zetaguard.keycloak.commons.server.toMinimalJWK
import jakarta.ws.rs.HttpMethod
import java.net.URI
import org.keycloak.OAuth2Constants.DPOP_DEFAULT_ALGORITHM
import org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time.currentTime
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.util.DPoPGenerator

object DPoPTokenGenerator : AbstractTokenGenerator() {
  /**
   * Generate DPoP, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1
   *
   * Inspired by [DPoPGenerator.generateRsaSignedDPoPProof]
   */
  fun generateDPoPToken(endpointURL: URI, accessToken: String): String {
    val jwsRsaHeader = JWSHeader(DPOP_DEFAULT_ALGORITHM, DPOP_JWT_HEADER_TYPE, keys.jwk.keyId, keys.keypair.public.toMinimalJWK())

    return DPoPGenerator()
        .generateSignedDPoPProof(
            SecretGenerator.getInstance().generateSecureID(),
            HttpMethod.POST,
            endpointURL.toString(),
            currentTime().toLong(),
            jwsRsaHeader,
            keys.keypair.private,
            accessToken,
        )
  }
}
