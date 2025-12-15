/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.nonce

import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import java.time.Duration
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap
import org.keycloak.common.util.SecretGenerator

/**
 * Create 128-Bit [nonces](https://de.wikipedia.org/wiki/Nonce) encoded in [BASE64](https://de.wikipedia.org/wiki/Base64).
 *
 * Nonces will be stored in memory until they expire (by default after 1 hour), or they are used in a token exchange.
 */
class NonceFactory(private val timeProvider: TimeProvider, private val nonceTimeToLive: Duration) {
  private val secretGenerator = SecretGenerator.getInstance()
  private val nonces = ConcurrentHashMap<String, Nonce>()

  fun createNonce(ipAddress: String): Nonce {
    cleanupExpiredNonces()

    val nonceValue = secretGenerator.randomBytes(16).toBase64()

    val nonce = Nonce(nonceValue, ipAddress, timeProvider().plus(nonceTimeToLive))

    nonces[nonceValue] = nonce

    return nonce
  }

  fun retrieveNonce(nonceValue: String): Nonce? {
    cleanupExpiredNonces()

    return nonces.remove(nonceValue)
  }

  private fun cleanupExpiredNonces() {
    nonces.entries.removeIf { (_, nonce) -> nonce.isExpired() }
  }

  private fun Nonce.isExpired() = timeProvider().isAfter(expiresAt)
}

// IP-Address may be used e.g., to check if the using client is the same that created the nonce
data class Nonce(val nonceValue: String, val ipAddress: String, val expiresAt: LocalDateTime)
