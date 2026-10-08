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
package de.gematik.zeta.zetaguard.keycloak.plugins.nonce

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.Scheduler
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import java.time.Duration
import java.time.LocalDateTime
import org.keycloak.common.util.SecretGenerator

/**
 * Create 128-Bit [nonces](https://de.wikipedia.org/wiki/Nonce) encoded in [BASE64](https://de.wikipedia.org/wiki/Base64).
 *
 * Nonces will be stored in memory until they expire (by default after 1 hour), or they are used in a token exchange.
 */
class NonceFactory(private val timeProvider: TimeProvider, private val nonceTimeToLive: Duration) {
  private val secretGenerator = SecretGenerator.getInstance()
  private val nonces = Caffeine.newBuilder()
      .expireAfterWrite(nonceTimeToLive)
      .maximumSize(100_000).scheduler(Scheduler.systemScheduler()).build<String, Nonce>()

  fun createNonce(): Nonce {
    val nonceValue = secretGenerator.randomBytes(16).toBase64()
    val nonce = Nonce(nonceValue, timeProvider().plus(nonceTimeToLive))

    nonces.put(nonceValue, nonce)

    return nonce
  }

  fun retrieveNonce(nonceValue: String): Nonce? {
    return nonces.asMap().remove(nonceValue)
  }
}

data class Nonce(val nonceValue: String, val expiresAt: LocalDateTime)
