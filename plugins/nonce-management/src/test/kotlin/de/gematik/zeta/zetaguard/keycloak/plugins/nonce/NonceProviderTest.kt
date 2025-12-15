/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import org.keycloak.models.KeycloakSession

class NonceProviderTest : FunSpec() {
  private val keycloakSession: KeycloakSession = mockk(relaxUnitFun = true)
  private val timeProvider: TimeProvider = mockk()
  private val fixedDate = LocalDateTime.of(2011, 7, 16, 19, 59, 12)
  private val nonceTTL = Duration.ofSeconds(1)

  private val objectUnderTest =
      object : NonceProviderFactory() {
        override fun timeProvider() = timeProvider

        override fun nonceTimeToLive() = nonceTTL
      }

  init {
    objectUnderTest.postInit(mockk())

    beforeTest {
      every { timeProvider() } returns fixedDate
      every { keycloakSession.context.connection.remoteAddr } returns "127.0.0.1"
    }

    test("Nonce creation") {
      val provider = objectUnderTest.create(keycloakSession)
      val nonce = provider.createNonce().entity as String

      objectUnderTest.nonceFactory.retrieveNonce("nonsens") shouldBe null

      val retrievedNonce = objectUnderTest.nonceFactory.retrieveNonce(nonce)
      retrievedNonce?.expiresAt shouldBe fixedDate.plus(nonceTTL)
      retrievedNonce?.ipAddress shouldBe "127.0.0.1"

      objectUnderTest.nonceFactory.retrieveNonce(nonce) shouldBe null
    }

    test("Nonce expiration") {
      val provider = objectUnderTest.create(keycloakSession)
      val nonce = provider.createNonce().entity as String

      every { timeProvider() } returns fixedDate.plus(nonceTTL.plus(1, ChronoUnit.SECONDS))

      objectUnderTest.nonceFactory.retrieveNonce(nonce) shouldBe null
    }
  }
}
