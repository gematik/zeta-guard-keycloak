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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.AttackDetectionLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.CapecAttackMechanics.AUTHENTICATION_BYPASS
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.reportAttack
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceFactory
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import java.time.Duration
import java.time.LocalDateTime
import org.keycloak.models.KeycloakSession

abstract class AbstractAttestationCheckerTest : ZetaGuardFunSpec() {
  protected val session = mockk<KeycloakSession>()
  protected val nonceFactory = NonceFactory(LocalDateTime::now, Duration.ofSeconds(10))
  protected var nonce: ByteArray = byteArrayOf()

  protected fun KeycloakError.shouldMatch(description: String) {
    errorDescription shouldContain description
  }

  init {
    beforeSpec {
      mockkStatic(KeycloakSession::clientIP)
      mockkStatic(AttackDetectionLogger::class.qualifiedName + "Kt")
    }

    beforeEach {
      every { session.clientIP } returns "127.0.0.1"
      every { session.reportAttack(any<KeycloakError>(), eq(AUTHENTICATION_BYPASS), eq("127.0.0.1")) } returns Unit

      nonce = nonceFactory.createNonce().nonceValue.fromBase64()
    }
  }
}
