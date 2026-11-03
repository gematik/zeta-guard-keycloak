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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import arrow.core.Either
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import java.util.Base64

private const val CLIENT_ID = "mobile-client"

class PepClientDataServiceTest :
    StringSpec({
      lateinit var clientData: ZetaGuardClientData
      lateinit var dataService: ZetaGuardDataService

      fun header(clientId: String = CLIENT_ID): String =
          Base64.getUrlEncoder()
              .encodeToString("""{"client_id":"$clientId","product_id":"demo_client","product_version":"0.1.0","platform":"apple"}""".toByteArray())

      beforeTest {
        val userData = ZetaGuardUserData("spicy-hash-of-kvnr", currentTime(), currentTime())
        clientData =
            ZetaGuardClientData(CLIENT_ID, currentTime(), currentTime()).apply {
              clientAuthMethod = ClientAuthMethod.SEK_IDP
              attestationState = ClientAttestationState.VALID
              registrationStatus = ClientRegistrationStatus.CONFIRMED
              this.userData = userData
            }
        dataService = mockk {
          every { findClientData(any()) } returns null
          every { findClientData(CLIENT_ID) } returns clientData
        }
      }

      fun service() = PepClientDataService(dataService)

      "a confirmed, valid mobile client bound to an identity is accepted" {
        service().clientFromPep(header()) shouldBe Either.Right(clientData)
        service().userFromPep(header()) shouldBe Either.Right(clientData.userData!!)
      }

      "unknown fields in the client data are tolerated" {
        val withExtra =
            Base64.getUrlEncoder()
                .encodeToString(
                    """{"client_id":"$CLIENT_ID","product_id":"demo_client","product_version":"0.1.0","platform":"apple","posture":{}}"""
                        .toByteArray()
                )

        service().clientFromPep(withExtra) shouldBe Either.Right(clientData)
      }

      "an unknown platform does not reject the client data" {
        val decoded = """{"client_id":"$CLIENT_ID","product_id":"demo_client","product_version":"0.1.0","platform":"tizen"}"""

        service().clientFromPep(Base64.getUrlEncoder().encodeToString(decoded.toByteArray())) shouldBe Either.Right(clientData)
      }

      "a missing header is rejected" { service().clientFromPep(null).shouldBeInstanceOf<Either.Left<String>>() }

      "an unparsable header is rejected" { service().clientFromPep("garbage").shouldBeInstanceOf<Either.Left<String>>() }

      "an unknown client is rejected" { service().clientFromPep(header("nobody")).shouldBeInstanceOf<Either.Left<String>>() }

      "a non-mobile client is rejected (A_29909)" {
        clientData.clientAuthMethod = ClientAuthMethod.SMC_B

        service().clientFromPep(header()).shouldBeInstanceOf<Either.Left<String>>()
      }

      "a client whose attestation is not VALID is rejected" {
        clientData.attestationState = ClientAttestationState.PENDING

        service().clientFromPep(header()).shouldBeInstanceOf<Either.Left<String>>()
      }

      "a client without confirmed email binding is rejected" {
        clientData.registrationStatus = ClientRegistrationStatus.OTP_PENDING

        service().clientFromPep(header()).shouldBeInstanceOf<Either.Left<String>>()
      }

      "a client not bound to an identity is rejected" {
        clientData.userData = null

        service().clientFromPep(header()).shouldBeInstanceOf<Either.Left<String>>()
      }
    })
