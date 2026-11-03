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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.MEDIA_TYPE_PROBLEM_JSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mockk.verify
import jakarta.ws.rs.core.Response
import java.util.Base64
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

/**
 * The resource only resolves the caller from the PEP-forwarded client data — no request without a usable header and a
 * known, enabled client may reach the [EmailChangeHandler]. The domain checks are covered by the handler's own tests.
 */
class EmailChangeResourceTest :
    StringSpec({
      lateinit var realm: RealmModel
      lateinit var session: KeycloakSession
      val client =
          mockk<ClientModel> {
            every { clientId } returns "mobile-client"
            every { isEnabled } returns true
          }

      fun tokenContent(json: String): String = Base64.getUrlEncoder().encodeToString(json.toByteArray())

      fun clientData(clientId: String): String =
          tokenContent("""{"client_id":"$clientId","product_id":"demo_client","product_version":"0.1.0","platform":"apple"}""")

      // the caller must be a confirmed mobile client (PepClientDataService)
      fun registered(clientId: String): ZetaGuardClientData =
          ZetaGuardClientData(clientId, currentTime(), currentTime()).apply {
            clientAuthMethod = ClientAuthMethod.SEK_IDP
            attestationState = ClientAttestationState.VALID
            registrationStatus = ClientRegistrationStatus.CONFIRMED
            userData = ZetaGuardUserData("user", currentTime(), currentTime())
          }

      val mobileClientData = registered("mobile-client")

      beforeTest {
        realm = mockk { every { getClientByClientId(any()) } returns null }
        val context = mockk<KeycloakContext> { every { this@mockk.realm } returns realm }
        session = mockk { every { this@mockk.context } returns context }
        mockkConstructor(ZetaGuardDataService::class)
        every { anyConstructed<ZetaGuardDataService>().findClientData(any()) } returns null
        every { anyConstructed<ZetaGuardDataService>().findClientData("mobile-client") } returns mobileClientData
        mockkConstructor(EmailChangeHandler::class)
        every { anyConstructed<EmailChangeHandler>().handle(any(), any()) } returns Response.accepted().build()
      }

      afterTest { unmockkAll() }

      "a request without the PEP header is rejected with 401 unauthorized before anything else runs" {
        val response = EmailChangeResource(session).changeEmail(null, EmailChangeRequest())

        response.status shouldBe 401
        response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
        response.entityMap()["code"] shouldBe ProblemCodes.UNAUTHORIZED
        verify(exactly = 0) { anyConstructed<EmailChangeHandler>().handle(any(), any()) }
      }

      "an unparsable header is rejected with 401 unauthorized" {
        val response = EmailChangeResource(session).changeEmail("garbage", EmailChangeRequest())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.UNAUTHORIZED
      }

      "client data whose client_id is not a registered client is rejected with 401 unauthorized" {
        val response = EmailChangeResource(session).changeEmail(clientData("nobody"), EmailChangeRequest())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.UNAUTHORIZED
        verify(exactly = 0) { anyConstructed<EmailChangeHandler>().handle(any(), any()) }
      }

      "a disabled client is rejected with 401 unauthorized" {
        every { realm.getClientByClientId("mobile-client") } returns mockk { every { isEnabled } returns false }

        EmailChangeResource(session).changeEmail(clientData("mobile-client"), EmailChangeRequest()).status shouldBe 401
      }

      "the client_id of the forwarded client data selects the client data handed to the handler" {
        every { realm.getClientByClientId("mobile-client") } returns client
        val request = EmailChangeRequest()

        val response = EmailChangeResource(session).changeEmail(clientData("mobile-client"), request)

        response.status shouldBe 202
        verify { anyConstructed<EmailChangeHandler>().handle(mobileClientData, request) }
      }
    })

@Suppress("UNCHECKED_CAST") //
private fun Response.entityMap(): Map<String, Any> = entity as Map<String, Any>
