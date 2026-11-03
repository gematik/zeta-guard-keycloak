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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ClientRegistrationState
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientResponseRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.oidc.addRegistrationState
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.representations.oidc.OIDCClientRepresentation

private const val CLIENT_ID = "a-client-id"
private const val CLIENT_NAME = "a client"
private const val GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

class RegistrationStateTest :
    FunSpec({
      /** A_30086: every state the registration can be in, and the status the OIDC response has to report for it. */
      val cases =
          listOf(
              // SMC-B: registered right away, attested by the first token exchange.
              Case("SMC-B, attestation outstanding", ClientAuthMethod.SMC_B, ClientAttestationState.PENDING, ClientRegistrationState.REGISTERED),
              Case("SMC-B, attested", ClientAuthMethod.SMC_B, ClientAttestationState.VALID, ClientRegistrationState.ACTIVE),
              Case("SMC-B, attestation rejected", ClientAuthMethod.SMC_B, ClientAttestationState.INVALID, null),
              // SEK-IdP: binding needs the attestation (F2), the verified e-mail (F1) and the TI identity (A_29903).
              Case(
                  "SEK-IdP, all three factors",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.VALID,
                  ClientRegistrationState.BOUND,
                  ClientRegistrationStatus.CONFIRMED,
                  hasUserData = true,
              ),
              Case(
                  "SEK-IdP, confirmed but no TI identity",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.VALID,
                  ClientRegistrationState.PENDING_USER_BINDING,
                  ClientRegistrationStatus.CONFIRMED,
              ),
              Case(
                  "SEK-IdP, e-mail not confirmed yet",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.VALID,
                  ClientRegistrationState.PENDING_USER_BINDING,
                  ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED,
                  hasUserData = true,
              ),
              Case(
                  "SEK-IdP, OTP still pending",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.VALID,
                  ClientRegistrationState.PENDING_USER_BINDING,
                  ClientRegistrationStatus.OTP_PENDING,
                  hasUserData = true,
              ),
              Case(
                  "SEK-IdP, no registration status",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.VALID,
                  ClientRegistrationState.PENDING_USER_BINDING,
                  hasUserData = true,
              ),
              // Fail closed: the registration policy attests mobile clients before it stores them, so neither state should occur.
              Case(
                  "SEK-IdP, attestation outstanding",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.PENDING,
                  null,
                  ClientRegistrationStatus.CONFIRMED,
                  hasUserData = true,
              ),
              Case(
                  "SEK-IdP, attestation rejected",
                  ClientAuthMethod.SEK_IDP,
                  ClientAttestationState.INVALID,
                  null,
                  ClientRegistrationStatus.CONFIRMED,
                  hasUserData = true,
              ),
          )

      test("registrationState reports the status of every registration state") {
        cases.forEach { case -> withClue(case.name) { case.clientData().registrationState() shouldBe case.expected } }
      }

      test("addRegistrationState keeps the representation and adds the status") {
        val dataService = mockk<ZetaGuardDataService>()
        every { dataService.findClientData(CLIENT_ID) } returns clientData(ClientAuthMethod.SMC_B, ClientAttestationState.VALID)

        val result = addRegistrationState(oidcClientRepresentation(), dataService).shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>()

        result.status shouldBe ClientRegistrationState.ACTIVE
        result.clientId shouldBe CLIENT_ID
        result.clientName shouldBe CLIENT_NAME
        result.grantTypes shouldBe listOf(GRANT_TYPE)
      }

      test("addRegistrationState leaves the status out when there is no client data") {
        val dataService = mockk<ZetaGuardDataService>()
        every { dataService.findClientData(CLIENT_ID) } returns null

        addRegistrationState(oidcClientRepresentation(), dataService).shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>().status.shouldBeNull()
      }

      test("addRegistrationState does not look anything up without a client id") {
        val dataService = mockk<ZetaGuardDataService>()

        addRegistrationState(oidcClientRepresentation(clientId = null), dataService)
            .shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>()
            .status
            .shouldBeNull()

        verify(exactly = 0) { dataService.findClientData(any()) }
      }

      test("addRegistrationState passes anything that is not a client representation through") {
        // Error responses carry an OAuth2ErrorRepresentation rather than a client — those must not be rewritten.
        val error = Any()

        addRegistrationState(error, mockk()) shouldBe error
        addRegistrationState(null, mockk()).shouldBeNull()
      }
    })

private fun oidcClientRepresentation(clientId: String? = CLIENT_ID) =
    OIDCClientRepresentation().apply {
      this.clientId = clientId
      clientName = CLIENT_NAME
      grantTypes = listOf(GRANT_TYPE)
    }

private fun clientData(
    authMethod: ClientAuthMethod,
    attestation: ClientAttestationState,
    status: ClientRegistrationStatus? = null,
    hasUserData: Boolean = false,
) =
    ZetaGuardClientData(CLIENT_ID, currentTime(), currentTime()).apply {
      clientAuthMethod = authMethod
      attestationState = attestation
      registrationStatus = status
      userData = if (hasUserData) ZetaGuardUserData("a-user", currentTime(), currentTime()) else null
    }

private data class Case(
    val name: String,
    val authMethod: ClientAuthMethod,
    val attestationState: ClientAttestationState,
    val expected: ClientRegistrationState?,
    val registrationStatus: ClientRegistrationStatus? = null,
    val hasUserData: Boolean = false,
) {
  fun clientData() = clientData(authMethod, attestationState, registrationStatus, hasUserData)
}
