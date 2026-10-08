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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_MOBILE_BROWSER_FLOW
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import org.keycloak.models.AuthenticationFlowBindings
import org.keycloak.models.AuthenticationFlowModel
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientScopeModel
import org.keycloak.models.RealmModel
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION
import org.keycloak.protocol.oidc.OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED
import org.keycloak.services.clientregistration.ClientRegistrationContext

class ZetaGuardClientRegistrationPolicyTest : FunSpec() {
  init {
    beforeEach {
      mockkObject(OidcFlowSettings)
      every { OidcFlowSettings.isEnabled() } returns true
    }
    afterEach { unmockkObject(OidcFlowSettings) }

    val dataService = mockk<ZetaGuardDataService>(relaxed = true)
    val integrityProviderService = mockk<IntegrityProviderService>(relaxed = true)
    val policy = ZetaGuardClientRegistrationPolicy(dataService, integrityProviderService)

    test("afterRegister for SMC-B client creates client data without email-binding scopes") {
      val clientModel = mockk<ClientModel>(relaxed = true)
      every { clientModel.clientId } returns "smc-client"
      every { clientModel.redirectUris } returns emptySet()

      val clientData = ZetaGuardClientData("smc-client", currentTime(), currentTime())
      clientData.attestationState = ClientAttestationState.PENDING
      every { dataService.createClientData("smc-client", ClientAuthMethod.SMC_B) } returns clientData

      val context = mockk<ClientRegistrationContext>(relaxed = true)
      every { context.session } returns mockk(relaxed = true)

      policy.afterRegister(context, clientModel)

      // SMC-B clients stay pending until the attestation check in the token exchange
      clientData.attestationState shouldBe ClientAttestationState.PENDING

      verify {
        clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, SAME_SESSION.name)
        clientModel.setAttribute(DPOP_BOUND_ACCESS_TOKENS, "true")
        dataService.createClientData("smc-client", ClientAuthMethod.SMC_B)
      }
      verify(exactly = 0) { clientModel.addClientScope(any(), any()) }
      verify(exactly = 0) { clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_ENABLED, any()) }
    }

    test("afterRegister for SEK_IDP client assigns email-binding scopes and creates SEK_IDP client data") {
      mockkStatic(KeycloakModelUtils::class)
      try {
        val realm = mockk<RealmModel>()
        val flow = mockk<AuthenticationFlowModel>()
        every { flow.id } returns "mobile-browser-flow-id"
        every { realm.getFlowByAlias(ZETA_MOBILE_BROWSER_FLOW) } returns flow

        val emailBindingScope = mockk<ClientScopeModel>()
        val emailVerifyScope = mockk<ClientScopeModel>()
        every { KeycloakModelUtils.getClientScopeByName(realm, SCOPE_EMAIL_BINDING) } returns emailBindingScope
        every { KeycloakModelUtils.getClientScopeByName(realm, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION) } returns
            emailVerifyScope

        val clientModel = mockk<ClientModel>(relaxed = true)
        every { clientModel.clientId } returns "mobile-client"
        every { clientModel.redirectUris } returns setOf("zeta://callback")
        every { clientModel.realm } returns realm
        justRun { clientModel.addClientScope(any(), false) }
        justRun { clientModel.setAuthenticationFlowBindingOverride(any(), any()) }
        justRun { clientModel.setAttribute(any(), any()) }

        val clientData = ZetaGuardClientData("mobile-client", currentTime(), currentTime())
        clientData.attestationState = ClientAttestationState.PENDING
        every { dataService.createClientData("mobile-client", ClientAuthMethod.SEK_IDP) } returns clientData

        val context = mockk<ClientRegistrationContext>(relaxed = true)
        every { context.session } returns mockk(relaxed = true)

        policy.afterRegister(context, clientModel)

        // Attestation of mobile clients is mocked — the registration is valid right away
        clientData.attestationState shouldBe ClientAttestationState.VALID

        verify {
          clientModel.setAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW, MOCK_MOBILE_CLIENT_STATEMENT)
          clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_ENABLED, "true")
          clientModel.setAuthenticationFlowBindingOverride(AuthenticationFlowBindings.BROWSER_BINDING, "mobile-browser-flow-id")
          clientModel.addClientScope(emailBindingScope, false)
          clientModel.addClientScope(emailVerifyScope, false)
          dataService.createClientData("mobile-client", ClientAuthMethod.SEK_IDP)
        }
      } finally {
        unmockkStatic(KeycloakModelUtils::class)
      }
    }

    test("afterRegister for SEK_IDP client fails when email-binding client scope is missing") {
      mockkStatic(KeycloakModelUtils::class)
      try {
        val realm = mockk<RealmModel>()
        val flow = mockk<AuthenticationFlowModel>()
        every { flow.id } returns "mobile-browser-flow-id"
        every { realm.getFlowByAlias(ZETA_MOBILE_BROWSER_FLOW) } returns flow
        every { KeycloakModelUtils.getClientScopeByName(realm, SCOPE_EMAIL_BINDING) } returns null

        val clientModel = mockk<ClientModel>(relaxed = true)
        every { clientModel.clientId } returns "mobile-client"
        every { clientModel.redirectUris } returns setOf("zeta://callback")
        every { clientModel.realm } returns realm

        val context = mockk<ClientRegistrationContext>(relaxed = true)
        every { context.session } returns mockk(relaxed = true)

        val ex = shouldThrow<IllegalStateException> { policy.afterRegister(context, clientModel) }
        ex.message shouldBe "Client scope '$SCOPE_EMAIL_BINDING' not found."
      } finally {
        unmockkStatic(KeycloakModelUtils::class)
      }
    }

    test("afterRegister with redirect_uris registers as SMC_B when mobile flow is disabled") {
      every { OidcFlowSettings.isEnabled() } returns false

      val clientModel = mockk<ClientModel>(relaxed = true)
      every { clientModel.clientId } returns "mobile-looking-client"
      every { clientModel.redirectUris } returns setOf("zeta://callback")

      val context = mockk<ClientRegistrationContext>(relaxed = true)
      every { context.session } returns mockk(relaxed = true)

      policy.afterRegister(context, clientModel)

      verify { dataService.createClientData("mobile-looking-client", ClientAuthMethod.SMC_B) }
      verify(exactly = 0) { clientModel.addClientScope(any(), any()) }
      verify(exactly = 0) { clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_ENABLED, any()) }
    }
  }
}
