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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.SMCB_ISSUER
import org.keycloak.broker.oidc.OIDCIdentityProvider
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.oidc.TokenExchangeContext

/**
 * As of version 26.3.4, Keycloak does not implement external-to-internal token exchange in V2.
 *
 * We try to use as much as possible from the V2 OIDC provider implementation. For details, see
 * https://www.keycloak.org/securing-apps/token-exchange
 */
open class SMCBIdentityProvider(session: KeycloakSession, config: OIDCIdentityProviderConfig) :
    OIDCIdentityProvider(session, config) {
    private val profile =
        ObjectMapper()
            .readTree(
                """{
              "sub": "$SMCB_ISSUER",
              "name": "SMC-B",
              "given_name": "B",
              "family_name": "SMC",
              "preferred_username": "user",
              "email": "user@gematik.de"
            }"""
                    .trimIndent()
            )

    /**
     * Inspired by
     * [org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.validateExternalTokenThroughUserInfo]
     * which is called by the legacy V1 version. We omit user info retrieval, since we have
     * (currently) no URL to do so. Instead the user information is hard-coded for now.
     */
    override fun exchangeExternalTokenV2Impl(
        tokenExchangeContext: TokenExchangeContext
    ): BrokeredIdentityContext =
        extractIdentityFromProfile(tokenExchangeContext.event, profile).apply {
            contextData[EXCHANGE_PROVIDER] = config.alias
            idp = this@SMCBIdentityProvider
            modelUsername = "user"
        }
}
