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

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory

const val TOKEN_EXCHANGE_PROVIDER_ID = "zeta-smc-b-token-exchange"

class SMCBTokenExchangeProviderFactory() : TokenExchangeProviderFactory {
    override fun create(session: KeycloakSession) = SMCBTokenExchangeProvider()

    override fun init(config: Config.Scope) {}

    override fun postInit(factory: KeycloakSessionFactory?) {}

    override fun close() {}

    override fun getId() = TOKEN_EXCHANGE_PROVIDER_ID

    // Higher priority than standard token exchange provider
    override fun order() = 30
}
