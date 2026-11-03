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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import org.keycloak.Config
import org.keycloak.OAuth2Constants.CODE_CHALLENGE
import org.keycloak.OAuth2Constants.CODE_CHALLENGE_METHOD
import org.keycloak.OAuth2Constants.PKCE_METHOD_S256
import org.keycloak.OAuth2Constants.REDIRECT_URI
import org.keycloak.OAuth2Constants.SCOPE
import org.keycloak.OAuth2Constants.STATE
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.par.clientpolicy.context.PushedAuthorizationRequestContext
import org.keycloak.protocol.oidc.utils.RedirectUtils
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation
import org.keycloak.services.clientpolicy.ClientPolicyContext
import org.keycloak.services.clientpolicy.ClientPolicyEvent.PUSHED_AUTHORIZATION_REQUEST
import org.keycloak.services.clientpolicy.ClientPolicyException
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory

private const val SEKIDP_PARAM_IDP_ISS = "idp_iss"
private const val SEKIDP_PARAM_OIDC_REDIRECT_URI = "oidc_redirect_uri"

// Keycloak's PAR endpoint already authenticates the client, requires response_type and validates the values of
// redirect_uri, scope and PKCE, but treats these parameters as optional.
private val REQUIRED_PAR_PARAMS =
    listOf(REDIRECT_URI, SEKIDP_PARAM_OIDC_REDIRECT_URI, SEKIDP_PARAM_IDP_ISS, SCOPE, STATE, CODE_CHALLENGE, CODE_CHALLENGE_METHOD)

/** the outer PAR must carry everything the SekIDP flow needs */
class OuterParExecutor(private val session: KeycloakSession) : ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

  override fun getProviderId(): String = OuterParExecutorFactory.PROVIDER_ID

  override fun executeOnEvent(context: ClientPolicyContext) {
    if (context.event != PUSHED_AUTHORIZATION_REQUEST) return
    val parContext = context as PushedAuthorizationRequestContext
    val params = parContext.requestParameters

    val missing = REQUIRED_PAR_PARAMS.filter { params.getFirst(it).isNullOrBlank() }
    if (missing.isNotEmpty()) throw ClientPolicyException(INVALID_REQUEST, "Missing parameter: ${missing.joinToString()}")

    if (params.getFirst(CODE_CHALLENGE_METHOD) != PKCE_METHOD_S256) {
      throw ClientPolicyException(INVALID_REQUEST, "$CODE_CHALLENGE_METHOD must be $PKCE_METHOD_S256")
    }

    if (RedirectUtils.verifyRedirectUri(session, params.getFirst(SEKIDP_PARAM_OIDC_REDIRECT_URI), parContext.client) == null) {
      throw ClientPolicyException(INVALID_REQUEST, "Invalid parameter: $SEKIDP_PARAM_OIDC_REDIRECT_URI")
    }
  }
}

class OuterParExecutorFactory : ClientPolicyExecutorProviderFactory {

  companion object {
    const val PROVIDER_ID = "zeta-outer-par"
  }

  override fun create(session: KeycloakSession): ClientPolicyExecutorProvider<*> = OuterParExecutor(session)

  override fun init(config: Config.Scope) {
    // no config to read
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // nothing to set up
  }

  override fun close() {
    // nothing to clean up
  }

  override fun getId(): String = PROVIDER_ID

  override fun getHelpText(): String = "Rejects an outer PAR lacking a parameter of the SekIDP flow."

  override fun getConfigProperties(): List<ProviderConfigProperty> = emptyList()
}
