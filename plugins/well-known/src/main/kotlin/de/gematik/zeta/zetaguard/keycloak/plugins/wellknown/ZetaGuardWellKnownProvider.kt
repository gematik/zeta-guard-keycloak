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
package de.gematik.zeta.zetaguard.keycloak.plugins.wellknown

import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakUriBuilder
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_PATH
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownProviderFactory.Companion.serviceDocumentationUri
import java.net.URI
import java.util.Locale
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory.PROVIDER_ID
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation
import org.keycloak.services.resources.RealmsResource
import org.keycloak.urls.UrlType
import org.keycloak.wellknown.WellKnownProvider

/**
 * Provide REST endpoint for 𝛇-Guard well-known configuration as defined in https://github.com/gematik/zeta/blob/main/src/schemas/as-well-known.yaml
 */
class ZetaGuardWellKnownProvider(private val session: KeycloakSession) : WellKnownProvider {
  override fun getConfig(): ZetaGuardWellKnownConfiguration {
    val realm = session.context.realm
    val provider = session.getProvider(WellKnownProvider::class.java, PROVIDER_ID)
    val wellknown = provider.config as OIDCConfigurationRepresentation
    val frontendUriInfo = session.context.getUri(UrlType.FRONTEND)
    val noncePath = frontendUriInfo.baseUriBuilder.path(RealmsResource::class.java).path(NONCE_PATH).build(realm.name)

    return ZetaGuardWellKnownConfiguration(
        issuer = URI.create(wellknown.issuer),
        authorizationEndpoint = URI.create(wellknown.authorizationEndpoint),
        tokenEndpoint = URI.create(wellknown.tokenEndpoint),
        nonceEndpoint = noncePath,
        openidProvidersEndpoint = KeycloakUriBuilder(frontendUriInfo).clientRegistrationOIDCUrl(realm.name),
        serviceDocumentation = serviceDocumentationUri(),
        jwksUri = URI.create(wellknown.jwksUri),
        scopesSupported = wellknown.scopesSupported,
        responseTypesSupported = listOf("code", "token"),
        responseModesSupported = wellknown.responseModesSupported,
        grantTypesSupported = wellknown.grantTypesSupported,
        tokenEndpointAuthMethodsSupported = wellknown.tokenEndpointAuthMethodsSupported,
        tokenEndpointAuthSigningAlgValuesSupported = wellknown.tokenEndpointAuthSigningAlgValuesSupported,
        uiLocalesSupported = listOf(Locale.GERMAN, Locale.ENGLISH).map { it.toString() },
        codeChallengeMethodsSupported = wellknown.codeChallengeMethodsSupported,
        apiVersionsSupported = listOf(ApiVersionsSupported(documentationUri = serviceDocumentationUri())),
    )
  }

  override fun close() {}
}
