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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import arrow.core.Either
import de.gematik.zeta.zetaguard.keycloak.commons.resolveClientIP
import io.opentelemetry.api.trace.Tracer
import jakarta.ws.rs.core.Response
import org.apache.http.impl.client.CloseableHttpClient
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.quarkus.runtime.tracing.OTelTracingProviderFactory
import org.keycloak.tracing.TracingProvider

val KeycloakSession.tracingProvider: TracingProvider
  get() = getProvider(TracingProvider::class.java, OTelTracingProviderFactory.PROVIDER_ID)

val KeycloakSession.serverHost: String get() = context.authServerUrl.host

val KeycloakSession.clientIP: String?
  get() = Either.catch { resolveClientIP(context.connection?.remoteAddr) { context.requestHeaders?.getHeaderString(it) } }.getOrNull()

fun rememberLastClientIp(session: KeycloakSession, client: ClientModel) {
  session.clientIP?.let { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, it) }
}

/**
 * Allow the access token mapper to issue KVNR claims to [client] within the current request.
 *
 * Only the mobile PDP gate (or the reduced email-binding issuance) grants this permit. It lives on the
 * [KeycloakSession], i.e. it ends with the request, and is bound to a single client: any other grant reaching a
 * SekIDP user session (device code, standard token exchange, ...) can't mint a KVNR token.
 */
fun KeycloakSession.permitMobileIssuance(client: ClientModel) = setAttribute(ATTRIBUTE_MOBILE_ISSUANCE_PERMIT, client.id)

fun KeycloakSession.isMobileIssuancePermitted(client: ClientModel): Boolean =
    getAttribute(ATTRIBUTE_MOBILE_ISSUANCE_PERMIT, String::class.java) == client.id

// Request-scoped session attribute: internal id of the client that may receive KVNR claims within the current request.
// Private on purpose: the permit is only set and read through the two functions above.
private const val ATTRIBUTE_MOBILE_ISSUANCE_PERMIT = "zetaguard.mobile.issuance_permit"

fun Response.isSuccessStatus() = statusInfo.family == Response.Status.Family.SUCCESSFUL

fun KeycloakSession.getTracer(name: String): Tracer = tracingProvider.getTracer(name)

fun KeycloakSession.lookupHttpClient(providerName: String): CloseableHttpClient = getProvider(HttpClientProvider::class.java, providerName).httpClient
