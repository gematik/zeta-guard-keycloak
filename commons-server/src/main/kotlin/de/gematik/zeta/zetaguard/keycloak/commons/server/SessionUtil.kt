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

import de.gematik.zeta.zetaguard.keycloak.commons.resolveClientIP
import io.opentelemetry.api.trace.Tracer
import jakarta.ws.rs.core.Response
import org.apache.http.impl.client.CloseableHttpClient
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.quarkus.runtime.tracing.OTelTracingProviderFactory
import org.keycloak.tracing.TracingProvider

val KeycloakSession.httpClient: CloseableHttpClient
  get() = getProvider(HttpClientProvider::class.java)?.httpClient ?: throw IllegalStateException("HTTP client not available")

val KeycloakSession.tracingProvider: TracingProvider
  get() = getProvider(TracingProvider::class.java, OTelTracingProviderFactory.PROVIDER_ID)

val KeycloakSession.serverHost: String get() = context.authServerUrl.host

val KeycloakSession.clientIP: String?
  get() = runCatching { resolveClientIP(context.connection?.remoteAddr) { context.requestHeaders?.getHeaderString(it) } }.getOrNull()

fun rememberLastClientIp(session: KeycloakSession, client: ClientModel) {
  session.clientIP?.let { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, it) }
}

fun Response.isSuccessStatus() = statusInfo.family == Response.Status.Family.SUCCESSFUL

fun KeycloakSession.getTracer(name: String): Tracer = tracingProvider.getTracer(name)
