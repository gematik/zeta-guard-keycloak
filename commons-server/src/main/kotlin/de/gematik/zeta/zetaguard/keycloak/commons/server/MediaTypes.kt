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

/** Media types used by 𝝵-Guard that `jakarta.ws.rs.core.MediaType` does not define. */
object MediaTypes {
  /** RFC 9457 Problem Details, required by the client-management API ([zeta-guard-client-management], Error schema). */
  const val PROBLEM_JSON = "application/problem+json"

  /** RFC 7519 JWT; Keycloak's well-known endpoint answers a String config with it. */
  const val JWT = "application/jwt"

  /** Entity configuration (OpenID Federation 1.1, "Federation Entity Configuration Response"). */
  const val ENTITY_STATEMENT_JWT = "application/entity-statement+jwt"

  /** RFC 6960 OCSP request. */
  const val OCSP_REQUEST = "application/ocsp-request"
}
