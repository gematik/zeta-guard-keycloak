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
package de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning

/**
 * Signals that HSM-backed token signing is required but no active HSM key is usable for the requested algorithm.
 *
 * Allowed to propagate out of [HsmTokenSigningKeyProviderFactory.createFallbackKeys] so Keycloak returns a 5xx to the client instead of inventing a
 * software signing key. The gematik/BSI contract for this deployment forbids any software fallback for the realm signing key.
 */
class HsmUnavailableException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
