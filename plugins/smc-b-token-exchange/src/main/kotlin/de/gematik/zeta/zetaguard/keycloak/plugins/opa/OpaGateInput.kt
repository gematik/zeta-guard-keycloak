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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaDeviceInfo

data class OpaGateInput(
    val clientId: String?,
    val clientPlatform: String?,
    val clientRegistrationTimestamp: Long?,
    val grantType: String?,
    val scopes: List<String>,
    val authenticationMethodsReferences: List<String>,
    val authenticationContextClassReference : String,
    val audiences: List<String>?,
    val ipAddress: String?,
    val previousIpAddress: String?,
    val postureType: String?,
    val clientProductID: String?,
    val clientProductVersion: String?,
    val userIdentifier: String?,
    val userProfessionOid: String?,
    val userCommonName: String? = null, // insured persons only (SekIDP); left null for SMC-B
    val deviceInfo: OpaDeviceInfo? = null,
)
