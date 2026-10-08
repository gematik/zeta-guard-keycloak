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
package de.gematik.zeta.zetaguard.keycloak.commons.smcb

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaDeviceInfo
import java.beans.ConstructorProperties
import java.time.Duration

/**
 * Data gathered during token exchange and OPA decision process.
 *
 * Used, e.g., to generate access and refresh tokens
 */
@JsonIgnoreProperties(ignoreUnknown = true)
data class ZetaGuardTokenExchangeData
@ConstructorProperties(
    "authenticationMethodsReferences",
    "authenticationContextClassReference",
    "clientId",
    "clientPlatform",
    "clientRegistrationTimestamp",
    "postureType",
    "previousIpAddress",
    "telematikID",
    "professionOID",
    "subjectOrganisation",
    "subjectCommonName",
    "clientIP",
    "accessTokenTTL",
    "refreshTokenTTL",
    "audiences",
    "scopes",
    "deviceInfo",
)
constructor(
    val authenticationMethodsReferences: List<String>,
    val authenticationContextClassReference: String,
    val clientId: String,
    val clientPlatform: String,
    val clientRegistrationTimestamp: Long,
    val postureType: String,
    val previousIpAddress: String,
    val telematikID: String,
    val professionOID: String,
    val subjectOrganisation: String,
    val subjectCommonName: String,
    val clientIP: String,
    val accessTokenTTL: Duration,
    val refreshTokenTTL: Duration,
    // Nullable -> session notes written before these fields existed.
    val audiences: List<String>? = null,
    val scopes: List<String>? = null,
    val deviceInfo: OpaDeviceInfo? = null,
)
