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
package de.gematik.zeta.zetaguard.keycloak.commons.opa

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import java.beans.ConstructorProperties
import java.time.Duration

@JsonIgnoreProperties(ignoreUnknown = true)
data class OpaSessionContext
@ConstructorProperties(
    "accessTokenTTL",
    "refreshTokenTTL",
    "scopes",
    "audiences",
    "clientId",
    "clientPlatform",
    "clientRegistrationTimestamp",
    "postureType",
    "clientProductID",
    "clientProductVersion",
    "authenticationMethodsReferences",
    "authenticationContextClassReference",
    "userIdentifier",
    "userProfessionOid",
    "userCommonName",
    "deviceInfo",
)
constructor(
    val accessTokenTTL: Duration,
    val refreshTokenTTL: Duration,
    val scopes: List<String>? = null,
    val audiences: List<String>? = null,
    val clientId: String? = null,
    val clientPlatform: String? = null,
    val clientRegistrationTimestamp: Long? = null,
    val postureType: String? = null,
    val clientProductID: String? = null,
    val clientProductVersion: String? = null,
    val authenticationMethodsReferences: List<String>? = null,
    val authenticationContextClassReference: String,
    val userIdentifier: String? = null,
    val userProfessionOid: String? = null,
    val userCommonName: String? = null,
    val deviceInfo: OpaDeviceInfo? = null,
)

fun opaTtlDurations(accessTtl: Int?, refreshTtl: Int?): Pair<Duration, Duration>? {
  if (accessTtl == null || refreshTtl == null) {
    logger.warnf("OPA returned partial TTLs (access=%s, refresh=%s) — skip note update!", accessTtl, refreshTtl)
    return null
  }
  return Duration.ofSeconds(accessTtl.toLong()) to Duration.ofSeconds(refreshTtl.toLong())
}
