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

import de.gematik.zeta.zetaguard.keycloak.commons.isBerufsgruppenOID
import de.gematik.zeta.zetaguard.keycloak.commons.isInstitutsOID
import de.gematik.zeta.zetaguard.keycloak.commons.isVersichertenOID

/**
 * Used to distinguish user types for security KPI calculation.
 * UserRole is chosen based on the profession OID of authenticated users.
 * [Unbekannt] applies to unauthenticated users and users with unknown/invalid profession OIDs.
 * @see [A_25484-03 - Security Monitoring - Security KPIs](https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.3.2/#A_25484-03)
 */
enum class UserRole {
  Leistungserbringer, Unbekannt, Versicherter;

  fun toLoggableString(): String = when (this) {
    Leistungserbringer -> "Leistungserbringer"
    Versicherter -> "Versicherter"
    Unbekannt -> "Unbekannt"
  }
}

/**
 * Extracts a [UserRole] from a String-formatted profession OID.
 */
fun String.toUserRole(): UserRole = when {
  this.isVersichertenOID() -> UserRole.Versicherter
  this.isBerufsgruppenOID() -> UserRole.Leistungserbringer
  this.isInstitutsOID() -> UserRole.Leistungserbringer
  else -> UserRole.Unbekannt
}
