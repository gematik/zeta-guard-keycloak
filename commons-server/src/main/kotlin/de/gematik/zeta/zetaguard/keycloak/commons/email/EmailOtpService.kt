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
package de.gematik.zeta.zetaguard.keycloak.commons.email

import java.security.SecureRandom
import org.keycloak.models.KeycloakSession

const val EMAIL_OTP_TTL_SECONDS = 300L
const val EMAIL_OTP_LENGTH = 6

/** Key prefix in Keycloak's single-use object store; the entry of one client is `PREFIX + clientId`. */
const val EMAIL_OTP_STORE_PREFIX = "zeta-email-otp:"

object EmailOtpService {
  private val random = SecureRandom()

  fun issue(session: KeycloakSession, clientId: String): String {
    val otp = (1..EMAIL_OTP_LENGTH).joinToString("") { random.nextInt(10).toString() }
    session.singleUseObjects().put(key(clientId), EMAIL_OTP_TTL_SECONDS, mapOf("otp" to otp))
    return otp
  }

  fun verify(session: KeycloakSession, clientId: String, code: String?): Boolean {
    if (code.isNullOrBlank()) return false
    val stored = session.singleUseObjects()[key(clientId)]?.get("otp") ?: return false
    if (stored != code) return false
    session.singleUseObjects().remove(key(clientId))
    return true
  }

  private fun key(clientId: String) = EMAIL_OTP_STORE_PREFIX + clientId
}

/** Mask an email for an informative hint, e.g. "alice@domain.de" -> "a*@d*.de". Shared by the grant + endpoints. */
fun maskEmail(email: String): String {
  val (local, domain) = email.split("@", limit = 2).takeIf { it.size == 2 } ?: return "*"
  val domainParts = domain.split(".", limit = 2)
  val host = domainParts[0]
  val suffix = domainParts.getOrNull(1)?.let { ".$it" }.orEmpty()
  return "${local.firstOrNull() ?: '*'}*@${host.firstOrNull() ?: '*'}*$suffix"
}
