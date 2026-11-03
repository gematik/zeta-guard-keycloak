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

import de.gematik.zeta.zetaguard.keycloak.commons.OTPUtil.createOTP
import org.keycloak.models.KeycloakSession

const val EMAIL_OTP_TTL_SECONDS = 300L

/** Key prefix in Keycloak's single-use object store; the entry of one client is `PREFIX + clientId`. */
const val EMAIL_OTP_STORE_PREFIX = "zeta-email-otp:"

private const val KEY_OTP = "otp"

object EmailOTPService {
  fun issue(session: KeycloakSession, clientId: String) = createOTP().also {
    session.singleUseObjects().put(key(clientId), EMAIL_OTP_TTL_SECONDS, mapOf(KEY_OTP to it))
  }

  fun verify(session: KeycloakSession, clientId: String, code: String?): Boolean {
    if (code.isNullOrBlank()) {
      return false
    }

    val singleUseObjectProvider = session.singleUseObjects()
    val key = key(clientId)
    val stored = singleUseObjectProvider[key]?.get(KEY_OTP) ?: return false

    if (stored != code) {
      return false
    }

    singleUseObjectProvider.remove(key)
    return true
  }

  /** Drops an open challenge of [clientId], if any, e.g. when the client is deleted. */
  fun invalidate(session: KeycloakSession, clientId: String) {
    session.singleUseObjects().remove(key(clientId))
  }

  private fun key(clientId: String) = EMAIL_OTP_STORE_PREFIX + clientId
}
