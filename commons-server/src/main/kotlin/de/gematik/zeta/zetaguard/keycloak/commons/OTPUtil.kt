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
package de.gematik.zeta.zetaguard.keycloak.commons

import java.security.SecureRandom

private const val EMAIL_OTP_UPPER_BOUND = 1_000_000 // 6-digit OTP

@Suppress("unused")
object OTPUtil {
  private val random = SecureRandom()

  fun createOTP() = "%06d".format(random.nextInt(EMAIL_OTP_UPPER_BOUND))
}

/**
 * Mask an email for an informative hint, e.g. "alice@domain.de" → "a*@d*.de".
 *
 * See [https://en.wikipedia.org/wiki/Email_address#Examples] for weird examples
 */
fun String.maskEmail(): String {
  if ('@' !in this) return "*"

  val domain = substringAfterLast('@')
  val host = domain.substringBeforeLast('.')
  val tld = domain.removePrefix(host) // ".de" or "" if domain has no dot

  return substringBeforeLast('@').maskParts() + "@" + host.maskParts() + tld
}

private fun String.maskParts() = split('.').joinToString(".") { (it.firstOrNull() ?: '*') + "*" }
