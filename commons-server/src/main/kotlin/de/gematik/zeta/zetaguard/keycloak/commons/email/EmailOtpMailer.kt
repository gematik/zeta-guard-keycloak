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

import org.keycloak.email.EmailException
import org.keycloak.email.EmailSenderProvider
import org.keycloak.models.KeycloakSession

object EmailOtpMailer {
  @Throws(EmailException::class)
  fun send(session: KeycloakSession, email: String, otp: String) {
    val minutes = EMAIL_OTP_TTL_SECONDS / 60
    val subject = "Your email verification code"
    val textBody = "Your verification code is: $otp\n\nThis code expires in $minutes minutes."
    val htmlBody = "<p>Your verification code is: <strong>$otp</strong></p><p>This code expires in $minutes minutes.</p>"
    session.getProvider(EmailSenderProvider::class.java).send(session.context.realm.smtpConfig, email, subject, textBody, htmlBody)
  }
}
