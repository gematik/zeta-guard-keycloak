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

import org.jboss.logging.Logger
import org.keycloak.email.EmailException
import org.keycloak.email.EmailSenderProvider
import org.keycloak.models.KeycloakSession

/**
 * Notifies the OLD address after an identity-scoped email change (A_25750, [zeta-guard-client-management]) — the
 * identity owner's primary chance to detect a hostile takeover of the email factor F1.
 *
 * Best effort: the change is already durable when this runs, so a mail failure is logged but never fails the
 * request (hardcoded German body, like EmailOTPMailer — proper templates come with the EmailTemplateProvider).
 */
object EmailChangeNotifier {
  private val logger: Logger = Logger.getLogger(EmailChangeNotifier::class.java)


  fun notifyOldAddress(session: KeycloakSession, oldEmail: String) {
    val subject = "Ihre E-Mail-Adresse wurde geändert"
    val textBody =
        "Die mit Ihrer Identität verknüpfte E-Mail-Adresse wurde geändert.\n\n" +
            "Falls Sie diese Änderung nicht veranlasst haben, wenden Sie sich bitte umgehend an den Support Ihres Anbieters."
    val htmlBody =
        "<p>Die mit Ihrer Identität verknüpfte E-Mail-Adresse wurde geändert.</p>" +
            "<p><strong>Falls Sie diese Änderung nicht veranlasst haben, wenden Sie sich bitte umgehend an den Support Ihres Anbieters.</strong></p>"
    try {
      session.getProvider(EmailSenderProvider::class.java).send(session.context.realm.smtpConfig, oldEmail, subject, textBody, htmlBody)
    } catch (e: EmailException) {
      logger.errorf(e, "Failed to notify the previous address about an identity email change (A_25750)")
    }
  }
}
