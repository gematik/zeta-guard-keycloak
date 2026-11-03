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

import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import org.jboss.logging.Logger
import org.keycloak.email.EmailException
import org.keycloak.email.EmailSenderProvider
import org.keycloak.models.KeycloakSession

/**
 * Notifies the identity's address when a client is added to or removed from it (N1 `client_added`, N3 `client_removed`, A_<tas>007).
 *
 * Best effort, like [EmailChangeNotifier]: the change is already committed when this runs.
 */
private const val NOT_YOU_HINT = "Falls Sie diese Änderung nicht veranlasst haben, wenden Sie sich bitte umgehend an den Support Ihres Anbieters."

object ClientNotifier {
  private val logger: Logger = Logger.getLogger(ClientNotifier::class.java)

  /** N1 `client_added`. */
  fun notifyClientAdded(session: KeycloakSession, email: String, clientName: String?) =
      send(
          session,
          email,
          subject = "Neues Gerät hinzugefügt",
          text = "Ihrer Identität wurde ein neues Gerät hinzugefügt: ${clientName.orUnnamed()}.",
          hint = NOT_YOU_HINT,
      )

  /** N3 `client_removed`; the explanation depends on [reason], unknown reasons are treated like a removal by the user. */
  fun notifyClientRemoved(session: KeycloakSession, email: String, clientName: String?, reason: ClientRemovalReason?) {
    val removed = "Ein Gerät wurde von Ihrer Identität entfernt: ${clientName.orUnnamed()}."

    val (text, hint) =
        when (reason) {
          ClientRemovalReason.EXPIRED -> "$removed Es wurde längere Zeit nicht verwendet." to "Sie können es bei Bedarf erneut registrieren."
          ClientRemovalReason.MAX_CLIENTS_EXCEEDED ->
              "$removed Die maximale Anzahl an Geräten war erreicht, als ein neues Gerät angemeldet wurde; dafür wurde das am längsten nicht " +
                  "verwendete Gerät entfernt." to
                  "Falls Sie kein neues Gerät angemeldet haben, wenden Sie sich bitte umgehend an den Support Ihres Anbieters."
          ClientRemovalReason.EMAIL_CHANGE_PENDING ->
              "$removed Seine Registrierung war noch nicht abgeschlossen, als die E-Mail-Adresse Ihrer Identität geändert wurde." to NOT_YOU_HINT
          ClientRemovalReason.USER_REQUEST,
          null -> removed to NOT_YOU_HINT
        }

    send(session, email, subject = "Gerät entfernt", text = text, hint = hint)
  }

  private fun send(session: KeycloakSession, email: String, subject: String, text: String, hint: String) {
    val textBody = "$text\n\n$hint"
    val htmlBody = "<p>${text.escapeHtml()}</p><p><strong>$hint</strong></p>"

    try {
      session.getProvider(EmailSenderProvider::class.java).send(session.context.realm.smtpConfig, email, subject, textBody, htmlBody)
    } catch (e: EmailException) {
      logger.errorf(e, "Failed to send the notification »%s«", subject)
    }
  }

  private fun String?.orUnnamed() = this?.takeIf { it.isNotBlank() } ?: "unbenanntes Gerät"

  private fun String.escapeHtml() = replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}
