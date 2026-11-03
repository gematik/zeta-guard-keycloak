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
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.slot
import org.keycloak.email.EmailSenderProvider
import org.keycloak.models.KeycloakSession

private const val EMAIL = "kvnr-user@example.de"
private const val SUPPORT = "wenden Sie sich bitte umgehend an den Support"

/** The N3 text explains why a client was removed, and only points to the support where the user may not have caused it. */
class ClientNotifierTest :
    StringSpec({
      val text = slot<String>()
      val html = slot<String>()

      val sender = mockk<EmailSenderProvider> { justRun { send(any(), EMAIL, any(), capture(text), capture(html)) } }
      val session =
          mockk<KeycloakSession>(relaxed = true) {
            every { getProvider(EmailSenderProvider::class.java) } returns sender
          }

      fun removed(reason: ClientRemovalReason?) = ClientNotifier.notifyClientRemoved(session, EMAIL, "Old phone", reason)

      "a removal by the user names the device and points to the support" {
        removed(ClientRemovalReason.USER_REQUEST)

        text.captured shouldContain "Ein Gerät wurde von Ihrer Identität entfernt: Old phone."
        text.captured shouldContain SUPPORT
      }

      "an expired client is explained and needs no support" {
        removed(ClientRemovalReason.EXPIRED)

        text.captured shouldContain "längere Zeit nicht verwendet"
        text.captured shouldNotContain SUPPORT
      }

      "an eviction points to the support only for a device the user did not sign in" {
        removed(ClientRemovalReason.MAX_CLIENTS_EXCEEDED)

        text.captured shouldContain "maximale Anzahl an Geräten"
        text.captured shouldContain "Falls Sie kein neues Gerät angemeldet haben"
      }

      "a client removed by an email change is explained" {
        removed(ClientRemovalReason.EMAIL_CHANGE_PENDING)

        text.captured shouldContain "noch nicht abgeschlossen"
      }

      "an unknown reason is treated like a removal by the user" {
        removed(null)

        text.captured shouldContain SUPPORT
      }

      "the device name is escaped in the html body" {
        ClientNotifier.notifyClientRemoved(session, EMAIL, "<b>Phone</b>", ClientRemovalReason.USER_REQUEST)

        html.captured shouldContain "&lt;b&gt;Phone&lt;/b&gt;"
        html.captured shouldNotContain "<b>Phone</b>"
      }
    })
