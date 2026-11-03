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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import org.keycloak.cookie.CookieProvider
import org.keycloak.cookie.CookieType
import org.keycloak.models.KeycloakSession

/** Keycloak's cookie provider, extended for the cookie-free Redirection Endpoint. */
class ZetaCookieProvider(private val session: KeycloakSession, private val delegate: CookieProvider) : CookieProvider by delegate {

  private val cookieValueByStateAs = AuthSessionCookieValueByStateAs(session)

  /**
   * Only the SekIDP's Redirection Endpoint sets this attribute. Every other
   * login (admin console, account console, other identity providers) finds it null and keeps its cookie.
   */
  override fun get(cookieType: CookieType): String? {
    if (cookieType != CookieType.AUTH_SESSION_ID) return delegate[cookieType]

    val stateAs = session.getAttribute(ATTRIBUTE_STATE_AS, String::class.java) ?: return delegate[cookieType]

    return cookieValueByStateAs.lookup(stateAs)
  }

  companion object {
    /** Session attribute key under which the Redirection Endpoint hands over `state_as`. */
    private const val ATTRIBUTE_STATE_AS = "zeta.state_as"

    /** Attaches [stateAs] to the request's [KeycloakSession] */
    fun attachStateAsToSession(session: KeycloakSession, stateAs: String) = session.setAttribute(ATTRIBUTE_STATE_AS, stateAs)
  }
}
