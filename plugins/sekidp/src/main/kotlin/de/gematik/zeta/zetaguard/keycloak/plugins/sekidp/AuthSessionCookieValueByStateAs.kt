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

import org.keycloak.models.KeycloakSession
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.StickySessionEncoderProvider

/** Key prefix in Keycloak's single-use object store. */
private const val STATE_AS_STORE_PREFIX = "zeta-state-as:"

/** Field of the stored entry: the root session id, encoded like the `AUTH_SESSION_ID` cookie. */
private const val FIELD_AUTH_SESSION_ID = "auth_session_id"

/** Maps `state_as` to the `AUTH_SESSION_ID` cookie value. */
class AuthSessionCookieValueByStateAs(private val session: KeycloakSession) {

  /**
   * Stores [authSession] under [stateAs].
   *
   * The value is built like the `AUTH_SESSION_ID` cookie: root session id, signed, plus sticky route.
   * Mirrors [AuthenticationSessionManager.setAuthSessionCookie].
   */
  fun store(stateAs: String, authSession: AuthenticationSessionModel) {
    val rootSessionId = authSession.parentSession.id
    val signed = AuthenticationSessionManager(session).signAndEncodeToBase64AuthSessionId(rootSessionId)
    val encodedRootSessionId = session.getProvider(StickySessionEncoderProvider::class.java).encodeSessionId(signed, rootSessionId)
    val ttlSeconds = authSession.realm.accessCodeLifespanLogin.toLong()

    session.singleUseObjects().put(keyWithPrefix(stateAs), ttlSeconds, mapOf(FIELD_AUTH_SESSION_ID to encodedRootSessionId))
  }

  /** The `AUTH_SESSION_ID` value for [stateAs], or null when unknown, expired or already used. */
  fun lookup(stateAs: String): String? = session.singleUseObjects()[keyWithPrefix(stateAs)]?.get(FIELD_AUTH_SESSION_ID)

  /** Removes the entry; true exactly once per `state_as`, atomic across nodes. */
  fun remove(stateAs: String): Boolean = session.singleUseObjects().remove(keyWithPrefix(stateAs)) != null

  private fun keyWithPrefix(stateAs: String) = STATE_AS_STORE_PREFIX + stateAs
}
