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

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.keycloak.cookie.CookieProvider
import org.keycloak.cookie.CookieType
import org.keycloak.crypto.SignatureProvider
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.models.Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.SingleUseObjectProvider
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.RootAuthenticationSessionModel
import org.keycloak.sessions.StickySessionEncoderProvider

private const val STATE_AS = "state-as-minted-by-the-guard"
private const val ROOT_AUTH_SESSION_ID = "4f1c2a6e-root-auth-session"
private const val LOGIN_TIMEOUT_SECONDS = 1800

/** The route a clustered Keycloak appends to the session id. */
private const val ROUTE = "node1"

/**
 * Maps `state_as` to the `AUTH_SESSION_ID` cookie value, because the Redirection Endpoint receives no cookie (A_29671).
 *
 * The stored value must equal what [AuthenticationSessionManager] writes into that cookie.
 */
class AuthSessionCookieValueByStateAsTest : ZetaGuardFunSpec() {

  init {
    test("stores the value Keycloak would have written into the AUTH_SESSION_ID cookie") {
      val fixture = Fixture()

      AuthSessionCookieValueByStateAs(fixture.session).store(STATE_AS, fixture.authSession)

      fixture.singleUseStore["zeta-state-as:$STATE_AS"].shouldNotBeNull()["auth_session_id"] shouldBe fixture.cookieValueKeycloakWouldSet()
    }

    test("the entry lives as long as the realm's login timeout") {
      val fixture = Fixture()

      AuthSessionCookieValueByStateAs(fixture.session).store(STATE_AS, fixture.authSession)

      val ttl = slot<Long>()
      verify { fixture.singleUse.put("zeta-state-as:$STATE_AS", capture(ttl), any()) }
      ttl.captured shouldBe LOGIN_TIMEOUT_SECONDS.toLong()
    }

    test("lookup hands the stored value back without consuming it") {
      val fixture = Fixture()
      val mapping = AuthSessionCookieValueByStateAs(fixture.session)
      mapping.store(STATE_AS, fixture.authSession)

      mapping.lookup(STATE_AS) shouldBe fixture.cookieValueKeycloakWouldSet()
      mapping.lookup(STATE_AS) shouldBe fixture.cookieValueKeycloakWouldSet()
    }

    test("lookup of an unknown state_as is null") {
      val fixture = Fixture()

      AuthSessionCookieValueByStateAs(fixture.session).lookup("unknown-state").shouldBeNull()
    }

    test("remove takes the entry out once: true the first time, false afterwards, nothing left to look up") {
      val fixture = Fixture()
      val mapping = AuthSessionCookieValueByStateAs(fixture.session)
      mapping.store(STATE_AS, fixture.authSession)

      mapping.remove(STATE_AS) shouldBe true

      mapping.remove(STATE_AS) shouldBe false
      mapping.lookup(STATE_AS).shouldBeNull()
    }

    test("remove of a state_as that was never stored is false") {
      val fixture = Fixture()

      AuthSessionCookieValueByStateAs(fixture.session).remove("unknown-state") shouldBe false
    }
  }

  /** A session with the providers the mapping and Keycloak's cookie writer share. */
  private class Fixture {
    val singleUseStore = linkedMapOf<String, Map<String, String>>()
    val singleUse =
        mockk<SingleUseObjectProvider>().also {
          every { it.put(any(), any(), any()) } answers { singleUseStore[firstArg()] = thirdArg<Map<String, String>>().toMap() }
          every { it[any()] } answers { singleUseStore[firstArg()] }
          every { it.remove(any()) } answers { singleUseStore.remove(firstArg()) }
        }

    val realm = mockk<RealmModel>().also { every { it.accessCodeLifespanLogin } returns LOGIN_TIMEOUT_SECONDS }

    val authSession =
        mockk<AuthenticationSessionModel>().also {
          every { it.parentSession } returns mockk<RootAuthenticationSessionModel>().also { root -> every { root.id } returns ROOT_AUTH_SESSION_ID }
          every { it.realm } returns realm
        }

    // Deterministic stand-in for the realm's HS512 key.
    private val signer =
        mockk<SignatureSignerContext>().also {
          every { it.kid } returns "internal-key"
          every { it.sign(any()) } answers { "signature-over-".toByteArray() + firstArg<ByteArray>() }
        }

    private val stickyEncoder =
        mockk<StickySessionEncoderProvider>().also { every { it.encodeSessionId(any(), any()) } answers { "${firstArg<String>()}.$ROUTE" } }

    val session =
        mockk<KeycloakSession>().also {
          every { it.singleUseObjects() } returns singleUse
          every { it.getProvider(SignatureProvider::class.java, Constants.INTERNAL_SIGNATURE_ALGORITHM) } returns
              mockk<SignatureProvider>().also { provider -> every { provider.signer() } returns signer }
          every { it.getProvider(StickySessionEncoderProvider::class.java) } returns stickyEncoder
        }

    /** What Keycloak's own cookie writer would set. */
    fun cookieValueKeycloakWouldSet(): String {
      val written = slot<String>()
      val cookies = mockk<CookieProvider>().also { every { it.set(CookieType.AUTH_SESSION_ID, capture(written)) } returns Unit }
      every { session.getProvider(CookieProvider::class.java) } returns cookies

      AuthenticationSessionManager(session).setAuthSessionCookie(ROOT_AUTH_SESSION_ID)

      return written.captured
    }
  }
}
