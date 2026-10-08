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
package de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding

import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import java.util.stream.Stream
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientScopeModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.services.util.DefaultClientSessionContext

class EmailBindingScopesTest : FunSpec() {
  init {
    test("withTokenScopesReducedTo keeps defaults and adds requested binding scopes") {
      mockkStatic(DefaultClientSessionContext::class)
      mockkStatic(KeycloakModelUtils::class)
      try {
        val session = mockk<KeycloakSession>()
        val realm = mockk<RealmModel>()
        val client = mockk<ClientModel>()
        val clientSession = mockk<AuthenticatedClientSessionModel>()
        every { clientSession.client } returns client
        every { clientSession.realm } returns realm

        val defaultScope = scope("roles", "d1", includeInToken = false)
        every { client.getClientScopes(true) } returns mapOf("roles" to defaultScope)

        val openid = scope("openid", "1", includeInToken = true)
        val emailBinding = scope(SCOPE_EMAIL_BINDING, "2", includeInToken = true)
        every { KeycloakModelUtils.getClientScopeByName(realm, SCOPE_EMAIL_BINDING) } returns emailBinding

        val source = mockk<ClientSessionContext>()
        every { source.clientSession } returns clientSession
        every { source.clientScopesStream } returns Stream.of(openid, defaultScope)

        val reduced = mockk<DefaultClientSessionContext>()
        every {
          DefaultClientSessionContext.fromClientSessionAndClientScopes(clientSession, any(), null, session)
        } answers
            {
              val kept = secondArg<Set<ClientScopeModel>>()
              kept.map { it.name }.toSet() shouldContainExactlyInAnyOrder setOf("roles", SCOPE_EMAIL_BINDING)
              reduced
            }

        source.withTokenScopesReducedTo(session, setOf(SCOPE_EMAIL_BINDING)).shouldBeInstanceOf<DefaultClientSessionContext>()
      } finally {
        unmockkStatic(DefaultClientSessionContext::class)
        unmockkStatic(KeycloakModelUtils::class)
      }
    }

    test("withTokenScopesReducedTo fails when requested scope is missing") {
      mockkStatic(KeycloakModelUtils::class)
      try {
        val session = mockk<KeycloakSession>()
        val realm = mockk<RealmModel>()
        val client = mockk<ClientModel>()
        val clientSession = mockk<AuthenticatedClientSessionModel>()
        every { clientSession.client } returns client
        every { clientSession.realm } returns realm
        every { client.getClientScopes(true) } returns emptyMap()
        every { KeycloakModelUtils.getClientScopeByName(realm, SCOPE_EMAIL_BINDING) } returns null

        val source = mockk<ClientSessionContext>()
        every { source.clientSession } returns clientSession
        every { source.clientScopesStream } returns Stream.empty()

        val ex =
            shouldThrow<IllegalStateException> {
              source.withTokenScopesReducedTo(session, setOf(SCOPE_EMAIL_BINDING))
            }
        ex.message shouldBe "Client scope '$SCOPE_EMAIL_BINDING' not found."
      } finally {
        unmockkStatic(KeycloakModelUtils::class)
      }
    }
  }

  private fun scope(name: String, id: String, includeInToken: Boolean): ClientScopeModel {
    val scope = mockk<ClientScopeModel>()
    every { scope.name } returns name
    every { scope.id } returns id
    every { scope.isIncludeInTokenScope } returns includeInToken
    return scope
  }
}
