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
package de.gematik.zeta.zetaguard.keycloak.plugins.mobile

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import jakarta.ws.rs.core.MultivaluedHashMap
import org.keycloak.OAuth2Constants
import org.keycloak.models.AuthenticatedClientSessionModel

class MobileOpaGateTest : FunSpec() {
  init {
    test("splitSpaceSeparated splits space-separated values and drops blanks") {
      MobileOpaGate.splitSpaceSeparated("openid  profile ") shouldBe listOf("openid", "profile")
      MobileOpaGate.splitSpaceSeparated(null) shouldBe emptyList()
      MobileOpaGate.splitSpaceSeparated("  ") shouldBe emptyList()
    }

    test("scopesOf prefers requested scopes over client-session note") {
      val clientSession = mockk<AuthenticatedClientSessionModel>()
      every { clientSession.getNote(OAuth2Constants.SCOPE) } returns "openid profile"

      MobileOpaGate.scopesOf("openid email", clientSession) shouldBe listOf("openid", "email")
    }

    test("scopesOf reads client-session scope note when request is empty") {
      val clientSession = mockk<AuthenticatedClientSessionModel>()
      every { clientSession.getNote(OAuth2Constants.SCOPE) } returns "openid profile"

      MobileOpaGate.scopesOf(null, clientSession) shouldBe listOf("openid", "profile")
      MobileOpaGate.scopesOf("  ", clientSession) shouldBe listOf("openid", "profile")
    }

    test("audiencesOf prefers client-session audience note") {
      val clientSession = mockk<AuthenticatedClientSessionModel>()
      every { clientSession.getNote(OAuth2Constants.AUDIENCE) } returns "https://a.example,https://b.example"

      MobileOpaGate.audiencesOf(clientSession) shouldBe listOf("https://a.example", "https://b.example")
    }

    test("audiencesOf prefers form params over client session") {
      val clientSession = mockk<AuthenticatedClientSessionModel>()
      every { clientSession.getNote(any()) } returns "https://session.example"
      val formParams = MultivaluedHashMap<String, String>()
      formParams.putSingle(OAuth2Constants.AUDIENCE, "https://form.example")

      MobileOpaGate.audiencesOf(formParams, clientSession) shouldBe listOf("https://form.example")
    }

    test("audiencesOf reads form audience when client session is missing") {
      val formParams = MultivaluedHashMap<String, String>()
      formParams.putSingle(OAuth2Constants.AUDIENCE, "requiredFDaud")

      MobileOpaGate.audiencesOf(formParams, null) shouldBe listOf("requiredFDaud")
    }

    test("audiencesOf falls back to client-session note when form audience is empty") {
      val clientSession = mockk<AuthenticatedClientSessionModel>()
      every { clientSession.getNote(OAuth2Constants.AUDIENCE) } returns "https://note.example"
      val formParams = MultivaluedHashMap<String, String>()

      MobileOpaGate.audiencesOf(formParams, clientSession) shouldBe listOf("https://note.example")
      formParams.putSingle(OAuth2Constants.AUDIENCE, "  ")
      MobileOpaGate.audiencesOf(formParams, clientSession) shouldBe listOf("https://note.example")
    }
  }
}
