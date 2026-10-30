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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.core.Response
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProvider

/**
 * ZF-0285 / CVE-2026-15572: the RFC 7592 update/delete resource endpoints are the attack surface
 * (the "Allowed Protocol Mapper Types" policy re-checks a mapper's type only on create, not on
 * update, so an attacker could register an allowed mapper and swap its type via PUT). These wrappers
 * keep create (POST) and read (GET) and drop update (PUT) and delete (DELETE).
 */
class ClientRegistrationResourceEndpointsTest : FunSpec() {
  init {
    test("oidc provider exposes create (POST) + read (GET) but no update (PUT) / delete (DELETE)") {
      val methods = ZetaGuardOIDCClientRegistrationProvider::class.java.declaredMethods
      methods.any { it.isAnnotationPresent(POST::class.java) } shouldBe true
      methods.any { it.isAnnotationPresent(GET::class.java) } shouldBe true
      methods.any { it.isAnnotationPresent(PUT::class.java) } shouldBe false
      methods.any { it.isAnnotationPresent(DELETE::class.java) } shouldBe false
    }

    test("oidc provider delegates create and read to the wrapped provider") {
      val delegate = mockk<OIDCClientRegistrationProvider>()
      val created = mockk<Response>()
      val read = mockk<Response>()
      every { delegate.createOIDC(any()) } returns created
      every { delegate.getOIDC(any()) } returns read

      val provider = ZetaGuardOIDCClientRegistrationProvider(delegate)

      provider.createOIDC(mockk<OIDCClientRepresentation>()) shouldBeSameInstanceAs created
      provider.getOIDC("a-client-id") shouldBeSameInstanceAs read
      verify { delegate.createOIDC(any()) }
      verify { delegate.getOIDC("a-client-id") }
    }
  }
}
