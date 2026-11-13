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

import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.oidc.ZetaGuardOIDCClientRegistrationProvider
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT

/**
 * The RFC 7592 update/delete resource endpoints are the attack surface of ZF-0285 / CVE-2026-15572 (mapper type swap on update) and of ZF-0277
 * (a client registered without redirect_uris adds them afterwards while its ZETA client data still says SMC_B): neither PUT nor DELETE may be
 * exposed, only create (POST) and read (GET).
 */
class ClientRegistrationResourceEndpointsTest : FunSpec() {
  init {
    test("oidc provider exposes create (POST) + read (GET) but no update (PUT) / delete (DELETE)") {
      // Including superclasses and interfaces: JAX-RS inherits the endpoints of whatever the provider extends or implements
      val methods = generateSequence(listOf<Class<*>>(ZetaGuardOIDCClientRegistrationProvider::class.java)) { types ->
        types.flatMap { listOfNotNull(it.superclass) + it.interfaces }.ifEmpty { null }
      }.flatten().flatMap { it.declaredMethods.asList() }.toList()

      methods.filter { it.isAnnotationPresent(PUT::class.java) }.shouldBeEmpty()
      methods.filter { it.isAnnotationPresent(DELETE::class.java) }.shouldBeEmpty()
      // Guards against the check passing vacuously
      methods.filter { it.isAnnotationPresent(POST::class.java) }.shouldNotBeEmpty()
      methods.filter { it.isAnnotationPresent(GET::class.java) }.shouldNotBeEmpty()
    }
  }
}
