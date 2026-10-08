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
package de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange

import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

class ZetaGuardTokenExchangeProviderTest :
    StringSpec({
      "readClientStatement returns the map when the claim is a proper object" {
        val statement = mapOf("sub" to "abc")
        val claims = mapOf(CLAIM_CLIENT_STATEMENT to statement)
        claims.readClientStatement() shouldBe statement
      }

      "readClientStatement returns null when the claim is absent" {
        val claims = emptyMap<String, Any>()
        claims.readClientStatement() shouldBe null
      }

      // A_26661: a client_statement re-encoded as a JSON string (e.g. "{}") instead of an object must be rejected
      // with a normal validation error (-> HTTP 400), not crash the request with an uncaught ClassCastException
      // (-> HTTP 500 "unknown_error").
      "readClientStatement returns null, not a ClassCastException, when the claim is a JSON string instead of an object" {
        val claims = mapOf(CLAIM_CLIENT_STATEMENT to "{}")
        claims.readClientStatement() shouldBe null
      }
    })
