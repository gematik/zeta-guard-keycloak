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
package de.gematik.zeta.zetaguard.keycloak.plugins.revocation

import com.fasterxml.jackson.databind.ObjectMapper
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe

/** The field names are the contract with the PEP (see its `block_list::Block`), so they are asserted literally rather than through a round-trip. */
class BlockTest :
    StringSpec({
      val block = Block(`when` = 1786020754, until = 1786021034, what = "mzEPAZMnxCwiDaN8D7DVDi91")

      "serializes to exactly the three fields the PEP parses" {
        val fields = ObjectMapper().readTree(block.toJson()).fieldNames().asSequence().toList()

        fields shouldContainExactlyInAnyOrder listOf("when", "until", "what")
      }

      "survives a round trip" { Block.fromJson(block.toJson()) shouldBe block }

      "reads a block that carries unknown fields" {
        val json = """{"when":1,"until":2,"what":"sid","future":"ignored"}"""

        Block.fromJson(json) shouldBe Block(`when` = 1, until = 2, what = "sid")
      }
    })
