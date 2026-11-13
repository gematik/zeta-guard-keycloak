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
package de.gematik.zeta.zetaguard.keycloak.commons

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldMatch
import io.kotest.matchers.string.shouldStartWith

/**
 * Expected classifications are taken from the spec tables, not from the implementation's OID sets.
 *
 * @see [gemSpec_OID: Tab_PKI_402-01 (Berufsgruppen) and Tab_PKI_403-04 (Institutionen SMC-B)](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html)
 */
class ObjectIdentifierTest : FunSpec({

  /** Expected results of [isBerufsgruppenOID], [isVersichertenOID] and [isInstitutsOID] */
  data class Classification(val berufsgruppe: Boolean = false, val versicherter: Boolean = false, val institut: Boolean = false)

  context("classification of OIDs") {
    listOf(
        Triple("1.2.276.0.76.4.30", "oid_arzt", Classification(berufsgruppe = true)),
        Triple("1.2.276.0.76.4.178", "oid_notfallsanitaeter", Classification(berufsgruppe = true)),
        Triple("1.2.276.0.76.4.277", "oid_ernaehrungstherapeut-hpc", Classification(berufsgruppe = true)),
        // oid_versicherter is listed in Tab_PKI_402-01, so it is a Berufsgruppen OID as well
        Triple("1.2.276.0.76.4.49", "oid_versicherter", Classification(berufsgruppe = true, versicherter = true)),
        Triple("1.2.276.0.76.4.50", "oid_praxis_arzt", Classification(institut = true)),
        Triple("1.2.276.0.76.4.53", "oid_krankenhaus", Classification(institut = true)),
        Triple("1.2.276.0.76.4.271", "oid_praxis-ergotherapeut", Classification(institut = true)),
        Triple("1.2.276.0.76.4.29", "no table entry", Classification()),
        Triple("1.2.276.0.76.4.272", "no table entry", Classification()),
        Triple("1.2.276.0.76.4.50.1", "oid_praxis_arzt as prefix", Classification()),
        Triple("", "empty string", Classification()),
    ).forEach { (oid, name, expected) ->
      test("$name »$oid« is classified as $expected") {
        Classification(
            berufsgruppe = oid.isBerufsgruppenOID(),
            versicherter = oid.isVersichertenOID(),
            institut = oid.isInstitutsOID(),
        ) shouldBe expected
      }
    }

    test("null is no OID of any kind") {
      null.isBerufsgruppenOID().shouldBeFalse()
      null.isVersichertenOID().shouldBeFalse()
      null.isInstitutsOID().shouldBeFalse()
    }
  }

  test("Berufsgruppen and Institutionen don't overlap") {
    (PROFESSION_OIDS intersect ProfessionOidValidator.VALID_PROFESSION_OIDS_SMCB).shouldBeEmpty()
  }

  test("PROFESSION_OIDS") {
    PROFESSION_OIDS shouldHaveSize 35
    PROFESSION_OIDS shouldContainAll setOf(
        "1.2.276.0.76.4.30",  // first in table
        OID_VERSICHERTER,
        "1.2.276.0.76.4.277", // last in table
    )
    PROFESSION_OIDS.forEach {
      it shouldStartWith "1.2.276.0.76.4."
      it shouldMatch "^(\\d{1,3}\\.){4}\\d{1,3}(\\.\\d{1,3})*$"
    }
  }

})
