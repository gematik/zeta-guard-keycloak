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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import de.gematik.zeta.zetaguard.keycloak.commons.OID_VERSICHERTER
import de.gematik.zeta.zetaguard.keycloak.commons.PROFESSION_OIDS
import de.gematik.zeta.zetaguard.keycloak.commons.ProfessionOidValidator
import de.gematik.zeta.zetaguard.keycloak.commons.isBerufsgruppenOID
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe

/**
 * Expected values are taken from the spec tables, not from the implementation's OID sets.
 *
 * @see [gemSpec_OID: Tab_PKI_402-01 (Berufsgruppen) and Tab_PKI_403-04 (Institutionen SMC-B)](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html)
 */
class UserRoleTest : FunSpec({

  context("toUserRole() for persons (Tab_PKI_402-01)") {
    mapOf(
        "1.2.276.0.76.4.30" to "oid_arzt",
        "1.2.276.0.76.4.31" to "oid_zahnarzt",
        "1.2.276.0.76.4.32" to "oid_apotheker",
        "1.2.276.0.76.4.48" to "oid_rettungsassistent",
        "1.2.276.0.76.4.178" to "oid_notfallsanitaeter",
        "1.2.276.0.76.4.234" to "oid_pflegefachkraft-hpc",
        "1.2.276.0.76.4.277" to "oid_ernaehrungstherapeut-hpc",
    ).forEach { (oid, name) ->
      test("$name »$oid« is a Leistungserbringer") {
        oid.toUserRole() shouldBe UserRole.Leistungserbringer
      }
    }

    test("oid_versicherter »1.2.276.0.76.4.49« is a Versicherter") {
      "1.2.276.0.76.4.49".toUserRole() shouldBe UserRole.Versicherter
    }
  }

  context("toUserRole() for institutions (Tab_PKI_403-04, SMC-B)") {
    mapOf(
        "1.2.276.0.76.4.50" to "oid_praxis_arzt",
        "1.2.276.0.76.4.51" to "oid_zahnarztpraxis",
        "1.2.276.0.76.4.53" to "oid_krankenhaus",
        "1.2.276.0.76.4.54" to "oid_oeffentliche_apotheke",
        "1.2.276.0.76.4.244" to "oid_institution-pflege",
        "1.2.276.0.76.4.271" to "oid_praxis-ergotherapeut",
    ).forEach { (oid, name) ->
      test("$name »$oid« is a Leistungserbringer") {
        oid.toUserRole() shouldBe UserRole.Leistungserbringer
      }
    }
  }

  context("toUserRole() for OIDs that are no profession OID") {
    listOf(
        "1.2.276.0.76.4.29",   // just below the first entry of Tab_PKI_402-01
        "1.2.276.0.76.4.179",  // gap after oid_notfallsanitaeter
        "1.2.276.0.76.4.272",  // gap between Tab_PKI_403-04 entries
        "1.2.276.0.76.4.300",  // beyond both tables
        "1.2.276.0.76.5.30",   // other arc, same last number as oid_arzt
        "1.2.276.0.76.4.3",    // prefix of oid_arzt
        "1.2.276.0.76.4.30.1", // oid_arzt as prefix
        " 1.2.276.0.76.4.30",  // surrounding whitespace is not trimmed
        "1.2.276.0.76.4.30 ",
        "",
        "Arzt",
    ).forEach { oid ->
      test("»$oid« is Unbekannt") {
        oid.toUserRole() shouldBe UserRole.Unbekannt
      }
    }
  }

  context("toUserRole() for all OIDs of the tables") {
    test("Versicherter takes precedence although it is a Berufsgruppen OID") {
      OID_VERSICHERTER.isBerufsgruppenOID().shouldBeTrue()
      OID_VERSICHERTER.toUserRole() shouldBe UserRole.Versicherter
    }

    test("no OID from the tables maps to Unbekannt") {
      (PROFESSION_OIDS + ProfessionOidValidator.VALID_PROFESSION_OIDS_SMCB)
          .filter { it.toUserRole() == UserRole.Unbekannt }
          .shouldBeEmpty()
    }
  }

  context("toLoggableString()") {
    // These values end up in the »user.roles« attribute and are evaluated by the security KPI queries (A_25484-03)
    mapOf(
        UserRole.Leistungserbringer to "Leistungserbringer",
        UserRole.Versicherter to "Versicherter",
        UserRole.Unbekannt to "Unbekannt",
    ).forEach { (role, expected) ->
      test("$role is logged as »$expected«") {
        role.toLoggableString() shouldBe expected
      }
    }
  }
})
