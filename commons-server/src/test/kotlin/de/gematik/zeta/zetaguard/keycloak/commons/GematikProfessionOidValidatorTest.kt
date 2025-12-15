/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

import de.gematik.zeta.zetaguard.keycloak.commons.server.betriebsstaetteArzt
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class GematikProfessionOidValidatorTest : FunSpec() {
  init {
    test("Validate profession OID format") {
      ProfessionOidValidator.isValidProfessionOidFormat("1.2.276.0") shouldBe false
      ProfessionOidValidator.isValidProfessionOidFormat("jens") shouldBe false
      ProfessionOidValidator.isValidProfessionOidFormat("1.2.276.0.76") shouldBe true
      ProfessionOidValidator.isValidProfessionOidFormat(betriebsstaetteArzt.id) shouldBe true
      ProfessionOidValidator.isValidProfessionOidFormat("100.20.276.032.76.4.50") shouldBe true
      ProfessionOidValidator.isValidProfessionOidFormat("100.20.276.032.76.4.50.100.87.76.999") shouldBe true

      for (oid in ProfessionOidValidator.VALID_PROFESSION_OIDS_SMCB) {
        ProfessionOidValidator.isValidProfessionOidFormat(oid) shouldBe true
      }

      ProfessionOidValidator.isValidProfessionOidSmcb("1.2.276.0.76.4.223") shouldBe true
    }
  }
}
