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

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class OidcFlowSettingsTest : FunSpec() {
  init {
    test("parse treats missing and blank as disabled") {
      OidcFlowSettings.parse(null) shouldBe false
      OidcFlowSettings.parse("") shouldBe false
      OidcFlowSettings.parse("  ") shouldBe false
      OidcFlowSettings.parse("false") shouldBe false
      OidcFlowSettings.parse("no") shouldBe false
    }

    test("parse accepts true, 1 and yes case-insensitively") {
      OidcFlowSettings.parse("true") shouldBe true
      OidcFlowSettings.parse("TRUE") shouldBe true
      OidcFlowSettings.parse("  Yes  ") shouldBe true
      OidcFlowSettings.parse("1") shouldBe true
    }
  }
}
