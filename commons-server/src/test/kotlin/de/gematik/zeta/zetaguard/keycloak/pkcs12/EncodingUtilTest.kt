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
package de.gematik.zeta.zetaguard.keycloak.pkcs12

import de.gematik.zeta.zetaguard.keycloak.commons.server.toDuration
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import de.gematik.zeta.zetaguard.keycloak.commons.server.toLocalDateTime
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration
import java.time.LocalDateTime

class EncodingUtilTest : FunSpec() {
  init {
    test("ISO-8601 conversion") {
      val dateTime = LocalDateTime.of(2011, 7, 16, 16, 58, 25)
      val iso8601 = "2011-07-16T16:58:25"

      dateTime.toISO8601() shouldBe iso8601
      iso8601.toLocalDateTime() shouldBe dateTime
    }

    test("Duration conversion") {
      val duration = Duration.ofSeconds(5)
      val iso8601 = "PT5S"

      duration.toString() shouldBe iso8601
      iso8601.toDuration() shouldBe duration
    }
  }
}
