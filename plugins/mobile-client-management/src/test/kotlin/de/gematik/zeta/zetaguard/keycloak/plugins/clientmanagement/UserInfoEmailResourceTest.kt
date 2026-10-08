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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.USERINFO_STATIC_EMAIL
import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.UserInfoEmailResource
import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.UserInfoEmailResponse
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

/**
 * The stub knows exactly two answers: the static email for any identifier, and an undifferentiated 404
 * when the identifier is missing (the spec defines no 400 for this endpoint).
 */
class UserInfoEmailResourceTest :
    StringSpec({
      "any identifier is answered with 200 and the static email" {
        val response = UserInfoEmailResource().getEmail("47114541")

        response.status shouldBe 200
        response.entity shouldBe UserInfoEmailResponse(USERINFO_STATIC_EMAIL)
      }

      "a missing id is answered with 404 without a body" {
        val response = UserInfoEmailResource().getEmail(null)

        response.status shouldBe 404
        response.entity shouldBe null
      }

      "a blank id is answered with 404 without a body" {
        val response = UserInfoEmailResource().getEmail("  ")

        response.status shouldBe 404
        response.entity shouldBe null
      }
    })
