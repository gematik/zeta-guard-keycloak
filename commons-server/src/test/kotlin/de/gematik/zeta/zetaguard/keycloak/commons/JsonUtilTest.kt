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

import com.fasterxml.jackson.annotation.JacksonInject
import com.fasterxml.jackson.annotation.JsonCreator
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.asMap
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObjectWithCreator
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.maps.shouldContainAll
import io.kotest.matchers.shouldBe
import org.keycloak.TokenCategory
import org.keycloak.representations.AccessToken
import org.keycloak.representations.RefreshToken

class JsonUtilTest : FunSpec() {
  init {
    test("Copy refresh token") {
      val accessToken =
        AccessToken().apply {
          subject = "jens"
          sessionId = "sid"
        }
      val refreshToken = RefreshToken(accessToken).apply { audience("HiFidelity") }
      val newRefreshToken = refreshToken.toJSON().toObjectWithCreator<MyRefreshToken>(mapOf("token" to refreshToken))

      newRefreshToken::class shouldBe MyRefreshToken::class
      newRefreshToken.sessionId shouldBe "sid"
      newRefreshToken.subject shouldBe "jens"
      newRefreshToken.audience shouldContainExactly (arrayOf("HiFidelity"))
      newRefreshToken shouldBe refreshToken
      newRefreshToken.asMap().shouldContainAll(refreshToken.asMap())
    }
  }
}

class MyRefreshToken @JsonCreator constructor(@JacksonInject("token") token: RefreshToken) : RefreshToken(token) {
  override fun getCategory(): TokenCategory = TokenCategory.ID
}
