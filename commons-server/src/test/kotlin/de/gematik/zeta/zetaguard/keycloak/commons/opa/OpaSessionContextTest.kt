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
package de.gematik.zeta.zetaguard.keycloak.commons.opa

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration

class OpaSessionContextTest : FunSpec() {
  init {
    test("round-trips a full OPA snapshot") {
      val original =
          OpaSessionContext(
              accessTokenTTL = Duration.ofSeconds(111),
              refreshTokenTTL = Duration.ofSeconds(600),
              scopes = listOf("openid", "email"),
              audiences = listOf("https://fachdienst.example"),
              clientId = "client-internal-id",
              clientPlatform = "apple",
              clientRegistrationTimestamp = 1_700_000_000,
              postureType = "apple",
              clientProductID = "demo_client",
              clientProductVersion = "0.1.0",
              authenticationMethodsReferences = listOf("mfa"),
              authenticationContextClassReference = "abc",
              userIdentifier = "X110123456",
              userProfessionOid = "1.2.276.0.76.4.49",
              userCommonName = "X110123456",
              deviceInfo = OpaDeviceInfo(os = "iOS", osVersion = "17.4.1", deviceModel = "iPhone15,2"),
          )

      original.toJSON().toObject<OpaSessionContext>() shouldBe original
    }

    test("reads TTL-only notes written before the snapshot fields existed") {
      val parsed = """{"accessTokenTTL":"PT111S","refreshTokenTTL":"PT10M", "authenticationContextClassReference":"abc"}""".toObject<OpaSessionContext>()

      parsed.accessTokenTTL shouldBe Duration.ofSeconds(111)
      parsed.refreshTokenTTL shouldBe Duration.ofSeconds(600)
      parsed.authenticationContextClassReference shouldBe "abc"
      parsed.scopes shouldBe null
      parsed.audiences shouldBe null
      parsed.deviceInfo shouldBe null
    }

    test("opaTtlDurations skips partial values") {
      opaTtlDurations(111, null) shouldBe null
      opaTtlDurations(null, 600) shouldBe null
      opaTtlDurations(111, 600) shouldBe (Duration.ofSeconds(111) to Duration.ofSeconds(600))
    }
  }
}
