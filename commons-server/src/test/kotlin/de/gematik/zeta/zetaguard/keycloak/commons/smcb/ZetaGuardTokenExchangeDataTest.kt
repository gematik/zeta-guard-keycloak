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
package de.gematik.zeta.zetaguard.keycloak.commons.smcb

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaDeviceInfo
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration

class ZetaGuardTokenExchangeDataTest : FunSpec() {
  init {
    val data =
        ZetaGuardTokenExchangeData(
            authenticationMethodsReferences = listOf("mfa"),
            authenticationContextClassReference = "abc",
            clientId = "client-internal-id",
            clientPlatform = "linux",
            clientRegistrationTimestamp = 1_700_000_000,
            postureType = "software",
            previousIpAddress = "10.0.0.2",
            telematikID = "1-20000300139",
            professionOID = "1.2.276.0.76.4.50",
            subjectOrganisation = "org",
            subjectCommonName = "cn",
            clientIP = "10.0.0.1",
            accessTokenTTL = Duration.ofSeconds(111),
            refreshTokenTTL = Duration.ofSeconds(600),
            audiences = listOf("https://fachdienst.example"),
            scopes = listOf("openid"),
            deviceInfo = OpaDeviceInfo(os = "Linux", osVersion = "6.12", deviceModel = null),
        )

    test("round-trips a session note including device info") { data.toJSON().toObject<ZetaGuardTokenExchangeData>() shouldBe data }

    test("reads notes written before deviceInfo existed") {
      val json = data.copy(deviceInfo = null).toJSON()

      json.toObject<ZetaGuardTokenExchangeData>().deviceInfo shouldBe null
    }

    test("ignores unknown fields from newer note versions") {
      val json = data.toJSON().removeSuffix("}") + ""","futureField":"x"}"""

      json.toObject<ZetaGuardTokenExchangeData>() shouldBe data
    }
  }
}
