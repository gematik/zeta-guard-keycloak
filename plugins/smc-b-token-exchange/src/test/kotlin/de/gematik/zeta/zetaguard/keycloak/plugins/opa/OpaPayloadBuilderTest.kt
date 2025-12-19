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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import org.keycloak.util.JsonSerialization

class OpaPayloadBuilderTest :
    FunSpec({
      test("scopes empty -> authorization_request.scopes omitted/null") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = emptyList(),
                    audiences = null,
                    grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                    ipAddress = "127.0.0.1",
                    professionOid = null,
                    productId = null,
                    productVersion = null,
                )
            )
        val node = JsonSerialization.mapper.readTree(json)
        val req = node["input"]["authorization_request"]
        req["scopes"].shouldBeNull()
      }

      test("audiences blank entries -> aud omitted/null") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = listOf(" ", "  "),
                    grantType = null,
                    ipAddress = null,
                    professionOid = null,
                    productId = null,
                    productVersion = null,
                )
            )
        val node = JsonSerialization.mapper.readTree(json)
        val req = node["input"]["authorization_request"]
        req["aud"].shouldBeNull()
      }

      test("professionOid provided -> user_info.professionOID present; blank omitted") {
        val withProfJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    professionOid = "1.2.3",
                    productId = null,
                    productVersion = null,
                )
            )
        val withProf = JsonSerialization.mapper.readTree(withProfJson)
        withProf["input"]["user_info"]["professionOID"].asText() shouldBe "1.2.3"

        val withoutProfJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    professionOid = "",
                    productId = null,
                    productVersion = null,
                )
            )
        val withoutProf = JsonSerialization.mapper.readTree(withoutProfJson)
        withoutProf["input"]["user_info"].shouldBeNull()
      }

      test("ip blank -> ip_address omitted; ip present -> included") {
        val withIpJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = "10.0.0.1",
                    professionOid = null,
                    productId = null,
                    productVersion = null,
                )
            )
        val withIp = JsonSerialization.mapper.readTree(withIpJson)
        withIp["input"]["authorization_request"]["ip_address"].asText() shouldBe "10.0.0.1"

        val withoutIpJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = "",
                    professionOid = null,
                    productId = null,
                    productVersion = null,
                )
            )
        val withoutIp = JsonSerialization.mapper.readTree(withoutIpJson)
        withoutIp["input"]["authorization_request"]["ip_address"].shouldBeNull()
      }
    })
