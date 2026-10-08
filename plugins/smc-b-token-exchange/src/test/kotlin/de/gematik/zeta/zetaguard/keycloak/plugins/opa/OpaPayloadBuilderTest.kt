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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaDeviceInfo
import io.kotest.assertions.json.shouldContainJsonKey
import io.kotest.assertions.json.shouldContainJsonKeyValue
import io.kotest.assertions.json.shouldNotContainJsonKey
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
                    userProfessionOid = null,
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        val node = JsonSerialization.mapper.readTree(json)
        val req = node["input"]["authorization_request"]
        req["scopes"].shouldBeNull()
      }

      test("audiences blank entries -> audience omitted/null") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = listOf(" ", "  "),
                    grantType = null,
                    ipAddress = null,
                    userProfessionOid = null,
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        val node = JsonSerialization.mapper.readTree(json)
        val req = node["input"]["authorization_request"]
        req["audience"].shouldBeNull()
      }

      test("audiences provided -> only audience is present") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = listOf(" audience-1 ", "audience-2"),
                    grantType = null,
                    ipAddress = null,
                    userProfessionOid = null,
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        val node = JsonSerialization.mapper.readTree(json)
        val req = node["input"]["authorization_request"]
        req["aud"].shouldBeNull()
        req["audience"].map { it.asText() } shouldBe listOf("audience-1", "audience-2")
      }

      test("professionOid provided -> user_info.professionOID present; blank omitted") {
        val withProfJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    userIdentifier = "007",
                    userProfessionOid = "1.2.3",
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        withProfJson.shouldContainJsonKeyValue("$.input.user_info.identifier", "007")
        withProfJson.shouldContainJsonKeyValue("$.input.user_info.professionOID", "1.2.3")

        val withoutProfJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    userIdentifier = "",
                    userProfessionOid = "",
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        withoutProfJson shouldContainJsonKey "$.input.user_info"
        withoutProfJson shouldNotContainJsonKey "$.input.user_info.identifier"
        withoutProfJson shouldNotContainJsonKey "$.input.user_info.professionOID"
      }

      test("commonName provided -> user_info.commonName present; blank omitted") {
        val withNameJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    userIdentifier = "007",
                    userCommonName = "007",
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        withNameJson.shouldContainJsonKeyValue("$.input.user_info.commonName", "007")

        val withoutNameJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = null,
                    userIdentifier = "",
                    userCommonName = "",
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        withoutNameJson shouldNotContainJsonKey "$.input.user_info.commonName"
      }

      test("ip blank -> ip_address omitted; ip present -> included") {
        val withIpJson =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("s1"),
                    audiences = null,
                    grantType = null,
                    ipAddress = "10.0.0.1",
                    userProfessionOid = null,
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
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
                    userProfessionOid = null,
                    clientProductId = null,
                    clientProductVersion = null,
                    clientId = null,
                    clientPlatform = null,
                    clientRegistrationTimestamp = null,
                    authenticationMethodsReferences = emptyList(),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = null,
                )
            )
        val withoutIp = JsonSerialization.mapper.readTree(withoutIpJson)
        withoutIp["input"]["authorization_request"]["ip_address"].shouldBeNull()
      }

      test("should have each mandatory field") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.PayloadParams(
                    scopes = listOf("scope #1", "scope #2"),
                    audiences = listOf("audience #1", "audience #2"),
                    grantType = "grantType",
                    ipAddress = "10.0.0.1",
                    clientProductId = "clientProductId",
                    clientProductVersion = "clientProductVersion",
                    clientId = "clientId",
                    clientPlatform = "clientPlatform",
                    clientRegistrationTimestamp = 1,
                    postureType = "postureType",
                    userIdentifier = "userIdentifier",
                    userProfessionOid = "userProfessionOid",
                    userCommonName = "userCommonName",
                    authenticationMethodsReferences = listOf("method #1", "method #2"),
                    authenticationContextClassReference = "abc",
                    previousIpAddress = "10.0.0.2",
                    deviceInfo = OpaDeviceInfo(os = "Linux", osVersion = "6.12", deviceModel = "model"),
                )
            )

        json.shouldContainJsonKeyValue("$.input.authorization_request.amr[0]", "method #1")
        json.shouldContainJsonKeyValue("$.input.authorization_request.acr", "abc")
        json shouldNotContainJsonKey "$.input.authorization_request.aud"
        json.shouldContainJsonKeyValue("$.input.authorization_request.audience[0]", "audience #1")
        json.shouldContainJsonKeyValue("$.input.authorization_request.grant_type", "grantType")
        json.shouldContainJsonKeyValue("$.input.authorization_request.ip_address", "10.0.0.1")
        json.shouldContainJsonKeyValue("$.input.authorization_request.previous_ip_address", "10.0.0.2")
        json.shouldContainJsonKeyValue("$.input.authorization_request.scopes[0]", "scope #1")

        json shouldContainJsonKey "$.input.client_registration_data.attestation_result"
        json.shouldContainJsonKeyValue("$.input.client_registration_data.client_id", "clientId")
        json shouldContainJsonKey "$.input.client_registration_data.device_info"
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os", "Linux")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os_version", "6.12")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.device_model", "model")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.platform", "clientPlatform")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.posture_type", "postureType")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.product_id", "clientProductId")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.product_version", "clientProductVersion")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.registration_timestamp", 1)

        json.shouldContainJsonKeyValue("$.input.user_info.identifier", "userIdentifier")
        json.shouldContainJsonKeyValue("$.input.user_info.professionOID", "userProfessionOid")
        json.shouldContainJsonKeyValue("$.input.user_info.commonName", "userCommonName")

        json.shouldContainJsonKeyValue("$.input.version", "1.0")
      }

      test("payloadParamsFromInput maps all OpaGateInput fields including postureType") {
        val json =
            OpaPayloadBuilder.build(
                OpaPayloadBuilder.payloadParamsFromInput(
                    OpaGateInput(
                        clientId = "clientId",
                        clientPlatform = "apple",
                        clientRegistrationTimestamp = 1,
                        grantType = "authorization_code",
                        scopes = listOf("openid"),
                        authenticationMethodsReferences = listOf("mfa"),
                        authenticationContextClassReference = "abc",
                        audiences = listOf("aud"),
                        ipAddress = "10.0.0.1",
                        previousIpAddress = "10.0.0.2",
                        postureType = "apple",
                        clientProductID = "product",
                        clientProductVersion = "1.0",
                        userIdentifier = "kvnr",
                        userProfessionOid = "1.2.3",
                        userCommonName = "kvnr",
                        deviceInfo = OpaDeviceInfo(os = "iOS", osVersion = "17.4.1", deviceModel = "iPhone15,2"),
                    )
                )
            )

        json.shouldContainJsonKeyValue("$.input.client_registration_data.posture_type", "apple")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.platform", "apple")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.product_id", "product")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os", "iOS")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os_version", "17.4.1")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.device_model", "iPhone15,2")
        json.shouldContainJsonKeyValue("$.input.user_info.identifier", "kvnr")
        json.shouldContainJsonKeyValue("$.input.user_info.commonName", "kvnr")
        json.shouldContainJsonKeyValue("$.input.authorization_request.grant_type", "authorization_code")
      }

      test("deviceInfo absent or blank -> device_info present but fields omitted") {
        val params =
            OpaPayloadBuilder.PayloadParams(
                scopes = listOf("s1"),
                audiences = null,
                grantType = null,
                ipAddress = null,
                userProfessionOid = null,
                clientProductId = null,
                clientProductVersion = null,
                clientId = null,
                clientPlatform = null,
                clientRegistrationTimestamp = null,
                authenticationMethodsReferences = emptyList(),
                authenticationContextClassReference = "abc",
                previousIpAddress = null,
            )

        val withoutJson = OpaPayloadBuilder.build(params)
        withoutJson shouldContainJsonKey "$.input.client_registration_data.device_info"
        withoutJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.os"
        withoutJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.os_version"
        withoutJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.device_model"

        val blankJson = OpaPayloadBuilder.build(params.copy(deviceInfo = OpaDeviceInfo(os = "Windows", osVersion = " ", deviceModel = "")))
        blankJson.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os", "Windows")
        blankJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.os_version"
        blankJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.device_model"
      }
    })
