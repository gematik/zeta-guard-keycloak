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

class OpaPayloadBuilderTest :
    FunSpec({

       val minimalParams = OpaPayloadBuilder.PayloadParams(
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

      test("scopes empty -> authorization_request.scopes omitted/null") {
        val json = OpaPayloadBuilder.build(
            minimalParams.copy(scopes = emptyList())
        )
        json shouldNotContainJsonKey "$.input.authorization_request.scopes"
      }

      test("audiences blank entries -> audience omitted/null") {
        val json = OpaPayloadBuilder.build(
            minimalParams.copy(audiences = listOf(" ", "  "))
        )
        json shouldNotContainJsonKey "$.input.authorization_request.audience"
      }

      test("audiences provided -> only audience is present") {
        val json = OpaPayloadBuilder.build(
            minimalParams.copy(audiences = listOf(" audience-1 ", "audience-2"))
        )
        json shouldNotContainJsonKey "$.input.authorization_request.aud"
        json.shouldContainJsonKeyValue("$.input.authorization_request.audience", listOf("audience-1", "audience-2"))
      }

      test("professionOid provided -> user_info.professionOID present; blank omitted") {
        val withProfJson = OpaPayloadBuilder.build(
            minimalParams.copy(
                userIdentifier = "007",
                userProfessionOid = "1.2.3",
            )
        )
        withProfJson.shouldContainJsonKeyValue("$.input.user_info.identifier", "007")
        withProfJson.shouldContainJsonKeyValue("$.input.user_info.professionOID", "1.2.3")

        val withoutProfJson = OpaPayloadBuilder.build(
            minimalParams.copy(
                userIdentifier = null,
                userProfessionOid = null,
            )
        )
        withoutProfJson shouldContainJsonKey "$.input.user_info"
        withoutProfJson shouldNotContainJsonKey "$.input.user_info.identifier"
        withoutProfJson shouldNotContainJsonKey "$.input.user_info.professionOID"
      }

      test("commonName provided -> user_info.commonName present; blank omitted") {
        val withNameJson = OpaPayloadBuilder.build(
            minimalParams.copy(
                userIdentifier = "007",
                userCommonName = "007",
            )
        )
        withNameJson.shouldContainJsonKeyValue("$.input.user_info.commonName", "007")

        val withoutNameJson = OpaPayloadBuilder.build(
            minimalParams.copy(
                userIdentifier = null,
                userCommonName = null,
            )
        )
        withoutNameJson shouldNotContainJsonKey "$.input.user_info.commonName"
      }

      test("organizationName provided -> user_info.organizationName present; blank omitted") {
        val withOrgJson = OpaPayloadBuilder.build(minimalParams.copy(userOrganizationName = "Praxis Dr. Mustermann"))
        withOrgJson.shouldContainJsonKeyValue("$.input.user_info.organizationName", "Praxis Dr. Mustermann")

        val blankOrgJson = OpaPayloadBuilder.build(minimalParams.copy(userOrganizationName = " "))
        blankOrgJson shouldNotContainJsonKey "$.input.user_info.organizationName"

        val withoutOrgJson = OpaPayloadBuilder.build(minimalParams.copy(userOrganizationName = null))
        withoutOrgJson shouldNotContainJsonKey "$.input.user_info.organizationName"
      }

      test("birthdate provided -> user_info.birthdate present; blank omitted") {
        val withBirthdateJson = OpaPayloadBuilder.build(minimalParams.copy(userBirthdate = "1970-01-31"))
        withBirthdateJson.shouldContainJsonKeyValue("$.input.user_info.birthdate", "1970-01-31")

        val blankBirthdateJson = OpaPayloadBuilder.build(minimalParams.copy(userBirthdate = ""))
        blankBirthdateJson shouldNotContainJsonKey "$.input.user_info.birthdate"

        val withoutBirthdateJson = OpaPayloadBuilder.build(minimalParams.copy(userBirthdate = null))
        withoutBirthdateJson shouldNotContainJsonKey "$.input.user_info.birthdate"
      }

      test("ip blank -> ip_address omitted; ip present -> included") {
        val withIpJson = OpaPayloadBuilder.build(
            minimalParams.copy(ipAddress = "10.0.0.1")
        )
        withIpJson.shouldContainJsonKeyValue("$.input.authorization_request.ip_address", "10.0.0.1")

        val withoutIpJson = OpaPayloadBuilder.build(
            minimalParams.copy(ipAddress = "")
        )
        withoutIpJson.shouldNotContainJsonKey("$.input.authorization_request.ip_address")
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
                    userOrganizationName = "userOrganizationName",
                    userBirthdate = "1970-01-31",
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
        json.shouldContainJsonKeyValue("$.input.user_info.organizationName", "userOrganizationName")
        json.shouldContainJsonKeyValue("$.input.user_info.birthdate", "1970-01-31")

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
                        userOrganizationName = "AOK",
                        userBirthdate = "1970-01-31",
                        deviceInfo = OpaDeviceInfo(os = "iOS", osVersion = "17.4.1", deviceModel = "iPhone15,2"),
                        attestationTimestamp = 1753272000,
                    )
                )
            )

        json.shouldContainJsonKeyValue("$.input.client_registration_data.posture_type", "apple")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.platform", "apple")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.product_id", "product")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os", "iOS")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os_version", "17.4.1")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.device_model", "iPhone15,2")
        json.shouldContainJsonKeyValue("$.input.client_registration_data.attestation_timestamp", 1753272000)
        json.shouldContainJsonKeyValue("$.input.user_info.identifier", "kvnr")
        json.shouldContainJsonKeyValue("$.input.user_info.commonName", "kvnr")
        json.shouldContainJsonKeyValue("$.input.user_info.organizationName", "AOK")
        json.shouldContainJsonKeyValue("$.input.user_info.birthdate", "1970-01-31")
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
        withoutJson shouldNotContainJsonKey "$.input.client_registration_data.attestation_timestamp"

        val blankJson = OpaPayloadBuilder.build(params.copy(deviceInfo = OpaDeviceInfo(os = "Windows", osVersion = " ", deviceModel = "")))
        blankJson.shouldContainJsonKeyValue("$.input.client_registration_data.device_info.os", "Windows")
        blankJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.os_version"
        blankJson shouldNotContainJsonKey "$.input.client_registration_data.device_info.device_model"
      }
    })
