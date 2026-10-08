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

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaDeviceInfo

private const val SCHEMA_VERSION = "1.0"

object OpaPayloadBuilder {
  data class PayloadParams(
      val clientId: String?,
      val clientPlatform: String?,
      val clientRegistrationTimestamp: Long?,
      val scopes: List<String>,
      val authenticationMethodsReferences: List<String>,
      val authenticationContextClassReference: String,
      val audiences: List<String>?,
      val grantType: String?,
      val ipAddress: String?,
      val previousIpAddress: String?,
      val clientProductId: String? = null,
      val clientProductVersion: String? = null,
      val postureType: String? = null,
      val userIdentifier: String? = null,
      val userProfessionOid: String? = null,
      val userCommonName: String? = null,
      val deviceInfo: OpaDeviceInfo? = null,
  )

  private fun PayloadParams.toUserInfo() =
      OpaInput.OpaUserInfo(
          identifier = userIdentifier?.takeIf(String::isNotBlank),
          professionOid = userProfessionOid?.takeIf(String::isNotBlank),
          commonName = userCommonName?.takeIf(String::isNotBlank),
      )

  private fun PayloadParams.toAuthorizationRequest(): OpaInput.OpaAuthorizationRequest {
    val effectiveAud = audiences?.map { it.trim() }?.filter { it.isNotBlank() }?.ifEmpty { null }
    return OpaInput.OpaAuthorizationRequest(
        scopes = scopes.ifEmpty { null },
        authenticationMethodsReferences = authenticationMethodsReferences.ifEmpty { null },
        authenticationContextClassReference = authenticationContextClassReference,
        audience = effectiveAud,
        grantType = grantType?.takeIf { it.isNotBlank() },
        ipAddress = ipAddress?.takeIf { it.isNotBlank() },
        previousIpAddress = previousIpAddress?.takeIf { it.isNotBlank() },
    )
  }

  private fun PayloadParams.toClientRegistrationData() =
      OpaInput.ZetaClientRegistration(
          attestationResult = toAttestationResult(),
          clientId = clientId,
          deviceInfo = toDeviceInfo(),
          platform = clientPlatform,
          postureType = postureType,
          productId = clientProductId,
          productVersion = clientProductVersion,
          registrationTimestamp = clientRegistrationTimestamp,
      )

  private fun toAttestationResult(): OpaInput.AttestationResult = OpaInput.AttestationResult()

  private fun PayloadParams.toDeviceInfo() =
      OpaInput.DeviceInfo(
          os = deviceInfo?.os?.takeIf(String::isNotBlank),
          osVersion = deviceInfo?.osVersion?.takeIf(String::isNotBlank),
          deviceModel = deviceInfo?.deviceModel?.takeIf(String::isNotBlank),
      )

  fun build(params: PayloadParams): String {
    val input =
        OpaInput.Input(
            authorizationRequest = params.toAuthorizationRequest(),
            clientRegistrationData = params.toClientRegistrationData(),
            userInfo = params.toUserInfo(),
            version = SCHEMA_VERSION,
        )

    return OpaInput(input = input).toJSON()
  }

  fun payloadParamsFromInput(input: OpaGateInput) =
      PayloadParams(
          scopes = input.scopes,
          audiences = input.audiences,
          grantType = input.grantType,
          ipAddress = input.ipAddress,
          previousIpAddress = input.previousIpAddress,
          authenticationMethodsReferences = input.authenticationMethodsReferences,
          authenticationContextClassReference = input.authenticationContextClassReference,
          clientId = input.clientId,
          clientPlatform = input.clientPlatform,
          clientProductId = input.clientProductID,
          clientProductVersion = input.clientProductVersion,
          clientRegistrationTimestamp = input.clientRegistrationTimestamp,
          postureType = input.postureType,
          userIdentifier = input.userIdentifier,
          userProfessionOid = input.userProfessionOid,
          userCommonName = input.userCommonName,
          deviceInfo = input.deviceInfo,
      )
}
