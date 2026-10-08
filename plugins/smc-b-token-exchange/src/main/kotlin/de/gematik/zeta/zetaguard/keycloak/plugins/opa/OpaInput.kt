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

import com.fasterxml.jackson.annotation.JsonProperty
import org.keycloak.OAuth2Constants.GRANT_TYPE

/**
 * Date model for a specific (policy) request send to OPA to trigger and retrieve a policy decision.
 *
 * @see [https://github.com/gematik/zeta/blob/v1.3.0/src/schemas/policy-engine-input.yaml]
 */
data class OpaInput(val input: Input) {
  data class Input(
      @get:JsonProperty("authorization_request") val authorizationRequest: OpaAuthorizationRequest? = null,
      @get:JsonProperty("client_registration_data") val clientRegistrationData: ZetaClientRegistration? = null,
      @get:JsonProperty("user_info") val userInfo: OpaUserInfo? = null,
      val version: String? = null,
  )

  data class OpaAuthorizationRequest(
      @get:JsonProperty("amr") val authenticationMethodsReferences: List<String>? = null,
      @get:JsonProperty("acr") val authenticationContextClassReference: String,
      val audience: List<String>? = null,
      @get:JsonProperty(GRANT_TYPE) val grantType: String? = null,
      @get:JsonProperty("ip_address") val ipAddress: String? = null,
      @get:JsonProperty("previous_ip_address") val previousIpAddress: String? = null,
      val scopes: List<String>? = null,
  )

  /** @see [https://github.com/gematik/zeta/blob/v1.3.0/src/schemas/policy-engine-client-data.yaml] */
  data class ZetaClientRegistration(
      @get:JsonProperty("attestation_result") val attestationResult: AttestationResult? = null,
      @get:JsonProperty("client_id") val clientId: String? = null,
      @get:JsonProperty("device_info") val deviceInfo: DeviceInfo? = null,
      val platform: String? = null,
      @get:JsonProperty("posture_type") val postureType: String? = null,
      @get:JsonProperty("product_id") val productId: String? = null,
      @get:JsonProperty("product_version") val productVersion: String? = null,
      @get:JsonProperty("registration_timestamp") val registrationTimestamp: Long? = null,
  )

  data class AttestationResult(val tpm: String? = null)

  data class DeviceInfo(
      val os: String? = null,
      @get:JsonProperty("os_version") val osVersion: String? = null,
      @get:JsonProperty("device_model") val deviceModel: String? = null,
  )

  /** @see [https://github.com/gematik/zeta/blob/v1.3.0/src/schemas/user-info.yaml] */
  data class OpaUserInfo(
      val identifier: String? = null,
      @get:JsonProperty("professionOID") val professionOid: String? = null,
      val commonName: String? = null,
  )
}
