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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb.opa

import com.fasterxml.jackson.annotation.JsonProperty

data class OpaInput(val input: Input) {
  data class Input(
      @get:JsonProperty("authorization_request") val authorizationRequest: AuthorizationRequest? = null,
      @get:JsonProperty("user_info") val userInfo: UserInfo? = null,
      @get:JsonProperty("client_assertion") val clientAssertion: ClientAssertion? = null,
  )

  data class AuthorizationRequest(
      val scopes: List<String>? = null,
      val aud: List<String>? = null,
      @get:JsonProperty("grant_type") val grantType: String? = null,
      @get:JsonProperty("ip_address") val ipAddress: String? = null,
  )

  data class UserInfo(@get:JsonProperty("professionOID") val professionOID: String? = null)

  data class ClientAssertion(val posture: Posture? = null)

  data class Posture(
      @get:JsonProperty("product_id") val productId: String? = null,
      @get:JsonProperty("product_version") val productVersion: String? = null,
  )
}
