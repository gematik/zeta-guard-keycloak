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

import org.keycloak.util.JsonSerialization

object OpaPayloadBuilder {
  data class PayloadParams(
      val scopes: List<String>,
      val audiences: List<String>?,
      val grantType: String?,
      val ipAddress: String?,
      val professionOid: String? = null,
      val productId: String? = null,
      val productVersion: String? = null,
  )

  fun build(params: PayloadParams): String {
    val userInfo = params.professionOid?.takeIf { it.isNotBlank() }?.let { OpaInput.UserInfo(professionOID = it) }
    val posture =
        if (!params.productId.isNullOrBlank() && !params.productVersion.isNullOrBlank()) {
          OpaInput.Posture(productId = params.productId, productVersion = params.productVersion)
        } else null
    val clientAssertion = posture?.let { OpaInput.ClientAssertion(posture = it) }
    val effectiveAud = params.audiences?.map { it.trim() }?.filter { it.isNotBlank() }?.ifEmpty { null }

    val input =
        OpaInput.Input(
            authorizationRequest =
                OpaInput.AuthorizationRequest(
                    scopes = params.scopes.ifEmpty { null },
                    aud = effectiveAud,
                    grantType = params.grantType?.takeIf { it.isNotBlank() },
                    ipAddress = params.ipAddress?.takeIf { it.isNotBlank() },
                ),
            userInfo = userInfo,
            clientAssertion = clientAssertion,
        )

    return JsonSerialization.writeValueAsString(OpaInput(input = input))
  }
}
