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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.fasterxml.jackson.annotation.JsonEnumDefaultValue
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.databind.DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService

@Suppress("unused")
enum class ZetaClientPlatform(@JsonValue val value: String) {
  ANDROID("android"), APPLE("apple"), WINDOWS("windows"), LINUX("linux"), @JsonEnumDefaultValue
  OTHER("other"),
}

// see [client-data.yaml](https://github.com/gematik/zeta/blob/main/src/schemas/client-data.yaml)
// see also pep: ClientData
data class ZetaClientDataHeader(
    @JsonProperty("client_id") val clientId: String,
    @JsonProperty("product_id") val productId: String,
    @JsonProperty("product_version") val productVersion: String,
    @JsonProperty("platform") val platform: ZetaClientPlatform,
)

/** Header the PEP adds for the client it authorized (`pep_forward_client_data on`): Base64-URL JSON per client-data.yaml. */
const val HEADER_ZETA_CLIENT_DATA = "zeta-client-data"

class PepClientDataService(private val dataService: ZetaGuardDataService) {

  /** Tolerates fields and platforms the schema may add later, instead of rejecting every PEP-forwarded request. */
  private val objectMapper: ObjectMapper =
      jacksonObjectMapper().disable(FAIL_ON_UNKNOWN_PROPERTIES).enable(READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE)

  /**
   * Resolves the calling client from the PEP-forwarded client data; only a registered, valid and confirmed *mobile* client
   * bound to an identity is accepted (A_29909). The registration endpoints (`bind-email`) pass [requireConfirmed] = false:
   * their caller is the client that is still confirming its e-mail binding.
   */
  internal fun clientFromPep(headerValue: String?, requireConfirmed: Boolean = true) = either {
    val header = headerValue ?: raise("zeta-client-data header missing")

    val decoded = Either.catch { header.fromBase64() }.mapLeft { "Unable to parse zeta-client-data header: »${it.message}«" }.bind()

    val zetaClientData =
        Either.catch { objectMapper.readValue<ZetaClientDataHeader>(decoded) }.mapLeft { "Unable to parse zeta-client-data header: »${it.message}«" }
            .bind()

    val zetaClient = Either.catch { dataService.findClientData(zetaClientData.clientId) }
        .mapLeft { "could not load zeta client »${zetaClientData.clientId}«: »${it.message}«" }.bind()
      ?: raise("zeta client »${zetaClientData.clientId}« not found")

    ensure(!requireConfirmed || zetaClient.registrationStatus == ClientRegistrationStatus.CONFIRMED) {
      "zeta client »${zetaClient.id}« email binding (F1) is not confirmed, registrationStatus=»${zetaClient.registrationStatus}«"
    }

    ensure(zetaClient.attestationState == ClientAttestationState.VALID) {
      "zeta client »${zetaClient.id}« is not valid, attestationState=»${zetaClient.attestationState}«"
    }

    ensure(zetaClient.clientAuthMethod == ClientAuthMethod.SEK_IDP) {
      "zeta client »${zetaClient.id}« is not a mobile client, clientAuthMethod=»${zetaClient.clientAuthMethod}«"
    }

    ensure(zetaClient.userData != null) { "zeta client »${zetaClient.id}« not bound to an identity" }

    zetaClient
  }

  internal fun userFromPep(headerValue: String?) = callerFromPep(headerValue).map { (_, user) -> user }

  /** The calling client together with its identity. */
  internal fun callerFromPep(headerValue: String?) = either {
    val client = clientFromPep(headerValue).bind()
    val user = client.userData ?: raise("no user data for zeta client »${client.id}«")
    client to user
  }
}
