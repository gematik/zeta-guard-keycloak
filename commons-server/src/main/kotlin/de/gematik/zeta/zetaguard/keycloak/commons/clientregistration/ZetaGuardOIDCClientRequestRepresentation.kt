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
package de.gematik.zeta.zetaguard.keycloak.commons.clientregistration

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonValue
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PLATFORM
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.Platform
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import org.keycloak.jose.jwk.JWK
import org.keycloak.representations.oidc.OIDCClientRepresentation

const val PROPERTY_ATTESTATION_TYPE = "attestation_type"
const val PROPERTY_SIGNED_HASH_PUK_CLIENT_SIG = "signed_hash_puk_client_sig"
const val PROPERTY_NONCE = "nonce"

/**
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 *
 * Extends Keycloak's [OIDCClientRepresentation], which already covers `client_name`, `token_endpoint_auth_method`,
 * `grant_types`, `redirect_uris` and `jwks`, with the gematik-specific attestation fields.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = PROPERTY_ATTESTATION_TYPE,
    visible = true,
    defaultImpl = SoftwareRegistrationRequest::class
)
@JsonSubTypes(
    value =
        [
          JsonSubTypes.Type(value = TpmRegistrationRequest::class, name = "tpm"),
          JsonSubTypes.Type(value = AppleRegistrationRequest::class, name = "apple"),
          JsonSubTypes.Type(value = AndroidRegistrationRequest::class, name = "android"),
          JsonSubTypes.Type(value = ZetaAttestationTokenRegistrationRequest::class, name = "zeta_attestation_token"),
          JsonSubTypes.Type(value = SoftwareRegistrationRequest::class, name = "software"),
        ]
)
abstract class ZetaGuardOIDCClientRequestRepresentation(
    @field:JsonProperty(PROPERTY_ATTESTATION_TYPE) //
    @field:JsonIgnore // Written/read via JsonTypeInfo above, a real property here would duplicated it
    val attestationType: AttestationType,
) : OIDCClientRepresentation() {
  @field:JsonPropertyDescription(
      "Plattform der Client-Instanz. Optional aus Kompatibilitätsgründen: fehlt das Feld, leitet der AuthS die Plattform aus dem attestation_type ab."
  )
  @field:JsonProperty(PROPERTY_PLATFORM)
  var platform: Platform? = null

  @field:JsonPropertyDescription(
      "gematik-Produktbezeichner der Client-Software, vom Hersteller bei der gematik registriert. Optional aus Kompatibilitätsgründen."
  )
  @field:JsonProperty(PROPERTY_PRODUCT_ID)
  var productId: String? = null

  @field:JsonPropertyDescription("Version der Client-Software zum Registrierungszeitpunkt.")
  @field:JsonProperty(PROPERTY_PRODUCT_VERSION)
  var productVersion: String? = null

  @field:JsonPropertyDescription(
      "Frische, einmalig verwendbare Nonce vom nonce_endpoint (GET /nonce). Geht, sofern gesetzt, in den signierten Hash von signed_hash_puk_client_sig ein."
  )
  @field:JsonProperty(PROPERTY_NONCE)
  var nonce: String? = null

  @field:JsonPropertyDescription(
      """Selbstsignatur: (Base64url-kodiert.)
        |- Apple:    Signatur des SHA-256-Hashes von PuK.Client.Sig, erstellt mit PrK.Client.Sig (Proof-of-Possession des Client Instance Keys).
        |- Android:  Signatur des SHA-256-Hashes von puk_client_sig, erstellt mit prk_client_sig (Proof-of-Possession des Client Instance Keys).
        |- Software: Selbstsignatur über SHA-256(puk_client_sig || nonce), erstellt mit prk_client_sig. Base64url-kodiert. Optional aus Kompatibilitätsgründen: fehlt das Feld, registriert der AuthS wie bisher ohne Besitznachweis.
        |- TPM:      Signatur des SHA-256-Hashes von puk_client_sig, erstellt mit dem TPM Attestation Key (prk_ak_sig).
        |- ZETA:     Signatur des SHA-256-Hashes von puk_client_sig, erstellt mit prk_client_sig (Proof-of-Possession des Client Instance Keys).
        |"""
  )
  @field:JsonProperty(PROPERTY_SIGNED_HASH_PUK_CLIENT_SIG)
  var signedHashPukClientSig: String? = null
}

@Suppress("unused")
enum class AttestationType {
  TPM,
  APPLE, // As well iOS as macOS
  ANDROID,
  ZETA_ATTESTATION_TOKEN,
  SOFTWARE;

  @JsonValue //
  val value = name.lowercase()
}

val ZetaGuardOIDCClientRequestRepresentation.jwk: Either<Throwable, JWK>
  get() = either {
    ensure(
        jwks?.keys != null
            && jwks.keys.isNotEmpty()
            && jwks.keys[0] != null
    ) { IllegalStateException("Invalid JWK") }

    jwks.keys[0]
  }

fun ZetaGuardOIDCClientRequestRepresentation.nonce(): ByteArray? = nonce?.fromBase64()
