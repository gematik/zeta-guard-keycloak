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
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import java.security.cert.X509Certificate

private const val PROPERTY_ANDROID_KEY_ATTESTATION_CERTIFICATE_CHAIN = "android_key_attestation_certificate_chain"
private const val PROPERTY_PLAY_INTEGRITY_TOKEN = "play_integrity_token"

/**
 * Android Hardware Attestation (Android Keystore Key Attestation, TEE / StrongBox).
 *
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 */
class AndroidRegistrationRequest : ZetaGuardOIDCClientRequestRepresentation(AttestationType.ANDROID) {
  @field:JsonPropertyDescription(
      "X.509-Zertifikatskette der Android Key Attestation, beginnend mit dem Blatt-Zertifikat des attestierten Schlüssels (C.AK.Sig) bis zur Google Hardware Attestation Root CA. Jedes Zertifikat ist Base64-kodiert (DER-Format)."
  )
  @field:JsonProperty(PROPERTY_ANDROID_KEY_ATTESTATION_CERTIFICATE_CHAIN)
  var androidKeyAttestationCertificateChain: List<String>? = null

  @field:JsonPropertyDescription(
      "Optionales Token der Google Play Integrity API (Base64-kodiert). Ermöglicht dem AuthS die zusätzliche App-Integritätsprüfung (meets_basic_integrity, meets_device_integrity)."
  )
  @field:JsonProperty(PROPERTY_PLAY_INTEGRITY_TOKEN)
  var playIntegrityToken: String? = null
}

/**
 * Parsed key attestation certificate chain, leaf (attested key) first. A chain consists at least of the leaf and one issuer certificate.
 */
fun ZetaGuardOIDCClientRequestRepresentation.androidCertificateChain(): Either<Throwable, List<X509Certificate>> = either {
  if (this@androidCertificateChain is AndroidRegistrationRequest) {
    val chain = this@androidCertificateChain.androidKeyAttestationCertificateChain
      ?: raise(IllegalStateException("No Android key attestation certificate chain found"))

    ensure(chain.size >= 2) { IllegalStateException("Invalid Android key attestation certificate chain") }

    Either.catch { chain.map { it.toCertificate() } }.mapLeft { IllegalStateException("Invalid Android key attestation certificate: ${it.message}") }.bind()
  } else {
    raise(IllegalStateException("Android attestation object type mismatch"))
  }
}
