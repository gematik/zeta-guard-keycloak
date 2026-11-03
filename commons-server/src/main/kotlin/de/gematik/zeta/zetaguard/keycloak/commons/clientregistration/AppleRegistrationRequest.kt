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
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement
import com.webauthn4j.data.attestation.AttestationObject
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.toAppleAttestationObject
import de.gematik.zeta.zetaguard.keycloak.commons.server.APPLE_APP_ATTESTATION_ROOT_CA
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.issuerCommonName

const val PROPERTY_APPLE_ATTESTATION_OBJECT = "apple_attestation_object"

/**
 * Apple Hardware Attestation (iOS, iPadOS & macOS).
 *
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 */
class AppleRegistrationRequest : ZetaGuardOIDCClientRequestRepresentation(AttestationType.APPLE) {
  @field:JsonPropertyDescription(
      "CBOR-kodiertes Attestation-Objekt der Apple App Attest API (fmt: \"apple-appattest\"). Enthält attStmt (x5c-Zertifikatskette inkl. puk_ak_sig + receipt) sowie authData (rpIdHash, counter, credentialId). Base64-kodiert."
  )
  @field:JsonProperty(PROPERTY_APPLE_ATTESTATION_OBJECT)
  var appleAttestationObject: String? = null
}

fun ZetaGuardOIDCClientRequestRepresentation.appleAttestationObject(): Either<Throwable, AttestationObject> = either {
  if (this@appleAttestationObject is AppleRegistrationRequest) {
    val obj = this@appleAttestationObject.appleAttestationObject?.fromBase64()?.toAppleAttestationObject()?.bind()
      ?: raise(IllegalStateException("No valid Apple attestation object found"))

    ensure(obj.format == AppleAppAttestAttestationStatement.FORMAT) { IllegalStateException("Invalid attestation format :»${obj.format}«") }

    obj
  } else {
    raise(IllegalStateException("Apple attestation object type mismatch"))
  }
}

val AttestationObject.appleAttestationStatement: Either<Throwable, AppleAppAttestAttestationStatement>
  get() = either {
    if (this@appleAttestationStatement.attestationStatement is AppleAppAttestAttestationStatement) {
      val statement = this@appleAttestationStatement.attestationStatement as AppleAppAttestAttestationStatement

      ensure(statement.x5c.size == 2) { IllegalStateException("Invalid x5c certificate chain") }
      ensure(statement.x5c[1].issuerCommonName() == APPLE_APP_ATTESTATION_ROOT_CA) { IllegalStateException("Invalid certificate issuer") }

      statement
    } else {
      raise(IllegalStateException("Apple attestation object type mismatch"))
    }
  }
