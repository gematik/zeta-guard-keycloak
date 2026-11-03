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
package de.gematik.zeta.zetaguard.keycloak.client_attestation

import arrow.core.Either
import arrow.core.raise.either
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.jsontype.NamedType
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement
import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_APPLE_APP_ATTEST_AAGUID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupBouncyCastleProvider
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import org.apache.commons.lang3.SystemUtils.getEnvironmentVariable
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.keycloak.util.JsonSerialization

const val APPLE_APP_ATTEST_AAGUID_PRODUCTION = "appattest"
const val APPLE_APP_ATTEST_AAGUID_DEVELOPMENT = "appattestdevelop"

private val APPLE_APP_ATTEST_AAGUID_STRING = getEnvironmentVariable(ENV_APPLE_APP_ATTEST_AAGUID, APPLE_APP_ATTEST_AAGUID_PRODUCTION)
val APPLE_APP_ATTEST_AAGUID = AAGUID(APPLE_APP_ATTEST_AAGUID_STRING.toByteArray().copyOf(16))

@Suppress("unused")
object AttestationUtil {
  val cborMapper = ObjectMapper(CBORFactory())
  private val objectConverter = ObjectConverter(JsonSerialization.mapper, cborMapper)
  private val attestationObjectConverter = AttestationObjectConverter(objectConverter)
  private val authenticatorDataConverter = AuthenticatorDataConverter(objectConverter)

  init {
    cborMapper.registerSubtypes(
        NamedType(AppleAppAttestAttestationStatement::class.java, AppleAppAttestAttestationStatement.FORMAT)
    )

    setupBouncyCastleProvider()
  }

  fun ByteArray.toAppleAttestationObject(): Either<Throwable, AttestationObject> = either {
    Either.catch<AttestationObject?> { attestationObjectConverter.convert(this@toAppleAttestationObject) }.bind()
      ?: raise(IllegalStateException("Could not parse AppleAttestationObject"))
  }

  fun ByteArray.extractRawAuthenticationData(): Either<Throwable, ByteArray> = either {
    Either.catch { attestationObjectConverter.extractAuthenticatorData(this@extractRawAuthenticationData) }.bind()
      ?: raise(IllegalStateException("Could not extract AuthenticationData"))
  }

  fun AttestationObject.toCBOR(): Either<Throwable, ByteArray> = Either.catch { attestationObjectConverter.convertToBytes(this@toCBOR) }

  fun AuthenticatorData<*>.toCBOR(): Either<Throwable, ByteArray> = Either.catch { authenticatorDataConverter.convert(this@toCBOR) }
}

/**
 * Calculate attestation challenge = SHA-256( SHA-256(pubKey) || nonce ). (BASE64 encoded)
 *
 * According to https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1
 *
 * @param nonce Server-provided nonce bytes
 * @param jwkThumbPrint Raw client JWK thumb print according to RFC 7638
 * @return BASE64-encoded attestation challenge
 */
fun calculateAttestationChallenge(jwkThumbPrint: ByteArray, nonce: ByteArray): String = toHash(jwkThumbPrint, nonce).toBase64()

fun ByteArray.toAppleASN1Sequence(): ASN1Sequence {
  val octet = DEROctetString(this)
  val taggedObject = DERTaggedObject(true, 1, octet)

  return DERSequence(arrayOf(taggedObject))
}
