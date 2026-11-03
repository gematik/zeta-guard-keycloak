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
import de.gematik.zeta.zetaguard.keycloak.commons.server.androidKeyAttestationExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject

private const val TAG_ORIGIN = 702
private const val TAG_ROOT_OF_TRUST = 704

const val ANDROID_KEY_ORIGIN_GENERATED = 0L

/**
 * Subset of the Android Key Attestation `KeyDescription` (extension OID 1.3.6.1.4.1.11129.2.1.17 of the attested key's leaf certificate) needed
 * to verify an attestation.
 *
 * https://source.android.com/docs/security/features/keystore/attestation#schema
 */
class AndroidKeyDescription(
    val attestationVersion: Long,
    val attestationSecurityLevel: AndroidSecurityLevel,
    val keyMintVersion: Long,
    val keyMintSecurityLevel: AndroidSecurityLevel,
    val attestationChallenge: ByteArray,
    val hardwareEnforced: AndroidAuthorizationList,
)

/** Only the fields of `AuthorizationList` that are checked during client registration. */
data class AndroidAuthorizationList(val origin: Long? = null, val rootOfTrust: AndroidRootOfTrust? = null)

class AndroidRootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: AndroidVerifiedBootState,
)

/** Order matches the ASN.1 ENUMERATED values. */
enum class AndroidSecurityLevel {
  SOFTWARE,
  TRUSTED_ENVIRONMENT,
  STRONG_BOX,
}

/** Order matches the ASN.1 ENUMERATED values. */
enum class AndroidVerifiedBootState {
  VERIFIED,
  SELF_SIGNED,
  UNVERIFIED,
  FAILED,
}

fun X509Certificate.extractAndroidKeyDescription(): Either<Throwable, AndroidKeyDescription> = either {
  val sequence = extractExtension<ASN1Sequence>(androidKeyAttestationExtension)
    ?: raise(IllegalStateException("No Android key attestation extension found"))

  Either.catch { sequence.toKeyDescription() }.mapLeft { IllegalStateException("Invalid Android key description: ${it.message}") }.bind()
}

/** ASN.1 encoding of the key description, e.g., to create test certificates.
 *  Fields not modeled here are encoded empty.
 */
fun AndroidKeyDescription.toASN1Sequence(): ASN1Sequence = DERSequence(
    arrayOf(
        ASN1Integer(attestationVersion),
        ASN1Enumerated(attestationSecurityLevel.ordinal),
        ASN1Integer(keyMintVersion),
        ASN1Enumerated(keyMintSecurityLevel.ordinal),
        DEROctetString(attestationChallenge),
        DEROctetString(ByteArray(0)), // uniqueId
        DERSequence(), // softwareEnforced
        hardwareEnforced.toASN1(),
    )
)

private fun ASN1Sequence.toKeyDescription() = AndroidKeyDescription(
    attestationVersion = ASN1Integer.getInstance(getObjectAt(0)).longValueExact(),
    attestationSecurityLevel = getObjectAt(1).toSecurityLevel(),
    keyMintVersion = ASN1Integer.getInstance(getObjectAt(2)).longValueExact(),
    keyMintSecurityLevel = getObjectAt(3).toSecurityLevel(),
    attestationChallenge = ASN1OctetString.getInstance(getObjectAt(4)).octets,
    hardwareEnforced = ASN1Sequence.getInstance(getObjectAt(7)).toAuthorizationList(),
)

private fun ASN1Encodable.toSecurityLevel() = AndroidSecurityLevel.entries[ASN1Enumerated.getInstance(this).intValueExact()]

private fun ASN1Sequence.toAuthorizationList(): AndroidAuthorizationList {
  val fields = map { ASN1TaggedObject.getInstance(it) }.associateBy { it.tagNo }

  return AndroidAuthorizationList(
      origin = fields[TAG_ORIGIN]?.let { ASN1Integer.getInstance(it.explicitBaseObject).longValueExact() },
      rootOfTrust = fields[TAG_ROOT_OF_TRUST]?.let { ASN1Sequence.getInstance(it.explicitBaseObject).toRootOfTrust() },
  )
}

private fun ASN1Sequence.toRootOfTrust() = AndroidRootOfTrust(
    verifiedBootKey = ASN1OctetString.getInstance(getObjectAt(0)).octets,
    deviceLocked = ASN1Boolean.getInstance(getObjectAt(1)).isTrue,
    verifiedBootState = AndroidVerifiedBootState.entries[ASN1Enumerated.getInstance(getObjectAt(2)).intValueExact()],
)

private fun AndroidAuthorizationList.toASN1() = DERSequence(
    listOfNotNull(
        origin?.let { DERTaggedObject(true, TAG_ORIGIN, ASN1Integer(it)) },
        rootOfTrust?.let { DERTaggedObject(true, TAG_ROOT_OF_TRUST, it.toASN1()) },
    ).toTypedArray()
)

private fun AndroidRootOfTrust.toASN1() = DERSequence(
    arrayOf(
        DEROctetString(verifiedBootKey),
        ASN1Boolean.getInstance(deviceLocked),
        ASN1Enumerated(verifiedBootState.ordinal),
    )
)
