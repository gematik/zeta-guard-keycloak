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
package de.gematik.zeta.zetaguard.keycloak.client_assertion

import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AAGUID
import de.gematik.zeta.zetaguard.keycloak.client_attestation.ANDROID_KEY_ORIGIN_GENERATED
import de.gematik.zeta.zetaguard.keycloak.client_attestation.APPLE_APP_ATTEST_AAGUID_DEVELOPMENT
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidSecurityLevel
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidVerifiedBootState
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.extractRawAuthenticationData
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.toAppleAttestationObject
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.toCBOR
import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.client_attestation.extractAndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.PROPERTY_APPLE_ATTESTATION_OBJECT
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.androidCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.appleAttestationObject
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.appleAttestationStatement
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.jwk
import de.gematik.zeta.zetaguard.keycloak.commons.server.APPLE_APP_ATTESTATION_ROOT_CA
import de.gematik.zeta.zetaguard.keycloak.commons.server.APPLE_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractAppleNonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.issuerCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.toAppleKeyId
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.commons.server.toJWK
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.toThumbprint
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.commons.server.verifySignature
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.SecureRandom
import java.security.cert.X509Certificate

val SECURE_RANDOM = SecureRandom()

class AttestationUtilTest : ZetaGuardFunSpec() {
  init {
    test("Parse and check Apple attestation object") {
      val request = javaClass.getResourceAsStream("/apple_dcr.json")!!.toObject<AppleRegistrationRequest>()
      val map = javaClass.getResourceAsStream("/apple_dcr.json")!!.toObject<Map<String, Any>>()
      val jwk = request.jwk.shouldBeRight()
      val clientDataHash = jwk.toClientHashData(null).toHash()
      val attestationObject = extractAndCheckAttestationObject(request)
      val attestationStatement = extractAndCheckAttestationStatement(attestationObject)
      val leafCertificate = extractAndCheckLeafCertificate(attestationStatement)
      val rawAttestationObject = map[PROPERTY_APPLE_ATTESTATION_OBJECT].toString().fromBase64()

      checkNonce(leafCertificate, rawAttestationObject, clientDataHash)
      checkKeyId(attestationObject, leafCertificate)
      checkClientDataSignature(request)
    }

    test("Parse and check Google attestation") {
      val request = javaClass.getResourceAsStream("/android_dcr.json")!!.toObject<AndroidRegistrationRequest>()
      val jwk = request.jwk.shouldBeRight()
      val clientDataHash = jwk.toClientHashData(null).toHash()
      val certificates = request.androidCertificateChain().shouldBeRight().shouldHaveSize(4)
      val rootCertificate = certificates.last()
      val leafCertificate = certificates.first()
      val intermediateCertificate = certificates[1]

      rootCertificate shouldBe GOOGLE_ROOT_CA

      leafCertificate.checkValidity()
      rootCertificate.checkValidity()
      intermediateCertificate.checkValidity()

      validateCertificateChain(rootCertificate, certificates.drop(1)).shouldBeRight()
      validateCertificateSignature(leafCertificate, intermediateCertificate.publicKey).shouldBeRight()

      checkClientDataSignature(request)

      checkAttestationChallenge(leafCertificate, clientDataHash)
    }

    test("Generate attestation challenge") {
      val thumbprint = generateKeyPair().toJWK().toThumbprint()
      val nonceBytes = ByteArray(16).apply { SECURE_RANDOM.nextBytes(this) }
      val attestationChallenge = shouldNotThrowAny { calculateAttestationChallenge(thumbprint, nonceBytes) }

      attestationChallenge shouldBe toHash(thumbprint, nonceBytes).toBase64()
    }

    test("Hashing multiple byte arrays") {
      val thumbprint = generateKeyPair().toJWK().toThumbprint()
      val nonceBytes = ByteArray(16).apply { SECURE_RANDOM.nextBytes(this) }
      val attestationChallenge = shouldNotThrowAny { calculateAttestationChallenge(thumbprint, nonceBytes) }
      val bytes =
          ByteArray(thumbprint.size + nonceBytes.size).apply {
            thumbprint.copyInto(this, destinationOffset = 0)
            nonceBytes.copyInto(this, destinationOffset = thumbprint.size)
          }

      attestationChallenge shouldBe bytes.toHash().toBase64()
    }
  }

  private fun checkAttestationChallenge(leafCertificate: X509Certificate, clientDataHash: ByteArray) {
    val description = leafCertificate.extractAndroidKeyDescription().shouldBeRight()

    description.attestationChallenge shouldBe clientDataHash
    description.attestationSecurityLevel shouldBe AndroidSecurityLevel.STRONG_BOX
    description.keyMintSecurityLevel shouldBe AndroidSecurityLevel.STRONG_BOX

    val hardwareEnforced = description.hardwareEnforced

    hardwareEnforced.origin shouldBe ANDROID_KEY_ORIGIN_GENERATED

    val rootOfTrust = hardwareEnforced.rootOfTrust.shouldNotBeNull()

    rootOfTrust.deviceLocked.shouldBeTrue()
    rootOfTrust.verifiedBootState shouldBe AndroidVerifiedBootState.VERIFIED
  }

  private fun checkNonce(leafCertificate: X509Certificate, rawAttestationObject: ByteArray, clientDataHash: ByteArray) {
    val nonceFromCertificate = leafCertificate.extractAppleNonce()?.shouldHaveSize(32)
    val rawAuthData = rawAttestationObject.extractRawAuthenticationData().shouldBeRight()
    val nonceToHash = (rawAuthData + clientDataHash).toHash()

    nonceFromCertificate shouldBe nonceToHash
  }

  private fun checkKeyId(attestationObject: AttestationObject, leafCertificate: X509Certificate) {
    val attestedCredentialData = attestationObject.authenticatorData.attestedCredentialData.shouldNotBeNull()
    val leafPublicKey = leafCertificate.publicKey
    val keyId = leafPublicKey.toAppleKeyId()

    attestedCredentialData.credentialId shouldBe keyId
  }

  private fun extractAndCheckLeafCertificate(attestationStatement: AppleAppAttestAttestationStatement): X509Certificate {
    val leafCertificate = attestationStatement.x5c[0]
    val intermediateCertificate = attestationStatement.x5c[1]

    intermediateCertificate.issuerCommonName() shouldBe APPLE_APP_ATTESTATION_ROOT_CA
    intermediateCertificate.checkValidity()

    validateCertificateSignature(leafCertificate, intermediateCertificate.publicKey).shouldBeRight()

    shouldThrowAny { leafCertificate.checkValidity() }.message shouldContain "certificate expired"

    val rootCertificate = APPLE_ROOT_CA
    rootCertificate.subjectOrganisationName() shouldBe APPLE_ORGANISATION
    rootCertificate.subjectCommonName() shouldBe APPLE_APP_ATTESTATION_ROOT_CA

    validateCertificateChain(rootCertificate, listOf(intermediateCertificate)).shouldBeRight()

    return leafCertificate
  }

  private fun extractAndCheckAttestationStatement(attestationObject: AttestationObject): AppleAppAttestAttestationStatement {
    val attestationStatement = attestationObject.appleAttestationStatement.shouldBeRight()
    attestationStatement.x5c.shouldHaveSize(2)
    attestationStatement.x5c.forEach { it.subjectOrganisationName() shouldBe APPLE_ORGANISATION }

    val cbor = attestationObject.toCBOR().shouldBeRight()
    val fromCBOR = cbor.toAppleAttestationObject().shouldBeRight()

    fromCBOR shouldBe attestationObject

    return attestationStatement
  }

  private fun extractAndCheckAttestationObject(request: AppleRegistrationRequest): AttestationObject {
    val attestationObject = request.appleAttestationObject().shouldBeRight()

    attestationObject.format shouldBe AppleAppAttestAttestationStatement.FORMAT
    attestationObject.authenticatorData.rpIdHash.shouldNotBeEmpty()
    attestationObject.attestationStatement.javaClass shouldBe AppleAppAttestAttestationStatement::class.java

    val attestedCredentialData = attestationObject.authenticatorData.attestedCredentialData.shouldNotBeNull()

    attestedCredentialData.aaguid shouldBe AAGUID(APPLE_APP_ATTEST_AAGUID_DEVELOPMENT.toByteArray())
    attestationObject.authenticatorData.signCount shouldBe 0

    return attestationObject
  }

  companion object {
    // https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
    val APPLE_ROOT_CA = javaClass.getResourceAsStream("/apple-root-ca.pem")!!.bufferedReader().readText().toCertificate()

    // https://android.googleapis.com/attestation/root
    val GOOGLE_ROOT_CA = javaClass.getResourceAsStream("/google-root-ca.pem")!!.bufferedReader().readText().toCertificate()
  }
}

internal fun checkClientDataSignature(request: ZetaGuardOIDCClientRequestRepresentation) {
  val jwk = request.jwk.shouldBeRight()
  val data = jwk.toClientHashData(null)
  val publicKey = jwk.toPublicKey()
  val signature = request.signedHashPukClientSig!!.fromBase64()

  publicKey.verifySignature(data, signature).shouldBeRight() shouldBe true
}
