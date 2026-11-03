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
package de.gematik.zeta.zetaguard.keycloak.commons

import arrow.core.getOrElse
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import de.gematik.zeta.zetaguard.keycloak.client_attestation.ANDROID_KEY_ORIGIN_GENERATED
import de.gematik.zeta.zetaguard.keycloak.client_attestation.APPLE_APP_ATTEST_AAGUID
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidAuthorizationList
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidRootOfTrust
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidSecurityLevel
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidVerifiedBootState
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.toCBOR
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.SoftwareRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.TpmRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaAttestationTokenRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.SMC_B_VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.getPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.signData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toAppleKeyId
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import java.math.BigInteger
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import org.keycloak.crypto.Algorithm.ES256
import org.keycloak.protocol.oidc.OIDCLoginProtocol.PRIVATE_KEY_JWT
import org.keycloak.protocol.oidc.utils.OIDCResponseType

@SuppressWarnings("java:S2068", "java:S1192")
const val APPLE_TRUSTSTORE_PASSWORD = "04edb0b1a1eacf727ff6f" // NOSONAR

@SuppressWarnings("java:S2068", "java:S1192")
const val GOOGLE_TRUSTSTORE_PASSWORD = "f92009e853b6b045" // NOSONAR

typealias AppleAuthenticatorData = AuthenticatorData<RegistrationExtensionAuthenticatorOutput>

object ClientRegistrationRequestFactory {
  private val appleKeystoreService by lazy {
    KeystoreService("APPLE",
        javaClass.getResourceAsStream("/apple-certificates-server.p12")!!, APPLE_TRUSTSTORE_PASSWORD
    )
  }

  private val googleKeystoreService by lazy {
    KeystoreService("GOOGLE",
        javaClass.getResourceAsStream("/google-certificates-server.p12")!!, GOOGLE_TRUSTSTORE_PASSWORD
    )
  }

  fun createClientRegistrationRequest(
      pki: PKIData,
      nonce: ByteArray?,
      leafKeyPair: KeyPair = generateKeyPair(),
      redirectUris: List<String>? = null,
      grantTypes: List<String> = SMC_B_VALID_GRANT_TYPES,
      responseTypes: List<String> = listOf(OIDCResponseType.TOKEN),
      attestationType: AttestationType = AttestationType.SOFTWARE,
      appleAuthenticatorData: AppleAuthenticatorData = createAppleAuthenticatorData(leafKeyPair.public),
      androidKeyDescription: AndroidKeyDescription = createAndroidKeyDescription(pki.jwk.toClientHashData(nonce).toHash()),
      leafSerialNumber: BigInteger = createSerialNumber()
  ): ZetaGuardOIDCClientRequestRepresentation = when (attestationType) {
    AttestationType.SOFTWARE -> SoftwareRegistrationRequest()
    AttestationType.APPLE -> createAppleRegistrationRequest(pki, leafKeyPair, nonce, appleAuthenticatorData)
    AttestationType.ANDROID -> createAndroidRegistrationRequest(leafKeyPair, androidKeyDescription, leafSerialNumber)
    AttestationType.TPM -> TpmRegistrationRequest()
    AttestationType.ZETA_ATTESTATION_TOKEN -> ZetaAttestationTokenRegistrationRequest()
  }.apply {
    clientName = ZETA_GUARD_CLIENT_NAME
    tokenEndpointAuthMethod = PRIVATE_KEY_JWT // "none" -> public client
    tokenEndpointAuthSigningAlg = ES256

    // See https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#A_27799
    this.grantTypes = grantTypes
    this.jwks = pki.jwks
    this.responseTypes = responseTypes
    this.redirectUris = redirectUris
    this.nonce = nonce?.toBase64()

    val clientHashData = pki.jwk.toClientHashData(nonce)
    val signature = pki.keypair.private.signData(clientHashData).getOrElse { error("Could not sign data!") }

    signedHashPukClientSig = signature.toBase64()
  }

  private fun createAppleRegistrationRequest(
      pki: PKIData,
      leafKeyPair: KeyPair,
      nonce: ByteArray?,
      appleAuthenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput>
  ): AppleRegistrationRequest = AppleRegistrationRequest().apply {
    val authData = appleAuthenticatorData.toCBOR().getOrElse { throw it }
    val clientHashData = pki.jwk.toClientHashData(nonce)
    val clientDataHash = clientHashData.toHash()
    val nonceToHash = (authData + clientDataHash).toHash()
    val intermediate = appleKeystoreService.findCertificate(APPLE_INTERMEDIATE_CA) ?: error("Missing intermediate certificate!")
    val intermediatePrivateKey = appleKeystoreService.getPrivateKey(APPLE_INTERMEDIATE_CA, APPLE_TRUSTSTORE_PASSWORD)
    val leaf = CertificateGenerator(
        subjectName = APPLE_LEAF_DN,
        subjectKeyPair = leafKeyPair,
        issuerName = intermediate.subjectX500Principal.name,
        issuerKeyPair = KeyPair(intermediatePrivateKey.getPublicKey(), intermediatePrivateKey),
        isCA = false,
        appleNonce = nonceToHash
    ).buildCertificate()

    appleAttestationObject = AttestationObject(
        appleAuthenticatorData,
        AppleAppAttestAttestationStatement(
            AttestationCertificatePath(listOf(leaf, intermediate)),
            "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID6DGCBVkwNAIBAgIBAQQsVktCTkYzS1I5VC5kZS5nZW1hdGlrLnpldGEudGVzdGNsaWVudC5pb3NBcHAwggQuAgEDAgEBBIIEJDCCBCAwggOnoAMCAQICBgGggUrGZTAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yNjA5MDcxMzUyMzZaFw0yNjA5MTAxMzUyMzZaMIGRMUkwRwYDVQQDDEAzMTMzNDgyMTM5Y2VlNDEwODJiNzc1MWMxNTFlNTkwNTgwNGVkYjBiMWExZWFjZjcyN2ZmNmY5YzNmNzhjMzQ3MRowGAYDVQQLDBFBQUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKvJXcPKiOXZSs8j0z1ISfuGybQIJ1C3NU1nf_S7AytsVpko9FjFNh1TyArOINxGBxWwge1gYr6AtB6EUSqOVyejggIqMIICJjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAUBgNVHSUEDTALBgkqhkiG92NkBBgwgYoGCSqGSIb3Y2QIBQR9MHukAwIBCr-JMAMCAQC_iTEDAgEAv4kyAwIBAL-JMwMCAQC_iTQuBCxWS0JORjNLUjlULmRlLmdlbWF0aWsuemV0YS50ZXN0Y2xpZW50Lmlvc0FwcL-JNgMCAQS_iTcDAgEAv4k5AwIBAL-JOgMCAQC_iTsDAgEAqgMCAQAwgdMGCSqGSIb3Y2QIBwSBxTCBwr-KeAgEBjI2LjYuMb-IUAMCAQK_inkJBAcxLjAuMjMzv4p7BwQFMjNHODO_inwIBAYyNi42LjG_in0IBAYyNi42LjG_in4DAgEAv4p_AwIBAL-LAAMCAQC_iwEDAgEAv4sCAwIBAL-LAwMCAQC_iwQDAgEBv4sFAwIBAL-LCg8EDTIzLjcuODMuMC4wLDC_iwsPBA0yMy43LjgzLjAuMCwwv4sMDwQNMjMuNy44My4wLjAsML-IAgoECGlwaG9uZW9zMDMGCSqGSIb3Y2QIAgQmMCShIgQgk5MVs3VguTUMkRUiq18wjy2jj0Woez0t4KksAy47iCUwWAYJKoZIhvdjZAgGBEswSaNHBEUwQwwCMTEwPTAKDANva2ShAwEB_zAJDAJvYaEDAQH_MAsMBG9zZ26hAwEB_zALDARvZGVsoQMEggF1AQH_MAoMA29ja6EDAQH_MAoGCCqGSM49BAMCA2cAMGQCMEu27lRnoQFjF3bJkfTvwz-tDZ0ZJPEpfyvvJpUMHJ_-43OJMoNUOzhvZP3CPAlw4gIwZby4bMR1utFhHuzjWGrPryiuKxkMDQV65cEu0AGfGqAobL6ntWnIox7n5iyb569UMCgCAQQCAQEEIK3voddDwoYIY76_T8Jn2zc705x7R-lrXHPIe3usmiNMMGACAQUCAQEEWGVoemlOTitEbThLTzN5TWRHdEVrajNXWXA2MWk1Q3E2QTNwVkFjanJvRi84WHNNdUtnNWtnWDhPVzZYbFd4VFhRWHJOUy9tU2tINjRORWRDREw5aEhnPT0wDgIBBgIBAQQGQVRURVNUMA8CAQcCAQEEB3NhbmRib3gwIAIBDAIBAQQYMjAyNi0wOS0wOFQxMzo1MjozNi40OTFaMCACARUCAQEEGDIwMjYtMTItMDdUMTM6NTI6MzYuNDkxWgAAAAAAAKCAMIIDrjCCA1SgAwIBAgIQZgI4gAAUJvddiw4VLF9uQzAKBggqhkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yNjAxMjAyMDIxMDlaFw0yNzAyMTgxODU4MzlaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7GK7OxRmtilNRtEBEtKMDmVe0zb1bhR_gGm_t4o3vsPqww2oCpB9EbgBtWA5WimeAiQfzSICRQ4sgzqpMndxWo4IB2DCCAdQwDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBTZF_5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUNFWJcHRgDiLSumfPpVtpwiPxyigwDgYDVR0PAQH_BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDSAAwRQIgHGeXuYJF0dbccgS3mwI8r_h78u_4k33XIMReiuRlwusCIQD8yFmEzsmhLMKGqdSSdv3w0vYl3HX8fPiHRWl75h6qtDCCAvkwggJ_oAMCAQICEFb7g9Qr_43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv-wSUgJGs9jHfpssoNW9ES-Eh5VfdEo2NuoJ8lb5J-r4zyq7NBBnxL0Ml-vS-s8uDfrqjgfcwgfQwDwYDVR0TAQH_BAUwAwEB_zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6-veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf-S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH_BAQDAgEGMBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr-OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG-gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F_IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW2Q7lpgUqd2R7X04407scRLV_9R-2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6-veuv2sskqzAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg-nBxBZeGl00GNnt7_RsDgBGS7jfskYRxQ_95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E_NjUM-tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA-eisigAADGB_TCB-gIBATCBkDB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIQZgI4gAAUJvddiw4VLF9uQzANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRHMEUCIFZN0acIWJ809B6Wd08POpK8G7QvmlkQL4XKIxBCRBU9AiEAlWqgQ_5OWtoFHn9juKw_K33X6QoIMiw4H6wGcQlW6qQAAAAAAAA".fromBase64()
        )
    ).toCBOR().getOrElse { error("Could not get attestation object!") }.toBase64()
  }

  /**
   * Certificate chain (leaf, intermediate, root) issued by the test Google trust store, the leaf certifying [leafKeyPair] with the given key
   * description.
   */
  private fun createAndroidRegistrationRequest(leafKeyPair: KeyPair, androidKeyDescription: AndroidKeyDescription,
                                               leafSerialNumber: BigInteger = createSerialNumber()) =
      AndroidRegistrationRequest().apply {
        val root = googleKeystoreService.findCertificate(GOOGLE_ROOT_CA) ?: error("Missing root certificate!")
        val intermediate = googleKeystoreService.findCertificate(GOOGLE_INTERMEDIATE_CA) ?: error("Missing intermediate certificate!")
        val intermediatePrivateKey = googleKeystoreService.getPrivateKey(GOOGLE_INTERMEDIATE_CA, GOOGLE_TRUSTSTORE_PASSWORD)
        val leaf = CertificateGenerator(
            subjectName = GOOGLE_LEAF_DN,
            subjectKeyPair = leafKeyPair,
            issuerName = intermediate.subjectX500Principal.name,
            issuerKeyPair = KeyPair(intermediatePrivateKey.getPublicKey(), intermediatePrivateKey),
            isCA = false,
            createAdmissionExtension = false,
            androidKeyDescription = androidKeyDescription
        ).buildCertificate(leafSerialNumber)

        androidKeyAttestationCertificateChain = listOf(leaf, intermediate, root).map { it.encoded.toBase64() }
      }

  fun createAndroidKeyDescription(
      attestationChallenge: ByteArray,
      securityLevel: AndroidSecurityLevel = AndroidSecurityLevel.STRONG_BOX,
      origin: Long? = ANDROID_KEY_ORIGIN_GENERATED,
      rootOfTrust: AndroidRootOfTrust? = AndroidRootOfTrust(ByteArray(32), true, AndroidVerifiedBootState.VERIFIED),
  ) = AndroidKeyDescription(
      attestationVersion = 300,
      attestationSecurityLevel = securityLevel,
      keyMintVersion = 300,
      keyMintSecurityLevel = securityLevel,
      attestationChallenge = attestationChallenge,
      hardwareEnforced = AndroidAuthorizationList(origin, rootOfTrust),
  )

  fun createAppleAuthenticatorData(
      leafPublicKey: PublicKey,
      aaguid: AAGUID = APPLE_APP_ATTEST_AAGUID,
      signCount: Long = 0,
      credentialId: ByteArray = leafPublicKey.toAppleKeyId(),
  ) = AppleAuthenticatorData(
      "vlgZtsDKrXBcPmQJ-sgPhsaaWFfofqpC3v-ZlDVH-G0".fromBase64(),
      64.toByte(), signCount,
      AttestedCredentialData(aaguid, credentialId, EC2COSEKey.create(leafPublicKey as ECPublicKey))
  )
}
