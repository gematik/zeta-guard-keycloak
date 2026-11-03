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
package de.gematik.zeta.zetaguard.keycloak.dcr_request

import de.gematik.zeta.zetaguard.keycloak.client_assertion.checkClientDataSignature
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.Platform
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.SoftwareRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.TpmRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaAttestationTokenRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.signData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

class ZetaGuardOIDCClientRequestRepresentationTest : ZetaGuardFunSpec() {
  init {
    val pki = PKIData(generateKeyPair())

    test("Serialize and deserialize TPM registration request") {
      val request =
          TpmRegistrationRequest().apply {
            clientName = "demo_client"
            grantTypes = listOf("authorization_code")
            redirectUris = listOf("https://example.com/cb/demo/app")
            jwks = pki.jwks
            platform = Platform.WINDOWS
            productId = "gematik-product"
            productVersion = "1.0.0"
            pukEkEnc = "puk_ek_enc"
            cEkEnc = "c_ek_enc"
            pukAkSig = "puk_ak_sig"
            signedHashPukClientSig = "signed_hash"
          }
      val json = request.toJSON()

      json shouldContain "\"attestation_type\":\"tpm\""
      json shouldContain "\"puk_ek_enc\":\"puk_ek_enc\""
      json shouldContain "\"client_name\":\"demo_client\""

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<TpmRegistrationRequest>()
      parsed.clientName shouldBe request.clientName
      parsed.productId shouldBe request.productId
      parsed.pukAkSig shouldBe request.pukAkSig
      parsed.signedHashPukClientSig shouldBe request.signedHashPukClientSig
    }

    test("Serialize and deserialize Apple registration request") {
      val request = createAppleRegistrationRequest(pki)
      val json = request.toJSON()

      json shouldContain "\"attestation_type\":\"apple\""

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<AppleRegistrationRequest>()
      parsed.appleAttestationObject shouldBe request.appleAttestationObject
    }

    test("Check signature of Apple registration request") {
      val request = createAppleRegistrationRequest(pki)

      checkClientDataSignature(request)
    }

    test("Serialize and deserialize Android registration request") {
      val request =
          AndroidRegistrationRequest().apply {
            clientName = "demo_client"
            jwks = pki.jwks
            platform = Platform.ANDROID
            productId = "gematik-product"
            productVersion = "1.0.0"
            androidKeyAttestationCertificateChain = listOf("cert1", "cert2", "cert3")
            signedHashPukClientSig = "signed_hash"
            playIntegrityToken = "play_integrity_token"
          }
      val json = request.toJSON()

      json shouldContain "\"attestation_type\":\"android\""

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<AndroidRegistrationRequest>()
      parsed.androidKeyAttestationCertificateChain shouldBe request.androidKeyAttestationCertificateChain
      parsed.playIntegrityToken shouldBe request.playIntegrityToken
    }

    test("Serialize and deserialize ZETA attestation token registration request") {
      val request =
          ZetaAttestationTokenRegistrationRequest().apply {
            clientName = "demo_client"
            jwks = pki.jwks
            zetaAttestationToken = "zeta_attestation_token_jwt"
            signedHashPukClientSig = "signed_hash"
            nonce = "some_nonce"
            attestationPop = "attestation_pop"
          }
      val json = request.toJSON()

      json shouldContain "\"attestation_type\":\"zeta_attestation_token\""

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<ZetaAttestationTokenRegistrationRequest>()
      parsed.attestationPop shouldBe request.attestationPop
      parsed.zetaAttestationToken shouldBe request.zetaAttestationToken
    }

    test("Serialize and deserialize Software registration request") {
      val request =
          SoftwareRegistrationRequest().apply {
            clientName = "demo_client"
            tokenEndpointAuthMethod = "self_signed_tls_client_auth"
            jwks = pki.jwks
            platform = Platform.LINUX
            productId = "gematik-product"
            productVersion = "1.0.0"
            nonce = "some_nonce"
            signedHashPukClientSig = "signed_hash"
          }
      val json = request.toJSON()

      json shouldContain "\"attestation_type\":\"software\""

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<SoftwareRegistrationRequest>()
      parsed.clientName shouldBe request.clientName
      parsed.tokenEndpointAuthMethod shouldBe request.tokenEndpointAuthMethod
      parsed.nonce shouldBe request.nonce
    }

    test("Legacy request without attestation_type falls back to Software registration request") {
      val json =
          """
          {
            "client_name": "legacy_client",
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": "x-coord", "y": "y-coord" } ] }
          }
          """
              .trimIndent()

      val parsed = json.toObject<ZetaGuardOIDCClientRequestRepresentation>()
      parsed.shouldBeInstanceOf<SoftwareRegistrationRequest>()
      parsed.clientName shouldBe "legacy_client"
      parsed.attestationType shouldBe AttestationType.SOFTWARE
    }
  }

  private fun createAppleRegistrationRequest(pki: PKIData): AppleRegistrationRequest {
    val data = pki.jwk.toClientHashData(null)
    val signature = pki.keypair.private.signData(data).shouldBeRight()

    return AppleRegistrationRequest().apply {
      clientName = "demo_client"
      jwks = pki.jwks
      platform = Platform.APPLE
      productId = "gematik-product"
      productVersion = "1.0.0"
      appleAttestationObject = "attestation_object"
      signedHashPukClientSig = signature.toBase64()
    }
  }
}
