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
package de.gematik.zeta.zetaguard.keycloak.it

import com.fasterxml.jackson.databind.ObjectMapper
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveAtLeastSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.security.Signature
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED
import org.apache.http.impl.client.HttpClients
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWKParser
import org.keycloak.jose.jws.JWSInput

private const val ZETA_GUARD = "zeta-guard"

/**
 * Prerequisites:
 * - `HSM_PROXY_TOKEN_KEY_ID` set in docker-compose-it.yml
 * - `zeta-guard-realm.json` sets `defaultSignatureAlgorithm: ES256`
 */
@Order(1)
class HsmTokenSigningIT : FunSpec() {

  init {
    val baseUrl = "http://${Docker.kchost}:${Docker.kcport}"
    val mapper = ObjectMapper()

    // ── zeta-guard realm (ES256 via HSM) ─────────────────────────────────────

    test("zeta-guard JWKS contains ES256 signing key from HSM") {
      val jwks = fetchJwks(baseUrl, mapper, realm = ZETA_GUARD)
      val es256Keys = jwks.keys.filter { it.algorithm == Algorithm.ES256 && it.publicKeyUse == "sig" }

      es256Keys shouldHaveAtLeastSize 1
    }

    test("zeta-guard token is signed with ES256 via HSM") {
      val accessToken = obtainZetaGuardToken(baseUrl, mapper)
      val jws = JWSInput(accessToken)

      jws.header.algorithm.name shouldBe Algorithm.ES256
    }

    test("zeta-guard token kid matches ES256 key in JWKS") {
      val jwks = fetchJwks(baseUrl, mapper, realm = ZETA_GUARD)
      val es256Kid =
          jwks.keys
              .first { it.algorithm == Algorithm.ES256 && it.publicKeyUse == "sig" }
              .keyId

      val accessToken = obtainZetaGuardToken(baseUrl, mapper)
      val jws = JWSInput(accessToken)

      jws.header.keyId shouldBe es256Kid
    }

    test("zeta-guard ES256 signature is valid against JWKS public key") {
      val jwks = fetchJwks(baseUrl, mapper, realm = ZETA_GUARD)
      val es256Jwk = jwks.keys.first { it.algorithm == Algorithm.ES256 && it.publicKeyUse == "sig" }
      val publicKey = JWKParser.create(es256Jwk).toPublicKey()

      val accessToken = obtainZetaGuardToken(baseUrl, mapper)
      val jws = JWSInput(accessToken)

      // JWS signature is P1363 (r||s), JCA Signature expects ASN.1 DER
      val derSignature = ECDSAAlgorithm.concatenatedRSToASN1DER(jws.signature, ECDSAAlgorithm.getSignatureLength(Algorithm.ES256))
      val verifier = Signature.getInstance("SHA256withECDSA")
      verifier.initVerify(publicKey)
      verifier.update(jws.encodedSignatureInput.toByteArray(Charsets.UTF_8))
      verifier.verify(derSignature) shouldBe true
    }

    test("zeta-guard JWKS has no RSA signing keys (Decision 6)") {
      val jwks = fetchJwks(baseUrl, mapper, realm = ZETA_GUARD)
      // Decision 6: software signing keys are deleted after HSM registration.
      // Realm import may re-create a fallback EC key (lifecycle timing), but RSA
      // signing keys must not be present — no RSA key material in the DB.
      val rsaSigKeys = jwks.keys.filter { it.publicKeyUse == "sig" && it.keyType == "RSA" }

      rsaSigKeys.size shouldBe 0
    }

    // ── master realm (also ES256 via HSM) ──────────────────────────────────

    test("master realm JWKS also contains ES256 key from HSM") {
      val jwks = fetchJwks(baseUrl, mapper, realm = "master")
      val es256Keys = jwks.keys.filter { it.algorithm == Algorithm.ES256 && it.publicKeyUse == "sig" }

      es256Keys shouldHaveAtLeastSize 1
    }

    test("master realm tokens use ES256 via HSM") {
      val accessToken = obtainMasterToken(baseUrl, mapper)
      val jws = JWSInput(accessToken)

      jws.header.algorithm.name shouldBe Algorithm.ES256
    }
  }

  private fun fetchJwks(baseUrl: String, mapper: ObjectMapper, realm: String): JSONWebKeySet {
    val url = "$baseUrl/realms/$realm/protocol/openid-connect/certs"
    val response =
        HttpClients.createDefault().use { client ->
          client.execute(RequestBuilder.get(url).build()) { resp ->
            resp.entity.content.readBytes()
          }
        }
    return mapper.readValue(response, JSONWebKeySet::class.java)
  }

  private fun obtainMasterToken(baseUrl: String, mapper: ObjectMapper): String =
      obtainToken(baseUrl, mapper, realm = "master", clientId = "admin-cli", username = "zeta", password = "sigma")

  private fun obtainZetaGuardToken(baseUrl: String, mapper: ObjectMapper): String =
      obtainToken(
          baseUrl,
          mapper,
          realm = "zeta-guard",
          clientId = "initial-client",
          username = "user1",
          password = "password",
      )

  private fun obtainToken(
      baseUrl: String,
      mapper: ObjectMapper,
      realm: String,
      clientId: String,
      username: String,
      password: String,
  ): String {
    val url = "$baseUrl/realms/$realm/protocol/openid-connect/token"
    val request =
        RequestBuilder.post(url)
            .addHeader("Content-Type", APPLICATION_FORM_URLENCODED.mimeType)
            .addParameter("grant_type", "password")
            .addParameter("client_id", clientId)
            .addParameter("username", username)
            .addParameter("password", password)
            .build()

    val body =
        HttpClients.createDefault().use { client ->
          client.execute(request) { resp -> resp.entity.content.readBytes() }
        }

    val tree = mapper.readTree(body)
    val accessToken = tree["access_token"]?.asText()
    accessToken.shouldNotBeNull()
    return accessToken
  }
}
