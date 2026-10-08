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
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_A_ID
import de.gematik.zeta.zetaguard.keycloak.commons.USER1
import de.gematik.zeta.zetaguard.keycloak.commons.USER1_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotBeEmpty
import java.util.concurrent.TimeUnit
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.HttpStatus
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED
import org.apache.http.impl.client.HttpClients
import org.keycloak.OAuth2Constants.PASSWORD
import org.keycloak.OAuth2Constants.USERNAME
import org.keycloak.crypto.Algorithm
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jws.JWSInput
import org.keycloak.protocol.oidc.OIDCLoginProtocol.CLIENT_ID_PARAM
import org.keycloak.protocol.oidc.OIDCLoginProtocol.GRANT_TYPE_PARAM
import org.testcontainers.DockerClientFactory

/**
 * Verifies the authserver refuses to issue tokens when HSM goes down at runtime, with no software-key fallback.
 *
 * Runs alphabetically after [HsmTokenSigningIT], which establishes the HSM-up baseline. We stop hsm-sim mid-test via the Docker client API, observe
 * fail-closed behaviour, then restart it so later ITs see a healthy stack.
 *
 * Scope: this covers the **warm-cache** fail-closed path — Keycloak already has an HSM KeyWrapper, so signing fails at the gRPC layer with a 5xx, and
 * no software key materialises. The **cold-start** path through [HsmTokenSigningKeyProviderFactory.createFallbackKeys] (HSM unreachable at boot,
 * component present, no cached KeyWrapper) is covered by unit tests only — exercising it in-stack would need a Keycloak restart with hsm-sim already
 * down, which this IT framework can't do cleanly.
 */
class HsmUnreachableIT : FunSpec() {

  init {
    val baseUrl = "http://${Docker.kchost}:${Docker.kcport}"
    val mapper = ObjectMapper()
    val dockerClient = DockerClientFactory.instance().client()

    var hsmContainerId: String? = null
    var baselineSigKids: Set<String> = emptySet()

    beforeSpec {
      hsmContainerId = dockerClient.listContainersCmd().withShowAll(false).exec().firstOrNull { c -> c.names.any { it.contains("hsm-sim") } }?.id
      hsmContainerId.shouldNotBe(null)

      // Snapshot the SIG keys exposed by zeta-guard's JWKS BEFORE HSM goes down. A software
      // fallback would later add new kids; comparing kid sets makes the assertion precise.
      val baseline = fetchJwks(baseUrl, mapper, ZETA_REALM)
      baselineSigKids = baseline.keys.filter { it.publicKeyUse == "sig" }.mapNotNull { it.keyId }.toSet()
      baseline.keys.filter { it.algorithm == Algorithm.ES256 && it.publicKeyUse == "sig" }.size shouldBeGreaterThanOrEqual 1

      dockerClient.stopContainerCmd(hsmContainerId!!).withTimeout(5).exec()
    }

    afterSpec {
      hsmContainerId?.let { runCatching { dockerClient.startContainerCmd(it).exec() } }
      awaitStableHsmRecovery(baseUrl)
    }

    test("token endpoint returns 5xx when HSM is unreachable (no software-signed JWT)") {
      val (status, body) = postTokenRequest(baseUrl)

      status shouldNotBe HttpStatus.SC_OK
      // Keycloak surfaces signing failures as 5xx
      (status >= 500) shouldBe true
      body.shouldNotBeEmpty()
    }

    test("JWKS does not gain a software-generated signing key while HSM is down") {
      // Exercise the fallback path multiple times — each failure that does NOT persist a
      // software key is the contract we care about. A pre-fix build would materialise an
      // ecdsa-generated ComponentModel after the first attempt; we'd see a new kid here.
      repeat(3) { postTokenRequest(baseUrl) }

      val jwks = fetchJwks(baseUrl, mapper, ZETA_REALM)

      // No RSA signing keys whatsoever (Decision 6).
      jwks.keys.filter { it.publicKeyUse == "sig" && it.keyType == "RSA" }.shouldBeEmpty()

      // No new SIG kids appeared — software fallback would add one not present in baseline.
      val currentSigKids = jwks.keys.filter { it.publicKeyUse == "sig" }.mapNotNull { it.keyId }.toSet()
      (currentSigKids - baselineSigKids).shouldBeEmpty()
    }

    test("token issuance recovers once HSM is reachable again") {
      // Bring hsm-sim back up.
      dockerClient.startContainerCmd(hsmContainerId!!).exec()

      // gRPC reconnect + Keycloak's per-session providersMap rebuild happen on the next
      // token request — poll until success or timeout.
      val deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30)
      var lastStatus = 0
      var token: String? = null
      while (System.currentTimeMillis() < deadline) {
        val (status, body) = postTokenRequest(baseUrl)
        lastStatus = status
        if (status == HttpStatus.SC_OK) {
          token = mapper.readTree(body)["access_token"]?.asText()
          break
        }
        Thread.sleep(1000)
      }

      lastStatus shouldBe HttpStatus.SC_OK
      token shouldNotBe null

      // The recovered token must be ES256 (HSM-signed), not anything else.
      JWSInput(token).header.algorithm.name shouldBe Algorithm.ES256
    }
  }

  /** Polls token issuance until 3 consecutive 200s, or fails. authserver's gRPC channel can stay flaky for several seconds after hsm-sim restart. */
  private fun awaitStableHsmRecovery(baseUrl: String) {
    val deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(60)
    var consecutive = 0
    while (consecutive < 3 && System.currentTimeMillis() < deadline) {
      if (postTokenRequest(baseUrl).first == HttpStatus.SC_OK) consecutive++ else consecutive = 0
      if (consecutive < 3) Thread.sleep(1000)
    }
    check(consecutive >= 3) { "hsm-sim recovery unstable: $consecutive/3 consecutive 200s within 60s" }
  }

  private fun fetchJwks(baseUrl: String, mapper: ObjectMapper, realm: String): JSONWebKeySet {
    val url = "$baseUrl/realms/$realm/protocol/openid-connect/certs"
    val response =
        HttpClients.createDefault().use { client -> client.execute(RequestBuilder.get(url).build()) { resp -> resp.entity.content.readBytes() } }
    return mapper.readValue(response, JSONWebKeySet::class.java)
  }

  private fun postTokenRequest(baseUrl: String): Pair<Int, String> {
    val url = "$baseUrl/realms/zeta-guard/protocol/openid-connect/token"
    val request =
        RequestBuilder.post(url)
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            .addParameter(GRANT_TYPE_PARAM, PASSWORD)
            .addParameter(CLIENT_ID_PARAM, CLIENT_A_ID)
            .addParameter(USERNAME, USER1)
            .addParameter(PASSWORD, USER1_PASSWORD)
            .build()

    return HttpClients.createDefault().use { client ->
      client.execute(request) { resp -> resp.statusLine.statusCode to String(resp.entity.content.readBytes()) }
    }
  }
}
