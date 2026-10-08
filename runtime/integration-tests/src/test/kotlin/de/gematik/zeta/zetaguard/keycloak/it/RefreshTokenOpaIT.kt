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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.entity.ContentType.APPLICATION_JSON
import org.keycloak.events.Errors

/**
 * Refresh-token grant policy enforcement.
 *
 * Verifies that the refresh-token grant authorizes via OPA before issuing a new token set, per the spec requirement to consult the Policy Engine
 * before issuing **any** token set (Access Token + Refresh Token):
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28837
 *
 * Without OPA on the refresh path, the deny case below would still succeed — i.e. the deny test directly proves the wiring. Rotation control from
 * A_25662 must still hold on top of OPA — covered by the third test.
 *
 * The OPA-unreachable wire contract (503 + Retry-After: 30 + `temporarily_unavailable`) is verified by the docker-compose recipe in
 * keycloak-zeta/runtime/integration-tests; an automated container-stop test is intentionally omitted here to avoid the kind of cross-IT pollution
 * observed with HsmUnreachableIT.
 */
class RefreshTokenOpaIT : ZetaGuardFunSpecIT() {
  private val http: HttpClient = HttpClient.newHttpClient()
  private val opaBase = "http://localhost:18181"
  private val professionPath = "/v1/data/professions/allowed_professions"

  init {
    test("refresh succeeds when OPA allows") {
      val accessTokenResponse1 = exchange()
      val refreshed = refresh(accessTokenResponse1.refreshToken).shouldBeRight().reponseObject
      refreshed.refreshToken.shouldNotBeNull().checkTokenHeader()
    }

    test("refresh is denied when OPA denies (proves OPA is consulted on refresh path)") {
      val accessTokenResponse1 = exchange()
      withOpaValue(professionPath, "[]") {
        refresh(accessTokenResponse1.refreshToken).shouldBeLeft().also {
          it.statusCode shouldBe 403
          it.error shouldBe Errors.ACCESS_DENIED
          it.errorDescription shouldBe "policy_denied"
        }
      }
    }

    test("refresh-token rotation (reuse=0) still enforced on top of OPA") {
      val accessTokenResponse1 = exchange()
      refresh(accessTokenResponse1.refreshToken).shouldBeRight()
      refresh(accessTokenResponse1.refreshToken).shouldBeLeft().errorDescription shouldBe "Maximum allowed refresh token reuse exceeded"
    }
  }

  private fun exchange() = run {
    val nonce = createNonce()
    val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
    val smcb =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            audiences = smcbTokenAudience,
            subject = smcb.telematikId,
            certificateChain = listOf(smcb.leafCertificate),
        )
    testExchangeToken(smcb, clientAssertion = jwt)
  }

  private fun refresh(encodedRefreshToken: String) = run {
    val nonce = createNonce()
    val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
    val smcb =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            audiences = smcbTokenAudience,
            subject = smcb.telematikId,
            certificateChain = listOf(smcb.leafCertificate),
        )
    val dPoP = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcb)
    keycloakWebClient.refreshToken(encodedRefreshToken, jwt, dPoP)
  }

  private fun get(path: String): String =
      http.send(HttpRequest.newBuilder(URI.create("$opaBase$path")).GET().build(), HttpResponse.BodyHandlers.ofString()).body()

  private fun putValue(path: String, jsonValue: String) {
    val req =
        HttpRequest.newBuilder(URI.create("$opaBase$path"))
            .header(CONTENT_TYPE, APPLICATION_JSON.mimeType)
            .PUT(HttpRequest.BodyPublishers.ofString(jsonValue))
            .build()
    val res = http.send(req, HttpResponse.BodyHandlers.ofString())
    require(res.statusCode() in 200..299) { "OPA PUT $path failed: ${res.statusCode()} body=${res.body()}" }
  }

  private fun snapshot(path: String): String = get(path)

  private fun restore(path: String, snapshotBody: String) {
    val resultStart = snapshotBody.indexOf(":")
    val resultJson = if (resultStart >= 0) snapshotBody.substring(resultStart + 1).trim().trimStart() else snapshotBody
    val trimmed = if (resultJson.startsWith("{")) resultJson.dropLast(1).trim() else resultJson
    putValue(path, trimmed)
  }

  @Suppress("SameParameterValue")
  private fun <T> withOpaValue(path: String, jsonValue: String, block: () -> T): T {
    val snap = snapshot(path)
    try {
      putValue(path, jsonValue)
      return block()
    } finally {
      restore(path, snap)
    }
  }
}
