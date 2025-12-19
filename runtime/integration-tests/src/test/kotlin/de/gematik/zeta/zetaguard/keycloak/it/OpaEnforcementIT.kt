/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.entity.ContentType.APPLICATION_JSON

private const val POLICY_DENIED = "policy_denied"

@Order(2)
class OpaEnforcementIT : FunSpec() {
  private val keycloak = KeycloakWebClient()
  private val realmUrl = keycloak.uriBuilder().realmUrl().toString()

  private val http: HttpClient = HttpClient.newHttpClient()
  private val opaBase = "http://localhost:18181"

  init {
    test("OPA allow: permitted scope and audience") {
      val nonce = keycloak.getNonce().shouldBeRight().reponseObject
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
      val smcb =
          smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = listOf(keycloak.uriBuilder().build().toString()),
              certificateChain = listOf(SMCBTokenHelper.leafCertificate),
          )

      keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true)
    }

    test("OPA deny: scopes not allowed") {
      withOpaValue("/v1/data/token/allowed_scopes", "[\"only-other-scope\"]") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true) {
          it.statusCode shouldBe 403
          it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
          it.errorDescription shouldBe POLICY_DENIED
        }
      }
    }

    test("OPA deny: audience not allowed") {
      withOpaValue("/v1/data/audiences/allowed_audiences", "[\"https://example.com/only\"]") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true) {
          it.statusCode shouldBe 403
          it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
          it.errorDescription shouldBe POLICY_DENIED
        }
      }
    }

    test("OPA deny: profession not allowed") {
      withOpaValue("/v1/data/professions/allowed_professions", "[]") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true) {
          it.statusCode shouldBe 403
          it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
          it.errorDescription shouldBe POLICY_DENIED
        }
      }
    }

    test("OPA deny: product posture not allowed") {
      withOpaValue("/v1/data/products/allowed_products", "{}") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true) {
          it.statusCode shouldBe 403
          it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
          it.errorDescription shouldBe POLICY_DENIED
        }
      }
    }

    test("OPA allow: profession explicitly allowed") {
      // Allow only the SMCB profession OID used in the test certificate
      withOpaValue("/v1/data/professions/allowed_professions", "[\"1.2.276.0.76.4.50\"]") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true)
      }
    }

    test("OPA deny: profession mismatch (different allowed OID)") {
      // Set an allowed profession OID that does not match the certificate's profession OID
      withOpaValue("/v1/data/professions/allowed_professions", "[\"1.2.276.0.76.4.51\"]") {
        val nonce = keycloak.getNonce().shouldBeRight().reponseObject
        val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
        val smcb =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = listOf(keycloak.uriBuilder().build().toString()),
                certificateChain = listOf(SMCBTokenHelper.leafCertificate),
            )

        keycloak.testExchangeToken(subjectToken = smcb, clientAssertion = jwt, requestedClientScope = CLIENT_B_SCOPE, useDPoP = true) {
          it.statusCode shouldBe 403
          it.error shouldBe org.keycloak.events.Errors.ACCESS_DENIED
          it.errorDescription shouldBe POLICY_DENIED
        }
      }
    }
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

  // Snapshot the current value (stores full {"result": ...} envelope)
  private fun snapshot(path: String): String = get(path)

  private fun restore(path: String, snapshotBody: String) {
    // Snapshot body is of shape {"result": <value>} from OPA GET
    val resultStart = snapshotBody.indexOf(":")
    val resultJson = if (resultStart >= 0) snapshotBody.substring(resultStart + 1).trim().trimStart() else snapshotBody
    val trimmed = if (resultJson.startsWith("{")) resultJson.dropLast(1).trim() else resultJson
    putValue(path, trimmed)
  }

  // Run a block with a temporary OPA value at [path], restoring afterward
  private fun <T> withOpaValue(path: String, jsonValue: String, block: () -> T): T {
    val snap = snapshot(path)
    try {
      putValue(path, jsonValue)
      return block()
    } finally {
      restore(path, snap)
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
