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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import arrow.core.getOrElse
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.any
import com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration.options
import de.gematik.zeta.zetaguard.keycloak.commons.server.EC_CURVE_P256
import de.gematik.zeta.zetaguard.keycloak.commons.server.signData
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicInteger
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKBuilder
import org.keycloak.util.JsonSerialization

/** TTL of every statement the mock issues. */
private const val STATEMENT_LIFETIME_SECONDS = 300

/** Numbers the mocks so each one gets issuers of its own. */
private val instanceCounter = AtomicInteger()

/** The endpoints [FederationMock] serves. */
enum class FederationEndpoint {
  FEDMASTER_STATEMENT,
  FEDMASTER_FETCH,
  IDP_STATEMENT,
  SIGNED_JWKS,
  PAR,
  TOKEN,
}

/**
 * An EC/P-256 signing key with its public JWK.
 *
 * The mock keeps three: the Federation Master's key, the SekIDP's federation key (signs entity statement and signed
 * JWK set) and its protocol key (signs ID tokens).
 */
class FederationKey(val kid: String) {

  val keyPair: KeyPair =
      KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(EC_CURVE_P256)) }.generateKeyPair()

  val publicJwk: JWK = JWKBuilder.create().kid(kid).algorithm(Algorithm.ES256).ec(keyPair.public)

  /** Signs [payload] into a compact JWS; [alg], [kid] and [extraHeaders] let negative tests forge the header. */
  fun sign(
      payload: Map<String, Any?>,
      alg: String = Algorithm.ES256,
      kid: String? = this.kid,
      extraHeaders: Map<String, Any> = emptyMap(),
  ): String {
    val header = buildMap<String, Any> {
      put("alg", alg)
      put("typ", "entity-statement+jwt")
      kid?.let { put("kid", it) }
      putAll(extraHeaders)
    }
    val encodedHeader = Base64Url.encode(JsonSerialization.writeValueAsBytes(header))
    val encodedPayload = Base64Url.encode(JsonSerialization.writeValueAsBytes(payload))
    val signingInput = "$encodedHeader.$encodedPayload"
    val data = signingInput.toByteArray(StandardCharsets.UTF_8)
    val derSignature = keyPair.private.signData(data).getOrElse { throw it }
    val rawSignature = ECDSAAlgorithm.asn1derToConcatenatedRS(derSignature, ECDSAAlgorithm.getSignatureLength(Algorithm.ES256))

    return "$signingInput.${Base64Url.encode(rawSignature)}"
  }
}

/**
 * A Federation Master and a sectoral IDP on one WireMock listener.
 *
 * Every endpoint starts out valid; [serve] replaces one so a test breaks exactly one link of the chain. Issuers carry
 * an instance number because the production caches are static and keyed by URL.
 */
class FederationMock : AutoCloseable {

  private val server = WireMockServer(options().dynamicPort().bindAddress("127.0.0.1")).apply { start() }

  private val baseUrl = "http://127.0.0.1:${server.port()}"

  private val instance = instanceCounter.incrementAndGet()

  val fedmasterUrl = "$baseUrl/fedmaster-$instance"
  val sekIdpIssuer = "$baseUrl/idp-$instance"

  val fedmasterKey = FederationKey("fedmaster-sig")
  val federationKey = FederationKey("idp-federation-sig")
  val protocolKey = FederationKey("idp-protocol-sig")

  val parEndpoint = url(FederationEndpoint.PAR)
  val authorizationEndpoint = "$sekIdpIssuer/auth"
  val tokenEndpoint = url(FederationEndpoint.TOKEN)
  val signedJwksUri = url(FederationEndpoint.SIGNED_JWKS)

  /** The `request_uri` the default PAR stub hands out. */
  val parRequestUri = "urn:ietf:params:oauth:request_uri:mock-$instance"

  init {
    serve(FederationEndpoint.FEDMASTER_STATEMENT, fedmasterKey.sign(defaultFedmasterStatementBody()))
    // The Federation Master vouching for the SekIDP's federation key.
    serve(FederationEndpoint.FEDMASTER_FETCH, fedmasterKey.sign(defaultVouchBody()))
    serve(FederationEndpoint.IDP_STATEMENT, federationKey.sign(defaultIdpStatementBody()))
    serve(FederationEndpoint.SIGNED_JWKS, federationKey.sign(defaultSignedJwksBody()))
    serve(FederationEndpoint.PAR, """{"request_uri":"$parRequestUri","expires_in":60}""", status = 201)
  }

  /** Answers [endpoint] with [body] from here on; the latest call wins. */
  fun serve(endpoint: FederationEndpoint, body: String, status: Int = 200) {
    server.stubFor(
        any(urlPathEqualTo(path(endpoint)))
            .willReturn(aResponse().withStatus(status).withHeader("Content-Type", "application/json").withBody(body)))
  }

  /** Every path the mock was asked for, in order. */
  val requestedPaths: List<String>
    get() = server.allServeEvents.reversed().map { it.request.url.substringBefore('?') }

  /** How often the mock was asked for [endpoint]. */
  fun callsTo(endpoint: FederationEndpoint): Int = requestedPaths.count { it == path(endpoint) }

  /** The form parameters of the single PAR request received. */
  fun parRequest(): Map<String, String> =
      server.findAll(anyRequestedFor(urlPathEqualTo(path(FederationEndpoint.PAR)))).single().formParameters().mapValues { it.value.firstValue() }

  private fun url(endpoint: FederationEndpoint): String =
      when (endpoint) {
        FederationEndpoint.FEDMASTER_STATEMENT -> "$fedmasterUrl/.well-known/openid-federation"
        FederationEndpoint.FEDMASTER_FETCH -> "$fedmasterUrl/fetch"
        FederationEndpoint.IDP_STATEMENT -> "$sekIdpIssuer/.well-known/openid-federation"
        FederationEndpoint.SIGNED_JWKS -> "$sekIdpIssuer/signed-jwks"
        FederationEndpoint.PAR -> "$sekIdpIssuer/par"
        FederationEndpoint.TOKEN -> "$sekIdpIssuer/token"
      }

  private fun path(endpoint: FederationEndpoint): String = url(endpoint).removePrefix(baseUrl)

  fun defaultFedmasterStatementBody(): Map<String, Any?> =
      mapOf(
          "iss" to fedmasterUrl,
          "sub" to fedmasterUrl,
          "iat" to Time.currentTime(),
          "exp" to Time.currentTime() + STATEMENT_LIFETIME_SECONDS,
          "jwks" to mapOf("keys" to listOf(fedmasterKey.publicJwk)),
          "metadata" to mapOf("federation_entity" to mapOf("federation_fetch_endpoint" to url(FederationEndpoint.FEDMASTER_FETCH))),
      )

  fun defaultVouchBody(): Map<String, Any?> =
      mapOf(
          "iss" to fedmasterUrl,
          "sub" to sekIdpIssuer,
          "iat" to Time.currentTime(),
          "exp" to Time.currentTime() + STATEMENT_LIFETIME_SECONDS,
          "jwks" to mapOf("keys" to listOf(federationKey.publicJwk)),
      )

  fun defaultIdpStatementBody(): Map<String, Any?> =
      mapOf(
          "iss" to sekIdpIssuer,
          "sub" to sekIdpIssuer,
          "iat" to Time.currentTime(),
          "exp" to Time.currentTime() + STATEMENT_LIFETIME_SECONDS,
          "metadata" to
              mapOf(
                  "openid_provider" to
                      mapOf(
                          "pushed_authorization_request_endpoint" to parEndpoint,
                          "authorization_endpoint" to authorizationEndpoint,
                          "token_endpoint" to tokenEndpoint,
                          "signed_jwks_uri" to signedJwksUri,
                      )),
      )

  /** The SekIDP entity statement without the `openid_provider` [endpoint]. */
  fun idpStatementBodyWithout(endpoint: String): Map<String, Any?> {
    val statement = defaultIdpStatementBody().toMutableMap()
    val metadata = (statement["metadata"] as Map<*, *>).toMutableMap()
    metadata["openid_provider"] = (metadata["openid_provider"] as Map<*, *>).filterKeys { it != endpoint }
    statement["metadata"] = metadata
    return statement
  }

  fun defaultSignedJwksBody(): Map<String, Any?> =
      mapOf(
          "iss" to sekIdpIssuer,
          "iat" to Time.currentTime(),
          "exp" to Time.currentTime() + STATEMENT_LIFETIME_SECONDS,
          "keys" to listOf(protocolKey.publicJwk),
      )

  /** An ID token signed with the protocol key unless a test says otherwise. */
  fun idToken(
      key: FederationKey = protocolKey,
      alg: String = Algorithm.ES256,
      kid: String? = key.kid,
      claims: Map<String, Any?> = emptyMap(),
      extraHeaders: Map<String, Any> = emptyMap(),
  ): String = key.sign(defaultIdTokenBody() + claims, alg, kid, extraHeaders)

  fun defaultIdTokenBody(): Map<String, Any?> =
      mapOf(
          "iss" to sekIdpIssuer,
          "sub" to "mock-subject",
          "aud" to "zeta-guard",
          "iat" to Time.currentTime(),
          "exp" to Time.currentTime() + STATEMENT_LIFETIME_SECONDS,
      )

  override fun close() = server.stop()
}
