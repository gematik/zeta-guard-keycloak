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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.recover
import com.fasterxml.jackson.databind.JsonNode
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_MTLS_HTTP_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.lookupHttpClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import org.jboss.logging.Logger
import org.keycloak.OID4VCConstants.CLAIM_NAME_EXP
import org.keycloak.OID4VCConstants.CLAIM_NAME_ISSUER
import org.keycloak.OID4VCConstants.CLAIM_NAME_SUB
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyType
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jws.JWSInput
import org.keycloak.models.KeycloakSession
import org.keycloak.util.JsonSerialization

private val logger: Logger = Logger.getLogger(Federation::class.java)

/**
 * Cap for the cached statements so a long-lived one cannot pin stale endpoints or keys.
 *
 * A_28848 requires the entity statement to be fetched again within 24 h (12 h recommended); this cap is our own, far
 * stricter bound on top of that.
 */
private const val MAX_CACHE_SECONDS = 300

/** SekIDP endpoints taken from the IDP's entity statement, verified against the keys the Federation Master vouches for. */
data class SekIDPEndpoints(
    val pushedAuthorizationRequestEndpoint: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val signedJwksUri: String,
)

/**
 * The federation as seen from here: the only way to reach a sectoral IDP.
 *
 * A_29660, A_28848. [sekIdp] returns only after the Federation Master has vouched for the issuer — nothing is fetched
 * from the IDP's own address before that.
 */
class Federation(private val session: KeycloakSession, private val fedmasterUrl: String) {
  /** A_29660: the sectoral IDP behind [sekIdpIssuer]; a [SekIdpFederationError] unless the Federation Master vouches for it. */
  fun sekIdp(sekIdpIssuer: String): Either<SekIdpFederationError, VouchedSekIDP> = either {
    val trustedIdpKeys = trustedIdpKeys(sekIdpIssuer).bind()

    VouchedSekIDP(session, sekIdpIssuer, trustedIdpKeys)
  }

  private fun fedmasterEntityStatement(): Either<SekIdpFederationError, JsonNode> = either {
    fedmasterEntityStatementCache[fedmasterUrl]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return@either it.value
    }

    // Double-checked: one thread fetches, everyone else waits — concurrent expiry must not stampede the Federation Master.
    synchronized(fedmasterEntityStatementCache) {
      fedmasterEntityStatementCache[fedmasterUrl]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return@either it.value
      }

      val what = "Federation Master entity statement of »$fedmasterUrl«"
      val statement =
          Either.catch { SimpleHttp.create(session.lookupHttpClient(SEKIDP_MTLS_HTTP_CLIENT_ID)).doGet("$fedmasterUrl/.well-known/openid-federation").asString() }
              .mapLeft { SekIdpFederationError.Unreachable(what, it) }
              .bind()
      val input = Either.catch { JWSInput(statement) }.mapLeft { SekIdpFederationError.MalformedJws(what, it) }.bind()
      ensure(!input.header.otherClaims.containsKey("crit")) { SekIdpFederationError.UnsupportedHeader(what, "crit") }
      ensure(input.header.contentType == null) { SekIdpFederationError.UnsupportedHeader(what, "cty") }
      val body =
          Either.catch { input.readJsonContent(JsonNode::class.java) }
              .mapLeft { SekIdpFederationError.MalformedJws(what, it) }.bind()

      rejectExpired(body, what).bind()

      fedmasterEntityStatementCache[fedmasterUrl] = Cached(body, cacheUntil(body))
      body
    }
  }

  /** The federation key(s) the Federation Master signs off for one sectoral IDP. */
  private fun trustedIdpKeys(sekIdpIssuer: String): Either<SekIdpFederationError, Map<String, JWK>> = either {
    trustedIdpKeyCache[sekIdpIssuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return@either it.value
    }

    synchronized(trustedIdpKeyCache) {
      trustedIdpKeyCache[sekIdpIssuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return@either it.value
      }

      val fedmasterWhat = "Federation Master entity statement of »$fedmasterUrl«"
      val fedmaster = fedmasterEntityStatement().bind()
      val fedmasterIssuer =
          fedmaster.path(CLAIM_NAME_ISSUER).takeIf { it.isTextual }?.asText()
            ?: raise(SekIdpFederationError.MissingClaim(fedmasterWhat, CLAIM_NAME_ISSUER))

      // The Federation Master publishes its fetch endpoint as an absolute URL and it is used exactly as published.
      val fetchEndpoint =
          fedmaster
              .path("metadata")
              .path("federation_entity")
              .path("federation_fetch_endpoint")
              .takeIf { it.isTextual }
              ?.asText()
            ?: raise(SekIdpFederationError.MissingClaim(fedmasterWhat, "metadata.federation_entity.federation_fetch_endpoint"))
      val fedmasterKeys = parseJwks(fedmaster.path("jwks"), fedmasterWhat).bind()

      ensure(fedmasterKeys.isNotEmpty()) { SekIdpFederationError.NoKeys(fedmasterWhat) }

      val what = "Federation Master's statement about »$sekIdpIssuer«"
      val statement =
          Either.catch {
                SimpleHttp.create(session.lookupHttpClient(SEKIDP_MTLS_HTTP_CLIENT_ID))
                    .doGet(fetchEndpoint)
                    .param("iss", fedmasterIssuer)
                    .param(CLAIM_NAME_SUB, sekIdpIssuer)
                    .asString()
              }
              .mapLeft { SekIdpFederationError.Unreachable(what, it) }
              .bind()
      val body = verifyAndDecode(statement, fedmasterKeys, what).bind()

      rejectExpired(body, what).bind()

      val keysByKid = parseJwks(body.path("jwks"), what).bind()
      ensure(keysByKid.isNotEmpty()) { SekIdpFederationError.NoKeys(what) }

      trustedIdpKeyCache[sekIdpIssuer] = Cached(keysByKid, cacheUntil(body))
      logger.infof("Federation Master vouches for »%s« with key(s): %s", sekIdpIssuer, keysByKid.keys)

      keysByKid
    }
  }
}

/**
 * A sectoral IDP the Federation Master has vouched for — holding one is the proof that it did.
 *
 * A_28848, A_22861. [vouchedKeys] is what the Federation Master signed off: the IDP's *federation* key. That key signs
 * both the entity statement behind [resolveEndpoints] and the JWK set at `signed_jwks_uri`, and only the latter carries
 * the keys used for the OIDC protocol itself ([verifyIdToken]). Keeping those two apart is the substance of the chain.
 */
class VouchedSekIDP(
    private val session: KeycloakSession,
    val issuer: String,
    private val vouchedKeys: Map<String, JWK>,
) {

  /** A_29660: PAR and authorization endpoints, taken from an entity statement signed by a vouched key. */
  fun resolveEndpoints(): Either<SekIdpFederationError, SekIDPEndpoints> = either {
    endpointCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return@either it.value
    }

    synchronized(endpointCache) {
      endpointCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return@either it.value
      }

      val what = "SekIDP entity statement of »$issuer«"
      val statement =
          Either.catch { SimpleHttp.create(session.lookupHttpClient(SEKIDP_MTLS_HTTP_CLIENT_ID))
              .doGet("$issuer/.well-known/openid-federation").asString() }
              .mapLeft { SekIdpFederationError.Unreachable(what, it) }
              .bind()
      val body = verifyAndDecode(statement, vouchedKeys, what).bind()

      rejectExpired(body, what).bind()

      val openidProvider = body.path("metadata").path("openid_provider")

      fun endpoint(name: String): String =
          openidProvider.path(name).takeIf { it.isTextual }?.asText()
            ?: raise(SekIdpFederationError.MissingClaim(what, "metadata.openid_provider.$name"))

      val endpoints =
          SekIDPEndpoints(
              pushedAuthorizationRequestEndpoint = endpoint("pushed_authorization_request_endpoint"),
              authorizationEndpoint = endpoint("authorization_endpoint"),
              tokenEndpoint = endpoint("token_endpoint"),
              signedJwksUri = endpoint("signed_jwks_uri"),
          )
      endpointCache[issuer] = Cached(endpoints, cacheUntil(body))
      logger.infof(
          "SekIDP endpoint discovery for »%s«: PAR=%s (trust chain verified)", issuer, endpoints.pushedAuthorizationRequestEndpoint
      )

      endpoints
    }
  }

  /**
   * A_29672, A_22861: verifies an ID token against this IDP's protocol keys.
   *
   * A kid this IDP has not published yet means it may have rotated its keys, so A_22861 asks for its entity statement
   * and signed JWK set to be fetched again before the token is rejected.
   *
   */
  fun verifyIdToken(jws: String): Either<SekIdpFederationError, JsonNode> = either {
    val what = "SekIDP token of »$issuer«"
    // Resolved outside the recover: only an unknown kid in the token itself is A_22861's case, not one in the documents.
    val knownKeys = idTokenSigningKeys().bind()
    val token = verifyAndDecode(jws, knownKeys, what).recover {
      when (it) {
        is SekIdpFederationError.UnknownKid -> {
          forgetSekIdpDocuments(issuer)
          verifyAndDecode(jws, idTokenSigningKeys().bind(), what).bind()
        }
        else -> raise(it)
      }
    }.bind()

    val tokenIssuer = token.path("iss").takeIf { it.isTextual }?.asText()?.trimEnd('/')

    ensure(tokenIssuer == issuer) { SekIdpFederationError.IssuerMismatch(what, expected = issuer, actual = tokenIssuer) }

    token
  }

  /**
   * The keys this IDP signs its ID tokens with.
   *
   * A_22861: resolved from the entity statement and the keys behind its `signed_jwks_uri`.
   */
  private fun idTokenSigningKeys(): Either<SekIdpFederationError, Map<String, JWK>> = either {
    idTokenSigningKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return@either it.value
    }

    synchronized(idTokenSigningKeyCache) {
      idTokenSigningKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return@either it.value
      }

      val what = "SekIDP signed JWK set of »$issuer«"
      val signedJwksUri = resolveEndpoints().bind().signedJwksUri
      val signedJwks =
          Either.catch { SimpleHttp.create(session.lookupHttpClient(SEKIDP_MTLS_HTTP_CLIENT_ID)).doGet(signedJwksUri).asString() }
              .mapLeft { SekIdpFederationError.Unreachable(what, it) }
              .bind()
      val body = verifyAndDecode(signedJwks, vouchedKeys, what).bind()

      rejectExpired(body, what).bind()

      // The entity statement names the URL; the document itself has to say whose keys these are.
      val declaredIssuer = body.path("iss").takeIf { it.isTextual }?.asText()?.trimEnd('/')
      ensure(declaredIssuer == issuer) { SekIdpFederationError.IssuerMismatch(what, expected = issuer, actual = declaredIssuer) }

      val keysByKid = parseJwks(body, what).bind()
      ensure(keysByKid.isNotEmpty()) { SekIdpFederationError.NoKeys(what) }
      idTokenSigningKeyCache[issuer] = Cached(keysByKid, cacheUntil(body))
      logger.infof("SekIDP »%s« signs ID tokens with key(s): %s", issuer, keysByKid.keys)

      keysByKid
    }
  }
}

/** One cached value, trusted until [validUntil] and fetched again after that. */
private class Cached<T>(val value: T, val validUntil: Int)

// The caches are shared by every request: Keycloak builds a new provider — and with it a new Federation — per request,
// so an instance cache would be empty every time. File-private keeps them reachable from both classes above.

/** Keyed by Federation Master URL: only one is configured today, but the cache must not survive a change of it. */
private val fedmasterEntityStatementCache = ConcurrentHashMap<String, Cached<JsonNode>>()

/** The key(s) the Federation Master vouches for one sectoral IDP, keyed by SekIDP issuer. */
private val trustedIdpKeyCache = ConcurrentHashMap<String, Cached<Map<String, JWK>>>()

/** Keyed by SekIDP issuer — several entries ARE expected once more SekIDPs are configured. */
private val endpointCache = ConcurrentHashMap<String, Cached<SekIDPEndpoints>>()

/** The ID-token signing key(s) from one sectoral IDP's `signed_jwks_uri`, keyed by SekIDP issuer. */
private val idTokenSigningKeyCache = ConcurrentHashMap<String, Cached<Map<String, JWK>>>()

/**
 * A_22861: drops what came out of one SekIDP's own documents, so both are fetched again.
 *
 * The Federation Master's vouch stays. It is the trust anchor the reload is verified against, and a token nobody can
 * verify is no reason to give it up.
 */
private fun forgetSekIdpDocuments(issuer: String) {
  endpointCache.remove(issuer)
  idTokenSigningKeyCache.remove(issuer)
}

/**
 * How long a document may be cached: its own `exp`, capped by [MAX_CACHE_SECONDS].
 *
 * A signed JWK set carries no `exp` — only `iss`, `iat` and `keys` — so a missing one means "no bound of its own" and
 * the cap alone applies. Read as zero it would expire the keys the moment they arrive, and every token check would
 * fetch them again.
 */
private fun cacheUntil(body: JsonNode): Int {
  val cap = Time.currentTime() + MAX_CACHE_SECONDS
  val exp = body.path("exp").takeIf { it.isNumber } ?: return cap

  return minOf(exp.asLong(), cap.toLong()).toInt()
}

/**
 * Turns a JWKS JSON node (`{"keys": [...]}`) into a lookup map by `kid`, skipping keys without one.
 *
 * A missing or null node reads as an empty map; a malformed one is [SekIdpFederationError.MalformedJwks].
 */
private fun parseJwks(json: JsonNode, what: String): Either<SekIdpFederationError, Map<String, JWK>> =
    Either.catch {
      val jwks = JsonSerialization.mapper.treeToValue(json, JSONWebKeySet::class.java)

      jwks.keys
          .orEmpty()
          .mapNotNull { jwk -> jwk.keyId?.let { it to jwk } }
          .toMap()
    }.mapLeft { SekIdpFederationError.MalformedJwks(what, it) }

private fun verifyAndDecode(jws: String, trustedKeys: Map<String, JWK>, what: String): Either<SekIdpFederationError, JsonNode> = either {
  val input = Either.catch { JWSInput(jws) }.mapLeft { SekIdpFederationError.MalformedJws(what, it) }.bind()
  val kid = input.header.keyId ?: raise(SekIdpFederationError.MissingKid(what))
  val jwk = trustedKeys[kid] ?: raise(SekIdpFederationError.UnknownKid(what, kid))
  val algorithm = input.header.rawAlgorithm

  // A_27802-03: reject JWS with unsupported crit extensions (RFC 7515 §5.2 step 5)
  ensure(!input.header.otherClaims.containsKey("crit")) { SekIdpFederationError.UnsupportedHeader(what, "crit") }
  // A_27802-03: no contentType is currently supported — reject any cty value (RFC 7519 §7.2 step 8)
  ensure(input.header.contentType == null) { SekIdpFederationError.UnsupportedHeader(what, "cty") }

  // A_23034-02 fixes ES256 as the entity statement's JWS algorithm.
  ensure(algorithm == Algorithm.ES256) { SekIdpFederationError.UnsupportedAlgorithm(what, algorithm) }
  val curve = jwk.otherClaims["crv"] as? String

  // A_23196 allows EC P-256 only — an issuer-side rule we mirror when verifying.
  ensure(jwk.keyType == KeyType.EC && curve == "P-256") { SekIdpFederationError.UnsupportedKey(what, kid, jwk.keyType, curve) }

  // Verify the signature with Keycloak's verifier context; broken signature bytes are rejected like a wrong signature.
  val publicKey = jwk.toPublicKey()
  val signedContent = input.encodedSignatureInput.toByteArray(StandardCharsets.UTF_8)

  val validSignature = Either.catch {
    publicKey.createVerifierContext().verify(signedContent, input.signature)
  }.mapLeft { SekIdpFederationError.InvalidSignature(what, it) }.bind()

  ensure(validSignature) { SekIdpFederationError.InvalidSignature(what) }

  JsonSerialization.mapper.readTree(input.content)
}

/**
 * A trust-chain document must not be trusted past its `exp`, even with a valid signature — called for every document
 * of the chain right after it is decoded.
 *
 * ID tokens are NOT checked here: their `exp` is checked by Keycloak's `validateToken`, which honors the configured
 * `allowedClockSkew`.
 */
private fun rejectExpired(body: JsonNode, what: String): Either<SekIdpFederationError, Unit> = either {
  val exp = body.path(CLAIM_NAME_EXP)

  if (exp.isNumber && exp.asLong() <= Time.currentTime()) {
    raise(SekIdpFederationError.Expired(what, exp.asLong()))
  }
}
