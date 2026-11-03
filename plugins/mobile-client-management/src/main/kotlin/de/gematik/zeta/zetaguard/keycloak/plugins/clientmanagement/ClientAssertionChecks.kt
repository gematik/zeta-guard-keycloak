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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import arrow.core.Either
import arrow.core.left
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import java.net.URI
import org.keycloak.OAuth2Constants
import org.keycloak.TokenVerifier
import org.keycloak.authentication.authenticators.client.AbstractBaseJWTValidator
import org.keycloak.authentication.authenticators.client.ClientAssertionState
import org.keycloak.keys.loader.PublicKeyStorageManager
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper
import org.keycloak.representations.JsonWebToken

typealias ClientAssertionCheckResult = Either<ClientAssertionCheckRejected, ClientAssertionCheckPassed>

/**
 * The individual strategies of the client-assertion policy ([zeta-guard-client-management], A_30101). Each check is
 * one self-contained class; [ClientAssertionValidator.defaultChecks] assembles the full set in the canonical order.
 */

/** Validates the JWS protected header: `typ` must be `JWT`, and `crit`/`cty` must be absent (A_25338-01, A_27802-03). */
class ProtectedHeaderCheck : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult = either {
    ensure(context.jws.header.type == OAuth2Constants.JWT) {
      rejected(ProblemCodes.INVALID_SIGNATURE, "Client assertion »typ« header must be »JWT«")
    }
    ensure(!context.jws.header.otherClaims.containsKey("crit")) {
      rejected(ProblemCodes.INVALID_SIGNATURE, "Unsupported crit header parameter")
    }
    ensure(context.jws.header.contentType == null) {
      rejected(ProblemCodes.INVALID_SIGNATURE, "Unsupported cty header parameter")
    }
    ClientAssertionCheckPassed
  }
}

/** `iss` and `sub` MUST both carry the `client_id` (RFC 7523) — and it must be the client addressed by the caller. */
class ClientBindingCheck : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult = either {
    val clientId = context.token.subject

    ensure(!clientId.isNullOrBlank() && context.token.issuer == clientId) {
      rejected(ProblemCodes.INVALID_SIGNATURE, "»iss« and »sub« must both carry the client_id")
    }

    ensure(clientId == context.client.clientId) {
      rejected(ProblemCodes.INVALID_SIGNATURE, "Client assertion does not belong to the addressed client")
    }

    ClientAssertionCheckPassed
  }
}

/**
 * Signature MUST verify against the client's REGISTERED instance key (F2). Key resolution uses the same helper as
 * the token endpoint's JWTClientAuthenticator; if the client configures `token_endpoint_auth_signing_alg`, the
 * assertion's algorithm MUST match it.
 */
class SignatureCheck : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult = either {
    val expectedAlg = OIDCAdvancedConfigWrapper.fromClientModel(context.client).tokenEndpointAuthSigningAlg
    val algorithm = context.jws.header.algorithm?.name ?: raise(rejected(ProblemCodes.INVALID_SIGNATURE, "Missing signature algorithm"))

    if (expectedAlg != null && expectedAlg != algorithm) {
      raise(rejected(ProblemCodes.INVALID_SIGNATURE, "Signature algorithm does not match the client configuration"))
    }

    val keyWrapper =
        Either.catch { PublicKeyStorageManager.getClientPublicKeyWrapper(context.session, context.client, context.jws) }.getOrNull()
          ?: raise(rejected(ProblemCodes.INVALID_SIGNATURE, "No matching registered instance key (F2)"))

    // ECDSA JOSE signatures are raw R||S and need the ECDSA context; plain asymmetric covers RSA (cf. PKIUtil.createVerifierContext)
    val verifierContext = keyWrapper.createVerifierContext()

    Either.catch {
      TokenVerifier.create(context.assertion, JsonWebToken::class.java)
          .verifierContext(verifierContext).verify()
    }.mapLeft { rejected(ProblemCodes.INVALID_SIGNATURE, "Signature verification failed") }
        .map { ClientAssertionCheckPassed }
        .bind()
  }
}

/** `aud` MUST contain the expected audience — this guard's realm issuer URL. */
class AudienceCheck(private val expectedAudience: String) : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult =
      if (!context.token.hasAudience(expectedAudience)) {
        rejected(ProblemCodes.WRONG_AUDIENCE, "Client assertion audience does not match this guard").left()
      } else {
        ClientAssertionCheckPassed.right()
      }
}

/**
 * `htm`/`htu` MUST match the HTTP method and target URI of the current request (RFC 9449 §4.2 semantics; query and
 * fragment are ignored) — a leaked assertion cannot be replayed against a different method or endpoint even within
 * its lifetime.
 */
class RequestBindingCheck(private val expectedHttpMethod: String, private val expectedTargetUri: URI) : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult = either {
    if (!(context.token.otherClaims["htm"] as? String).equals(expectedHttpMethod, ignoreCase = true)) {
      raise(rejected(ProblemCodes.INVALID_BINDING, "»htm« does not match the HTTP method of this request"))
    }

    if (stripQueryAndFragment(context.token.otherClaims["htu"] as? String) != stripQueryAndFragment(expectedTargetUri.toString())) {
      raise(rejected(ProblemCodes.INVALID_BINDING, "»htu« does not match the target URI of this request"))
    }

    ClientAssertionCheckPassed
  }

  private fun stripQueryAndFragment(uri: String?): String? =
      uri?.let { Either.catch { URI(it).let { u -> URI(u.scheme, u.authority, u.path, null, null).toString() } }.getOrNull() }
}

/**
 * The assertion MUST be active (exp/iat sanity with clock skew), MUST NOT live longer than [maxLifetimeSeconds]
 * and its `jti` is single-use (replay cache shared with the token endpoint). Delegates to Keycloak's
 * flow-independent [AbstractBaseJWTValidator] — the same policy engine the token endpoint uses.
 */
class ActivityCheck(
    private val allowedClockSkewSeconds: Int = 15, // same tolerance as JWTClientValidator.getAllowedClockSkew
    private val maxLifetimeSeconds: Int = 60, // hard cap of the client-management API
) : ClientAssertionCheck {
  override fun check(context: ClientAssertionContext): ClientAssertionCheckResult {
    val state =
        ClientAssertionState(OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT, context.assertion, context.jws, context.token)
            .apply { client = context.client }
    var failureDetail = "Client assertion is not active"
    val keycloakChecks =
        object : AbstractBaseJWTValidator(context.session, state) {
          override fun failureCallback(errorDescription: String) {
            failureDetail = errorDescription
          }
        }

    // reusePermitted=false: enforces exp, iat sanity, the max lifetime AND jti single-use in one go
    return if (!keycloakChecks.validateTokenActive(allowedClockSkewSeconds, maxLifetimeSeconds, false)) {
      rejected(ProblemCodes.STALE_REQUEST, failureDetail).left()
    } else {
      ClientAssertionCheckPassed.right()
    }
  }
}
