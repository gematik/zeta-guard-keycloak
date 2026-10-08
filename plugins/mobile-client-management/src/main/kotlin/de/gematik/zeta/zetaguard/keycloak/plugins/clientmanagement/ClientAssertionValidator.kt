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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import jakarta.ws.rs.core.Response
import java.net.URI
import org.jboss.logging.Logger
import org.keycloak.jose.jws.JWSInput
import org.keycloak.jose.jws.JWSInputException
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.representations.JsonWebToken

private val logger: Logger = Logger.getLogger(ClientAssertionValidator::class.java)

sealed interface ClientAssertionResult {
  data class Valid(val token: JsonWebToken) : ClientAssertionResult

  data class Invalid(val status: Response.Status, val code: String, val detail: String) : ClientAssertionResult
}

/** Everything a [ClientAssertionCheck] may look at: the parsed assertion plus the client it must belong to. */
class ClientAssertionContext(
    val session: KeycloakSession,
    val client: ClientModel,
    val assertion: String,
    val jws: JWSInput,
    val token: JsonWebToken,
)

/** Outcome of a single [ClientAssertionCheck]. */
sealed interface ClientAssertionCheckResult {
  data object Passed : ClientAssertionCheckResult

  data class Rejected(val status: Response.Status, val code: String, val detail: String) : ClientAssertionCheckResult
}

/**
 * One validation step of the client-assertion policy (strategy). Implementations are small, self-contained classes
 * (see ClientAssertionChecks.kt) returning [ClientAssertionCheckResult.Passed] or the
 * [ClientAssertionCheckResult.Rejected] that rejects the request.
 */
fun interface ClientAssertionCheck {
  fun check(context: ClientAssertionContext): ClientAssertionCheckResult
}

/**
 * Validates the per-request `private_key_jwt` client assertion of the client-management API (`Client-Assertion` HTTP
 * header, the compact JWS alone — no `client_assertion_type` parameter; [zeta-guard-client-management], A_30101).
 *
 * The validator itself only parses the assertion and runs the given [checks] in order, stopping at the first
 * rejection. WHAT is validated is the caller's choice: it assembles the check list — normally via [defaultChecks],
 * which yields the full policy of the spec's `clientAssertion` security scheme. Endpoint-specific expectations
 * (audience, `htm`/`htu`) are constructor arguments of the respective check classes, so the contract of each
 * endpoint is visible at the call site. The [session] is used solely for provider access by the checks
 * (key resolution, single-use `jti` cache).
 */
class ClientAssertionValidator(
    private val session: KeycloakSession,
    private val checks: List<ClientAssertionCheck>,
) {

  companion object {
    /**
     * Unverified `client_id` (`iss` = `sub`) of an assertion — ONLY a selector for resolving the [ClientModel]
     * (A_30101: the client_id is non-secret); trust is established solely by [validate].
     */
    fun unverifiedClientId(assertion: String): String? =
        runCatching { JWSInput(assertion).readJsonContent(JsonWebToken::class.java) }.getOrNull()
            ?.let { token -> token.subject?.takeIf { it.isNotBlank() && it == token.issuer } }

    /**
     * The full policy of the spec's `clientAssertion` security scheme, in checking order: `typ: JWT` (A_25338-01),
     * `iss` = `sub` = `client_id` of the addressed client, signature against the registered instance key (F2),
     * expected audience, `htm`/`htu` request binding (RFC 9449 §4.2) and activity incl. max lifetime and
     * single-use `jti`.
     */
    fun defaultChecks(expectedAudience: String, expectedHttpMethod: String, expectedTargetUri: URI): List<ClientAssertionCheck> =
        listOf(
            TypeHeaderCheck(),
            ClientBindingCheck(),
            SignatureCheck(),
            AudienceCheck(expectedAudience),
            RequestBindingCheck(expectedHttpMethod, expectedTargetUri),
            ActivityCheck(),
        )
  }

  /** Parses [assertion] and runs all [checks] against it and the given [client]; first rejection wins. */
  fun validate(assertion: String, client: ClientModel): ClientAssertionResult {
    val jws =
        try {
          JWSInput(assertion)
        } catch (e: JWSInputException) {
          return invalid("parse", rejected(ProblemCodes.INVALID_SIGNATURE, "Malformed client assertion"))
        }

    val token =
        try {
          jws.readJsonContent(JsonWebToken::class.java)
        } catch (_: JWSInputException) {
          return invalid("parse", rejected(ProblemCodes.INVALID_SIGNATURE, "Unreadable client assertion payload"))
        }

    val context = ClientAssertionContext(session, client, assertion, jws, token)
    checks.forEach { check ->
      when (val result = check.check(context)) {
        is ClientAssertionCheckResult.Rejected -> return invalid(check.javaClass.simpleName, result)
        is ClientAssertionCheckResult.Passed -> Unit
      }
    }

    return ClientAssertionResult.Valid(token)
  }

  private fun invalid(source: String, rejection: ClientAssertionCheckResult.Rejected): ClientAssertionResult.Invalid {
    logger.warnf("Client assertion rejected by %s (%s): %s", source, rejection.code, rejection.detail)
    return ClientAssertionResult.Invalid(rejection.status, rejection.code, rejection.detail)
  }
}

/** Shorthands for check implementations — client-assertion failures are `401` problems ([zeta-guard-client-management]). */
internal fun rejected(code: String, detail: String, status: Response.Status = Response.Status.UNAUTHORIZED): ClientAssertionCheckResult.Rejected =
    ClientAssertionCheckResult.Rejected(status, code, detail)

internal fun passed(): ClientAssertionCheckResult = ClientAssertionCheckResult.Passed
