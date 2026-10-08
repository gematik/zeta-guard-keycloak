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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import jakarta.ws.rs.core.Response

/** RFC 9457 Problem Details media type, required by the client-management API ([zeta-guard-client-management], Error schema). */
const val MEDIA_TYPE_PROBLEM_JSON = "application/problem+json"

/**
 * Machine-readable failure codes carried in the `code` member of a problem response.
 *
 * Taken from the `Error` schema of [zeta-guard-client-management]. [INVALID_REQUEST] is not part of that enum (which has no
 * generic validation code yet) — flagged for feedback to the spec.
 */
object ProblemCodes {
  const val INVALID_REQUEST = "invalidRequest"
  const val INVALID_BINDING = "invalidBinding"
  const val INVALID_SIGNATURE = "invalidSignature"
  const val WRONG_AUDIENCE = "wrongAudience"
  const val STALE_REQUEST = "staleRequest"
  const val POP_REQUIRED = "popRequired"
  const val FACTOR_REQUIRED = "factorRequired"
  const val STEP_UP_REQUIRED = "stepUpRequired"
  const val EMAIL_MISMATCH = "emailMismatch"
  const val FORBIDDEN_TARGET = "forbiddenTarget"
  const val TOO_MANY_ATTEMPTS = "tooManyAttempts"
}

/**
 * Builds an RFC 9457 `application/problem+json` response. The `type` member is omitted and thus defaults to `about:blank`;
 * [code] carries the machine-readable reason per the Error schema of [zeta-guard-client-management].
 */
fun problem(status: Response.Status, code: String, title: String, detail: String? = null): Response =
    Response.status(status)
        .type(MEDIA_TYPE_PROBLEM_JSON)
        .entity(
            buildMap {
              put("status", status.statusCode)
              put("code", code)
              put("title", title)
              detail?.let { put("detail", it) }
            }
        )
        .build()
