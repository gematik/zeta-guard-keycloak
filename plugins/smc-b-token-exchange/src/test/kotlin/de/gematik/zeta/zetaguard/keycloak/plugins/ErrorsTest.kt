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
package de.gematik.zeta.zetaguard.keycloak.plugins

import de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning.HsmUnavailableException
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import jakarta.ws.rs.core.Response.Status.SERVICE_UNAVAILABLE
import java.security.SignatureException
import org.keycloak.OAuthErrorException.TEMPORARILY_UNAVAILABLE

class ErrorsTest :
    StringSpec({
      "tokenSigningUnavailable yields 503 + temporarily_unavailable + generic message" {
        val err = tokenSigningUnavailable(SignatureException("HSM down — should not leak to client"))
        err.error shouldBe TEMPORARILY_UNAVAILABLE
        err.errorDescription shouldBe "Token signing temporarily unavailable"
        err.statusCode shouldBe SERVICE_UNAVAILABLE.statusCode
      }

      "invalidClientClaim yields 400, not 403, per gemSpec_ZETA_V1.3.2's malformed-assertion requirement" {
        invalidClientClaim("Claim »client_statement« not found").statusCode shouldBe BAD_REQUEST.statusCode
      }

      "hasSigningFailureCause detects SignatureException directly" { hasSigningFailureCause(SignatureException("boom")) shouldBe true }

      "hasSigningFailureCause walks wrapped cause chain (mid-flight wrap)" {
        val wrapped = RuntimeException("org.keycloak.crypto.SignatureException: Signing failed", SignatureException("HSM Proxy signing failed"))
        hasSigningFailureCause(wrapped) shouldBe true
      }

      "hasSigningFailureCause detects HsmUnavailableException by FQCN (cold-start path)" {
        // Test fixture lives at the *production* FQCN on the test classpath only. The smc-b-token-exchange module does
        // NOT depend on hsm-token-signing in Maven — production code matches by literal FQCN string. This test pins the
        // wire contract: a Throwable whose class name matches the production FQCN is treated as a signing failure.
        hasSigningFailureCause(HsmUnavailableException("HSM unreachable")) shouldBe true
      }

      "HSM_UNAVAILABLE_FQCN string contract — production class must live at this exact path" {
        // If you ever rename / move the production class, three things must change in lockstep:
        //   1. plugins/smc-b-token-exchange/.../Errors.kt              — the HSM_UNAVAILABLE_FQCN constant
        //   2. plugins/hsm-token-signing/.../HsmUnavailableException   — the production class
        //   3. this test                                                — the expected FQCN below
        HSM_UNAVAILABLE_FQCN shouldBe "de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning.HsmUnavailableException"
      }

      "hasSigningFailureCause returns false for unrelated errors" {
        hasSigningFailureCause(IllegalStateException("nothing to do with signing")) shouldBe false
      }

      "hasSigningFailureCause stops at 10-deep cause chain (no infinite loop on cycles)" {
        // Build a chain of 12 wrapped RuntimeExceptions ending in a SignatureException at depth 12 — should NOT be detected.
        val deep = (1..11).fold<Int, Throwable>(SignatureException("at depth 12")) { acc, _ -> RuntimeException("wrap", acc) }
        hasSigningFailureCause(deep) shouldBe false
      }
    })
