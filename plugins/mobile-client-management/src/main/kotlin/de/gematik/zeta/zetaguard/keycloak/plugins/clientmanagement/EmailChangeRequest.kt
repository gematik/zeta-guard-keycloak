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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

/**
 * JSON body of `POST /zeta/identity/email` (EmailChangeRequest in [zeta-guard-client-management]).
 *
 * Authorization does NOT travel in this body — it is the `Client-Assertion` header (instance key F2, A_30101),
 * which at the same time is the surviving factor of A_29911; there are deliberately no `pop`/`old_email_proof`
 * members. `idp_step_up` is accepted but not yet evaluated, so clients can already send the full wire format.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
class EmailChangeRequest {
  @JsonProperty("new_email") //
  var newEmail: String? = null

  /** RFC 9470 step-up proof (DPoP-bound access token issued by this guard). Not yet evaluated A_29911. */
  @JsonProperty("idp_step_up") //
  var idpStepUp: String? = null
}
