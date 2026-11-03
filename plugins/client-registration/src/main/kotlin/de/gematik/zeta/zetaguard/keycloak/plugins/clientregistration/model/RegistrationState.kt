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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model

import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ClientRegistrationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus

/**
 * A_30086: get the registration status for OIDC responses, set in
 * [de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.oidc.ZetaGuardOIDCClientRegistrationProvider]
 *
 * Calculates the value from the current state of [ZetaGuardClientData] without db calls.
 *
 * [ClientRegistrationState.TOMBSTONE] is never returned: a tombstoned registration is removed rather than marked (A_29944 ff., not implemented).
 *
 * @return the registration's status, or `null` if it has none (attestation not valid).
 */
fun ZetaGuardClientData.registrationState(): ClientRegistrationState? =
    when (clientAuthMethod) {
      ClientAuthMethod.SMC_B ->
        when (attestationState) {
          // Attestation/F2 still outstanding — registered, not yet usable for resource access.
          ClientAttestationState.PENDING -> ClientRegistrationState.REGISTERED
          // Set by the token exchange once the policy decision came back »allow« (A_25762, A_29733).
          ClientAttestationState.VALID -> ClientRegistrationState.ACTIVE
          ClientAttestationState.INVALID -> null
        }

      ClientAuthMethod.SEK_IDP ->
        when (attestationState) {
          ClientAttestationState.VALID ->
            // bound needs all three factors: F2 (above), the verified e-mail F1, and the TI identity of A_29903.
            if (registrationStatus == ClientRegistrationStatus.CONFIRMED && userData != null) ClientRegistrationState.BOUND
            // A_29905: identity binding only — no scope or audience for resource access.
            else ClientRegistrationState.PENDING_USER_BINDING

          // Unreachable in practice: the registration policy attests mobile clients before it stores them. Fail closed regardless.
          ClientAttestationState.PENDING,
          ClientAttestationState.INVALID -> null
        }
    }
