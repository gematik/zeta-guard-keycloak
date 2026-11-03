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

import org.keycloak.broker.provider.IdentityBrokerException
import org.keycloak.representations.IDToken

/**
 * Why mapping the SekIDP's verified ID token onto a local identity fails (A_29672).
 *
 * Distinct from [SekIdpFederationError]: the token's signature and issuer are already established by then — this is about the
 * claims its content is expected to carry, and about the session state without which no token can be attributed at all.
 */
sealed interface SekIdpIdentityError {
  val message: String

  /** The authentication session names no sectoral IDP, so there is no issuer to verify the token against. */
  data object MissingIdpIss : SekIdpIdentityError {
    override val message
      get() = "no idp_iss on the authentication session"
  }

  /** No `urn:telematik:claims:id` (KVNR) claim — was scope urn:telematik:versicherter requested? */
  data object MissingKvnr : SekIdpIdentityError {
    override val message
      get() = "SekIDP ID token contains no urn:telematik:claims:id claim — was scope urn:telematik:versicherter requested?"
  }

  /** No `urn:telematik:claims:display_name` claim — commonName has no source (A_26973-03). */
  data object MissingDisplayName : SekIdpIdentityError {
    override val message
      get() = "SekIDP ID token contains no urn:telematik:claims:display_name claim — was scope urn:telematik:display_name requested?"
  }

  /** No `${IDToken.ACR}` claim — the attested authentication level is unknown. */
  data object MissingAcr : SekIdpIdentityError {
    override val message
      get() = "SekIDP ID token contains no »${IDToken.ACR}« claim — the attested authentication level is unknown"
  }
}

/** The one place an identity-mapping failure becomes what Keycloak's broker API expects. */
fun SekIdpIdentityError.toIdentityBrokerException(): IdentityBrokerException = IdentityBrokerException(message)
