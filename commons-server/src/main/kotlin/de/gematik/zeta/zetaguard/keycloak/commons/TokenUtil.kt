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
package de.gematik.zeta.zetaguard.keycloak.commons

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import org.keycloak.TokenVerifier
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.representations.AccessToken
import org.keycloak.representations.IDToken
import org.keycloak.representations.JsonWebToken
import org.keycloak.representations.RefreshToken

data class IDTokenInfo(val token: IDToken, val header: JWSHeader)

fun String.toAccessToken(): AccessToken = TokenVerifier.create(this, AccessToken::class.java).token

fun String.toRefreshToken(): RefreshToken = TokenVerifier.create(this, RefreshToken::class.java).token

fun String.toIDTokenInfo(verifer: SignatureVerifierContext? = null): IDTokenInfo {
  val tokenVerifier =
      TokenVerifier.create(this, IDToken::class.java).also {
        if (verifer != null) {
          it.verifierContext(verifer).verify()
        }
      }

  return IDTokenInfo(tokenVerifier.token, tokenVerifier.header)
}

// https://stackoverflow.com/questions/39926104/what-format-is-the-exp-expiration-time-claim-in-a-jwt
// exp is Time in SECONDS since "Epoch"
fun JsonWebToken.expirationDate(): LocalDateTime = (exp * 1000).toLocalDateTime()

fun JsonWebToken.issuedAt(): LocalDateTime = (iat * 1000).toLocalDateTime()

fun Long.toLocalDateTime(): LocalDateTime = Instant.ofEpochMilli(this).atZone(ZoneId.systemDefault()).toLocalDateTime()

fun now(): LocalDateTime = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS)
