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

sealed interface SekIdpFederationError {
  val what: String
  val message: String
  val exception: Throwable?
    get() = null

  /** The document could not be fetched at all. */
  data class Unreachable(override val what: String, override val exception: Throwable) : SekIdpFederationError {
    override val message: String
      get() = "$what could not be fetched: ${exception.message}"
  }

  /** The response is not a compact JWS. */
  data class MalformedJws(override val what: String, override val exception: Throwable) : SekIdpFederationError {
    override val message: String
      get() = "$what is not a JWS"
  }

  /** The JWS header names no `kid` to look the signing key up by. */
  data class MissingKid(override val what: String) : SekIdpFederationError {
    override val message: String
      get() = "$what has no »kid« in its JWS header"
  }

  /**
   * The `kid` is not among the keys trusted for the document.
   *
   * Told apart from the other rejections so [VouchedSekIDP.verifyIdToken] can distinguish a rotated key from a broken
   * signature — A_22861 asks for a reload only in the first case.
   */
  data class UnknownKid(override val what: String, val kid: String) : SekIdpFederationError {
    override val message: String
      get() = "$what is signed with unknown kid »$kid«"
  }

  /** A_23034-02: only ES256 is accepted. */
  data class UnsupportedAlgorithm(override val what: String, val algorithm: String) : SekIdpFederationError {
    override val message: String
      get() = "$what is signed with: $algorithm — only ES256 is supported (A_23034-02)"
  }

  /** A_23196: only EC P-256 keys are accepted. */
  data class UnsupportedKey(override val what: String, val kid: String, val keyType: String?, val curve: String?) : SekIdpFederationError {
    override val message: String
      get() = "$what: key »$kid« is not an EC/P-256 key (kty=$keyType, crv=$curve) — A_23196"
  }

  /** The signature does not verify; broken signature bytes are reported the same way. */
  data class InvalidSignature(override val what: String, override val exception: Throwable? = null) : SekIdpFederationError {
    override val message: String
      get() = "$what has an invalid signature"
  }

  /** A_28848: a trust-chain document is not trusted past its `exp`. */
  data class Expired(override val what: String, val expiredAt: Long) : SekIdpFederationError {
    override val message: String
      get() = "$what expired at $expiredAt"
  }

  /** The document lacks a claim the chain needs, given as its JSON path. */
  data class MissingClaim(override val what: String, val path: String) : SekIdpFederationError {
    override val message: String
      get() = "$what has no $path"
  }

  /** The document's `jwks` cannot be read as a JWK set. */
  data class MalformedJwks(override val what: String, override val exception: Throwable) : SekIdpFederationError {
    override val message: String
      get() = "$what carries an unreadable jwks: ${exception.message}"
  }

  /** The document carries no key with a `kid`, so nothing could ever be verified against it. */
  data class NoKeys(override val what: String) : SekIdpFederationError {
    override val message: String
      get() = "$what carries no keys"
  }

  /** A_27802-03: the JWS header contains an unsupported parameter (e.g. crit, cty). */
  data class UnsupportedHeader(override val what: String, val parameter: String) : SekIdpFederationError {
    override val message: String
      get() = "$what contains unsupported header parameter »$parameter«"
  }

  /** The document is issued by or for another issuer than the one the chain leads to. */
  data class IssuerMismatch(override val what: String, val expected: String, val actual: String?) : SekIdpFederationError {
    override val message: String
      get() = "$what is issued by »$actual«, not »$expected«"
  }
}

/** The one place a chain failure becomes what Keycloak's broker API expects. */
fun SekIdpFederationError.toIdentityBrokerException(): IdentityBrokerException =
    exception?.let { IdentityBrokerException(message, it) } ?: IdentityBrokerException(message)
