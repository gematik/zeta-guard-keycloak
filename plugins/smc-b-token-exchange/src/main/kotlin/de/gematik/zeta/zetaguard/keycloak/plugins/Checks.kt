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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import de.gematik.zeta.zetaguard.keycloak.client_attestation.deserializeQuote
import de.gematik.zeta.zetaguard.keycloak.client_attestation.validateQuoteSignature
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.KeycloakValidationError
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.ZetaGuardTokenExchangeContext

private const val ATTESTATION_CHALLENGE_DOES_NOT_MATCH = "Attestation challenge does not match"

internal fun checkSoftwarePosture(context: ZetaGuardTokenExchangeContext, posture: SoftwarePosture): Either<KeycloakValidationError, Unit> = either {
  val postureKey = posture.publicKey.toPublicKey().mapLeft { invalidClientAttestation(it) }.bind()
  val clientKey = context.clientJWK.toPublicKey()
  val expectedAttestationChallenge = context.attestationChallenge.fromBase64()
  val attestationChallenge = posture.attestationChallenge.fromBase64()

  ensure(clientKey == postureKey) { invalidClientAttestation("Public keys from posture and client do not match") }
  ensure(expectedAttestationChallenge.contentEquals(attestationChallenge)) { invalidClientAttestation(ATTESTATION_CHALLENGE_DOES_NOT_MATCH) }
}

internal fun checkTPMPosture(
    context: ZetaGuardTokenExchangeContext,
    keystoreService: KeystoreService,
    posture: TPMPosture,
): Either<KeycloakValidationError, Unit> = either {
  val tpmQuoteBytes = posture.tpmQuote.fromBase64()
  val tpmQuote = tpmQuoteBytes.deserializeQuote().mapLeft { invalidTPMQuote(it) }.bind()
  val tpmPublicKey = posture.tpmAttestationKey.toPublicKey().mapLeft { invalidClientAttestation(it) }.bind()
  val quoteSignature = posture.tpmQuoteSignature.fromBase64()
  val certificateChain = posture.tpmEkCertificateChain.map { it.toCertificate() }
  val expectedAttestationChallenge = context.attestationChallenge.fromBase64()

  ensure(certificateChain.isNotEmpty()) { invalidClientAttestation("TPM certificate chain is empty") }

  // TODO: missing attribute attestationChain in specification
  // https://ey-fp-dev.atlassian.net/browse/ZETAP-905
  //  ensure(certificateChain[0].publicKey == tpmPublicKey) { invalidClientAttestation("Public keys from attestation and certificate do not match") }
  ensure(expectedAttestationChallenge.contentEquals(tpmQuote.extraData)) { invalidClientAttestation(ATTESTATION_CHALLENGE_DOES_NOT_MATCH) }

  tpmQuoteBytes.validateQuoteSignature(quoteSignature, tpmPublicKey).mapLeft { invalidTPMQuote(it) }.bind()
  validateCertificateChain(keystoreService, certificateChain).mapLeft { invalidTpmCertificate(it) }.bind()
}

internal fun checkPostureTypeMatchesPlatform(clientStatementData: ClientStatementData): Either<KeycloakValidationError, Unit> = either {
  if (clientStatementData.postureType in listOf(PostureType.SOFTWARE, PostureType.TPM)) {
    val platform = clientStatementData.posture.platformProductId?.productPlatform ?: Platform.LINUX // default to LINUX if not provided

    ensure(platform in listOf(Platform.WINDOWS, Platform.LINUX)) {
      invalidClientClaim("Invalid combination of »${clientStatementData.postureType}« and »${platform}«")
    }
  }
}

internal fun checkPostureType(clientStatementData: ClientStatementData, context: ZetaGuardTokenExchangeContext, tpmKeystoreService: KeystoreService) =
    either {
      when (clientStatementData.postureType) {
        PostureType.SOFTWARE -> checkSoftwarePosture(context, clientStatementData.posture as SoftwarePosture).bind()
        PostureType.TPM -> checkTPMPosture(context, tpmKeystoreService, clientStatementData.posture as TPMPosture).bind()
        else -> raise(invalidClientAttestation("Client attestation check not implemented for »${clientStatementData.postureType}« posture type"))
      }
    }
