/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.token

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.ProfessionOidValidator
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.ZetaGuardClientInstanceData
import de.gematik.zeta.zetaguard.keycloak.commons.secondsToLocalDateTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_PENDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_VALID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_ATTESTATION_STATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_ASSESSMENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_SELF_ASSESSMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SMCB_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstAdmission
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfession
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfessionInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientDisabled
import de.gematik.zeta.zetaguard.keycloak.plugins.exchangeError
import de.gematik.zeta.zetaguard.keycloak.plugins.internalError
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidCertificate
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidClientSelfAssessment
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidContext
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidGrantType
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidNonce
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidProviderModel
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidSubject
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidToken
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.missingClientState
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceProviderFactory
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import jakarta.ws.rs.core.MultivaluedMap
import jakarta.ws.rs.core.Response
import java.time.Duration
import java.time.LocalDateTime
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.keycloak.OAuth2Constants
import org.keycloak.OAuth2Constants.AUDIENCE
import org.keycloak.OAuth2Constants.JWT
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.TokenVerifier
import org.keycloak.TokenVerifier.IS_ACTIVE
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.ExchangeExternalToken
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.SignatureProvider
import org.keycloak.models.ClientModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.protocol.oidc.TokenManager.TokenRevocationCheck
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider
import org.keycloak.representations.AccessToken
import org.keycloak.representations.IDToken
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.managers.UserSessionManager
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resources.IdentityBrokerService.getIdentityProvider
import org.keycloak.util.TokenUtil
import org.keycloak.utils.EmailValidationUtil.isValidEmail

typealias KeycloakValidationError = KeycloakError

typealias KeycloakValidation = Either<KeycloakValidationError, ZetaGuardTokenExchangeContext>

private val REFERENCE_DATE = LocalDateTime.of(2025, 12, 1, 0, 0)!!

/**
 * External to internal token exchange provider for SMC-B created tokens.
 *
 * We try to use as much as possible from the standard V2 OIDC provider implementation.
 *
 * For details, see https://www.keycloak.org/securing-apps/token-exchange and
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5
 */
open class ZetaGuardTokenExchangeProvider(private val keystoreService: KeystoreService, private val opaConfig: OPAConfig) :
    StandardTokenExchangeProvider() {
  /**
   * Adapted from [StandardTokenExchangeProvider.tokenExchange]
   *
   * The supplied client assertion token has already been validated by [org.keycloak.authentication.authenticators.client.JWTClientValidator] at this
   * point.
   */
  override fun tokenExchange(): Response {
    // Override default, since it does not allow to influence refresh token creation
    tokenManager = ZetaGuardTokenManager()

    return verifyX5CCertificate(ZetaGuardTokenExchangeContext(this))
        .flatMap { checkGrantType(it) }
        .flatMap { verifyToken(it) }
        .flatMap { verifyCertificate(it) }
        .flatMap { checkNonce(it) }
        .flatMap { checkSubject(it) }
        .flatMap { opaGate(it) }
        .flatMap { handleClientData(it) }
        .flatMap { exchangeExternalToken(it) }
        .getOrElse { throw mapToCorsException(it) }
  }

  /**
   * We want to reuse as much as possible from the overridden method, as opposed to copying the code.
   *
   * Unfortunately, the last check is for token type [org.keycloak.OAuth2Constants.ACCESS_TOKEN_TYPE], whereas we want token type [JWT_TOKEN_TYPE].
   */
  override fun supports(context: TokenExchangeContext): Boolean {
    var ok = super.supports(context)

    // Undo the last check of the overridden method
    if (!ok && context.isNoAccessToken()) {
      context.unsupportedReason = null // reset error
      ok = true
    }

    val subjectTokenType = context.params.subjectTokenType

    // Either there is another error or the token type is "access token" → Let the standard implementation do the job
    return ok && JWT_TOKEN_TYPE == subjectTokenType
  }

  /**
   * We refer to the new standard implementation
   *
   * @see [org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.exchangeExternal]
   */
  override fun getVersion(): Int = 2

  /**
   * The overridden code is not feasible, because is does not just check audiences.
   *
   * It also disallows public clients, i.e. clients without a client secret. Since we use client_assertion, this not correct
   */
  override fun validateAudience(token: AccessToken?, disallowOnHolderOfTokenMismatch: Boolean, targetAudienceClients: List<ClientModel>) {
    val disabledTargetAudienceClient = targetAudienceClients.firstOrNull { !it.isEnabled }

    if (disabledTargetAudienceClient != null) {
      throw clientDisabled(disabledTargetAudienceClient)
    }
  }

  /**
   * Verify that the given certificate from the "x5c" header is signed by an issuer from the given trust store.
   *
   * The method finds the issuer certificate in the keystore, validates the signature of the leaf certificate and verifies the certificate chain.
   */
  private fun verifyCertificate(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val certificate = context.certificate
    val issuerCertificate = keystoreService.findIssuerCertificate(certificate)

    ensure(issuerCertificate != null) { invalidToken("Certificate issuer not found: ${certificate.issuerX500Principal}") }

    validateCertificateSignature(certificate, issuerCertificate.publicKey).onLeft { raise(invalidToken(it)) }

    validateCertificateChain(issuerCertificate, certificate).onLeft { raise(invalidToken(it)) }

    context
  }

  /**
   * Read and check data from client_assertion token.
   *
   * Store assembled data in user session context
   */
  private fun handleClientData(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val clientAssertionToken = context.clientAssertionToken.toJsonWebToken()
    val claims = clientAssertionToken.otherClaims ?: raise(invalidClientSelfAssessment("No claims found"))
    val clientSelfAssessment = claims.readSelfAssessment() ?: raise(invalidClientSelfAssessment("Claim »$CLAIM_CLIENT_SELF_ASSESSMENT« not found"))
    val clientInstanceData =
        Either.catch { clientSelfAssessment.toObject<ZetaGuardClientInstanceData>() }
            .mapLeft {
              logger.warn("Failed to read client self assessment", it)
              invalidClientSelfAssessment(it.message ?: "Failed to read")
            }
            .bind()

    val registrationTime = clientInstanceData.registrationTimestamp.secondsToLocalDateTime()
    ensure(registrationTime.isAfter(REFERENCE_DATE)) { invalidClientSelfAssessment("Invalid registration timestamp $registrationTime") }
    ensure(clientInstanceData.clientId == client.clientId) { invalidClientSelfAssessment("Invalid client id »${clientInstanceData.clientId}«") }
    ensure(isValidEmail(clientInstanceData.ownerMail)) { invalidClientSelfAssessment("Invalid Email address »${clientInstanceData.ownerMail}«") }

    context.clientInstanceData = clientInstanceData
    context
  }

  @Suppress("UNCHECKED_CAST") //
  private fun Map<String, Any>.readSelfAssessment() = this[CLAIM_CLIENT_SELF_ASSESSMENT] as Map<String, Any>?

  /**
   * Validates the given subject token, inspired by [AuthenticationManager.verifyIdentityToken].
   *
   * Additional checks check the issuer, algorithm, ...
   */
  private fun verifyToken(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val expectedAudiences = session.context.uri.baseUri.toString()
    val actualAudiences = context.subjectToken.toAccessToken().audience.toList()

    logger.debug("Audience check: Expecting »$expectedAudiences«, subject token contains: $actualAudiences ")

    val verifier =
        Either.catch {
              val verifier =
                  TokenVerifier.create(context.subjectToken, IDToken::class.java)
                      .withChecks(IS_ACTIVE)
                      .withChecks(TokenRevocationCheck(session))
                      .audience(expectedAudiences)
                      .tokenType(listOf(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP))
              val key = context.createKeyWrapper()
              val signatureProvider = session.getProvider(SignatureProvider::class.java, context.header.algorithm.name)
              val signatureVerifier = signatureProvider.verifier(key)

              verifier.verifierContext(signatureVerifier)
            }
            .mapLeft {
              logger.warn("Failed to create verifier", it)
              invalidToken(it.message ?: "Failed to create verifier")
            }
            .bind()

    ensure(verifier.header.algorithm.name == Algorithm.ES256) { invalidToken("Invalid algorithm: »${verifier.header.algorithm.name}«") }
    ensure(verifier.header.type == JWT) { invalidToken("Invalid token type: »${verifier.header.type}«") }

    val token =
        Either.catch { verifier.verify().getToken() }
            .mapLeft {
              logger.warn("Failed to verify identity token", it)
              invalidToken(it.message ?: "Token validation failed")
            }
            .bind()

    ensure(token.issuer == client.clientId) { invalidToken("Issuer does not match client id") }
    ensure(token.isActive(2) && token.iat >= realm.notBefore) { invalidToken("Identity token expired") }

    context.token = token

    context
  }

  private fun verifyX5CCertificate(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    ensure(context.header.x5c != null && context.header.x5c.isNotEmpty()) { invalidToken("Invalid x5c claim in token header") }

    val certificate =
        Either.catch {
              // leaf certificate is first in chain
              context.header.x5c[0].toCertificate()
            }
            .mapLeft { invalidToken(it.message ?: "Invalid certificate") }
            .bind()

    context.certificate = certificate

    val admissionSyntax = context.certificate.extractExtension<AdmissionSyntax>(admission) ?: raise(invalidCertificate("Invalid admission extension"))
    val admissions = admissionSyntax.firstAdmission() ?: raise(invalidCertificate("Invalid contents of admission extension"))
    val professionInfo = admissions.firstProfessionInfo() ?: raise(invalidCertificate("Invalid profession infos"))
    val professionIdentifier = professionInfo.firstProfession() ?: raise(invalidCertificate("Invalid profession OID"))
    val professionOID = professionIdentifier.id
    val telematikID = professionInfo.registrationNumber ?: raise(invalidCertificate("Invalid registration number"))

    ensure(ProfessionOidValidator.isValidProfessionOidFormat(professionOID)) { invalidCertificate("Invalid profession OID format") }
    ensure(ProfessionOidValidator.isValidProfessionOidSmcb(professionOID)) { invalidCertificate("Unknown SMCB profession OID") }

    // See https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26972
    context.apply {
      this.certificate = certificate
      this.telematikID = telematikID
      this.professionOID = professionOID
      this.subjectName = certificate.subjectCommonName()
      this.subjectOrganisation = certificate.subjectOrganisationName()
    }
  }

  private fun checkNonce(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val nonceFactory =
        Either.catch {
              val nonceProvider =
                  session.keycloakSessionFactory.getProviderFactory(RealmResourceProvider::class.java, NONCE_PROVIDER_ID) as NonceProviderFactory

              nonceProvider.nonceFactory
            }
            .mapLeft { internalError(it) }
            .bind()

    ensure(nonceFactory.retrieveNonce(context.token.nonce) != null) { invalidNonce() }

    context
  }

  private fun checkSubject(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    ensure(context.telematikID == context.token.subject) { invalidSubject(context.telematikID) }

    context
  }

  /** Check OPA */
  private fun opaGate(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    // If OPA check is disabled via configuration, skip gate
    if (!opaConfig.enabled) return@either context

    val httpClient = session.getProvider(HttpClientProvider::class.java)?.httpClient
    val grantType = formParams.getFirst(OAuth2Constants.GRANT_TYPE)
    val scopes = formParams.getFirst("scope")?.split(' ')?.filter { it.isNotBlank() } ?: emptyList()
    val audiences = resolveAudiences(formParams, context)
    val ipAddress = session.context.connection?.remoteAddr
    val professionOid = context.professionOID
    val input = OpaGateInput(grantType = grantType, scopes = scopes, audiences = audiences, ipAddress = ipAddress, professionOid = professionOid)

    when (val outcome = OpaGateEnforcer.enforce(httpClient, input, opaConfig, logger)) {
      is OpaGateEnforcer.Outcome.Skip -> {
        context.accessTokenTTLSeconds = Duration.ofSeconds(-1) // avoid lateinit error
        context.refreshTokenTTLSeconds = Duration.ofSeconds(-1)
        context
      }
      is OpaGateEnforcer.Outcome.Allow -> {
        context.accessTokenTTLSeconds = Duration.ofSeconds(outcome.accessTokenTtl?.toLong() ?: -1)
        context.refreshTokenTTLSeconds = Duration.ofSeconds(outcome.refreshTokenTtl?.toLong() ?: -1)
        context
      }

      is OpaGateEnforcer.Outcome.Deny -> raise(outcome.error)
      is OpaGateEnforcer.Outcome.Error -> raise(outcome.error)
    }
  }

  private fun resolveAudiences(formParams: MultivaluedMap<String, String>, context: ZetaGuardTokenExchangeContext): List<String>? {
    val audiencesRaw = formParams.getFirst(AUDIENCE)

    return if (!audiencesRaw.isNullOrBlank()) {
      audiencesRaw.split(',', ' ').map { it.trim() }.filter { it.isNotBlank() }.ifEmpty { null }
    } else {
      try {
        context.subjectToken.toAccessToken().audience?.toList()
      } catch (_: Exception) {
        null
      }
    }
  }

  /**
   * Check valid grant types.
   *
   * Only token exchange and refresh are supported. The latter is not allowed when the client is in state "pending_attestation"
   */
  private fun checkGrantType(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val grantType = context().formParams.getFirst(OIDCLoginProtocol.GRANT_TYPE_PARAM)

    ensure(VALID_GRANT_TYPES.contains(grantType)) { invalidGrantType() }

    val attestationState = context().client.getAttribute(ATTRIBUTE_ATTESTATION_STATE)

    when (attestationState) {
      null -> raise(missingClientState())
      ATTESTATION_STATE_PENDING -> ensure(grantType == TOKEN_EXCHANGE_GRANT_TYPE) { invalidGrantType() }
    }

    context
  }

  /**
   * Adapted from [org.keycloak.protocol.oidc.tokenexchange.AbstractTokenExchangeProvider.exchangeExternalToken]
   *
   * Handle and categorize exceptions explicitely, since otherwise the stack traces are "lost".
   */
  private fun exchangeExternalToken(smcbContext: ZetaGuardTokenExchangeContext): Either<KeycloakValidationError, Response> = either {
    val accessToken = smcbContext.subjectToken.toAccessToken()
    val provider = getProvider()
    val model = session.identityProviders().getByAlias(SMCB_IDENTITY_PROVIDER_ID) ?: raise(invalidProviderModel())
    val context = provider.exchangeExternal(smcbContext.exchangeProvider, smcbContext.context) ?: raise(invalidContext())

    context.setSMCBContext(smcbContext)

    val user = importUser(context)
    val userSession =
        UserSessionManager(session).createUserSession(realm, user, user.username, clientConnection.remoteHost, "external-exchange", false, null, null)

    provider.exchangeExternalComplete(userSession, context, formParams)

    userSession.setNote(IdentityProvider.EXTERNAL_IDENTITY_PROVIDER, model.alias)
    userSession.setNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, smcbContext.subjectToken)
    userSession.setNote(ATTRIBUTE_SMCB_CONTEXT, smcbContext.data.toJSON())
    userSession.setNote(ATTRIBUTE_CLIENT_ASSESSMENT_DATA, smcbContext.clientInstanceData.toJSON())

    context.addSessionNotesToUserSession(userSession)

    val response = exchangeClientToClient(user, userSession, accessToken)

    context().client.setAttribute(ATTRIBUTE_ATTESTATION_STATE, ATTESTATION_STATE_VALID)

    response
  }

  private fun Raise<KeycloakValidationError>.exchangeClientToClient(user: UserModel, userSession: UserSessionModel, accessToken: AccessToken) =
      Either.catch { //
            exchangeClientToClient(user, userSession, accessToken, false)
          }
          .mapLeft { exchangeError(it, "exchange_client") }
          .bind()

  private fun Raise<KeycloakValidationError>.importUser(context: BrokeredIdentityContext): UserModel =
      Either.catch { //
            importUserFromExternalIdentity(context)
          }
          .mapLeft { exchangeError(it, "user_model") }
          .bind()

  private fun Raise<KeycloakValidationError>.getProvider(): ExchangeExternalToken =
      Either.catch { getIdentityProvider(session, SMCB_IDENTITY_PROVIDER_ID) }.mapLeft { exchangeError(it, "identity_provider") }.bind()
          as ExchangeExternalToken

  internal fun context() = context
}

private fun TokenExchangeContext.isNoAccessToken(): Boolean = unsupportedReason?.contains("supports access tokens only") == true

internal fun BrokeredIdentityContext.setSMCBContext(smcbContext: ZetaGuardTokenExchangeContext) {
  contextData[ATTRIBUTE_SMCB_CONTEXT] = smcbContext
}

internal fun BrokeredIdentityContext.getSMCBContext(): ZetaGuardTokenExchangeContext =
    contextData[ATTRIBUTE_SMCB_CONTEXT] as ZetaGuardTokenExchangeContext?
        ?: throw IllegalStateException("Value for »$ATTRIBUTE_SMCB_CONTEXT« not found in BrokeredIdentityContext")
