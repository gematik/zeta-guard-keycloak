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
package de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.OcspUtil
import de.gematik.zeta.zetaguard.keycloak.commons.opa.toOpaDeviceInfo
import de.gematik.zeta.zetaguard.keycloak.commons.ProfessionOidValidator
import de.gematik.zeta.zetaguard.keycloak.commons.secondsToLocalDateTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_DPOP_KEY
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_JKT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CapecAttackMechanics.AUTHENTICATION_BYPASS
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SMCB_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstAdmission
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfession
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfessionInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.httpClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.reportAttack
import de.gematik.zeta.zetaguard.keycloak.commons.server.serverHost
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.tracingProvider
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.checkPostureType
import de.gematik.zeta.zetaguard.keycloak.plugins.checkPostureTypeMatchesPlatform
import de.gematik.zeta.zetaguard.keycloak.plugins.clientDisabled
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.convertToJWKS
import de.gematik.zeta.zetaguard.keycloak.plugins.createToken
import de.gematik.zeta.zetaguard.keycloak.plugins.createTokenVerifier
import de.gematik.zeta.zetaguard.keycloak.plugins.exchangeError
import de.gematik.zeta.zetaguard.keycloak.plugins.extractPublicKey
import de.gematik.zeta.zetaguard.keycloak.plugins.hasSigningFailureCause
import de.gematik.zeta.zetaguard.keycloak.plugins.internalError
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidCertificate
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidClientClaim
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidClientPublicKey
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidContext
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidGrantType
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidNonce
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidProviderModel
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidSubject
import de.gematik.zeta.zetaguard.keycloak.plugins.invalidToken
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.missingClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.missingClientState
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceProviderFactory
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.commons.OcspConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.logInvalidAuthorizationCodes
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import de.gematik.zeta.zetaguard.keycloak.plugins.parseClaim
import de.gematik.zeta.zetaguard.keycloak.plugins.readCertificate
import de.gematik.zeta.zetaguard.keycloak.plugins.resolveAudiences
import de.gematik.zeta.zetaguard.keycloak.plugins.tokenSigningUnavailable
import io.opentelemetry.semconv.ServerAttributes
import jakarta.ws.rs.core.Response
import java.time.Duration
import java.time.LocalDateTime
import java.time.ZoneOffset
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.keycloak.OAuth2Constants
import org.keycloak.OAuth2Constants.JWT
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.OAuthErrorException.SERVER_ERROR
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.ExchangeExternalToken
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.EXTERNAL_IDENTITY_PROVIDER
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN
import org.keycloak.crypto.Algorithm
import org.keycloak.jose.jwk.JWK
import org.keycloak.keys.loader.PublicKeyStorageManager
import org.keycloak.models.ClientModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.OIDCConfigAttributes.JWKS_STRING
import org.keycloak.protocol.oidc.OIDCConfigAttributes.USE_JWKS_STRING
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider
import org.keycloak.representations.AccessToken
import org.keycloak.representations.IDToken
import org.keycloak.representations.dpop.DPoP
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.managers.UserSessionManager
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resources.IdentityBrokerService.getIdentityProvider
import org.keycloak.services.util.CertificateInfoHelper
import org.keycloak.services.util.DPoPUtil
import org.keycloak.util.JWKSUtils.computeThumbprint

typealias KeycloakValidationError = KeycloakError

typealias KeycloakValidation = Either<KeycloakValidationError, ZetaGuardTokenExchangeContext>

private val REFERENCE_DATE = LocalDateTime.of(2025, 12, 1, 0, 0)!!

private const val OPA_TRACER = "zetaguard.opa"

private const val AMR_TELEMATIK_SMCB = "urn:telematik:auth:sc"
private const val ACR_TELEMATIK_SMCB = "gematik-ehealth-loa-substantial"

/**
 * External to internal token exchange provider for SMC-B created tokens.
 *
 * We try to use as much as possible from the standard V2 OIDC provider implementation.
 *
 * For details, see https://www.keycloak.org/securing-apps/token-exchange and
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5
 */
open class ZetaGuardTokenExchangeProvider internal constructor(
    private val integrityProviderService: IntegrityProviderService,
    private val dataService: ZetaGuardDataService,
    currentTrustMaterial: () -> TrustMaterial,
    private val opaConfig: OPAConfig,
    private val ocspConfig: OcspConfig,
) : StandardTokenExchangeProvider() {
  /**
   * The truststores this exchange works against, resolved exactly once.
   *
   * [currentTrustMaterial] hands out whatever the reload has published most recently, and a provider lives for a single
   * request — so resolving it once here is what keeps one exchange from checking the certificate against one snapshot
   * and the revocation state against the next.
   */
  private val trust by lazy { currentTrustMaterial() }

  /**
   * Adapted from [StandardTokenExchangeProvider.tokenExchange]
   *
   * The supplied client assertion token has already been validated by [org.keycloak.authentication.authenticators.client.JWTClientValidator] at this
   * point.
   */
  override fun tokenExchange(): Response {
    // Override value, in order to implement org.keycloak.protocol.oidc.mappers.OIDCRefreshTokenMapper feature
    tokenManager = ZetaGuardTokenManager()
    tagRequestSpan()

    return checkIntegrityProvider(ZetaGuardTokenExchangeContext(this))
        .flatMap { validateX5CCertificate(it) }
        .flatMap { checkGrantType(it) }
        .flatMap { verifySubjectToken(it) }
        .flatMap { verifyCertificate(it) }
        .flatMap { checkNonce(it) }
        .flatMap { checkSubject(it) }
        .flatMap { checkClientPublicKeyConsistency(it) }
        .flatMap { checkSubjectTokenKeyBindings(it) }
        .flatMap { handleClientStatementData(it) }
        .flatMap { checkOPAPolicies(it) }
        .flatMap { exchangeExternalToken(it) }
        .onLeft { logInvalidAuthorizationCodes(error = it) }
        .getOrElse { throw mapToCorsException(it, context().cors, context().event) }
  }

  /**
   * We want to reuse as much as possible from the overridden method, as opposed to copying the code.
   *
   * Unfortunately, the last check is for token type [OAuth2Constants.ACCESS_TOKEN_TYPE], whereas we want token type [JWT_TOKEN_TYPE].
   *
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25659
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
   * We refer to the new token exchange standard implementation
   *
   * @see [org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.exchangeExternal]
   */
  override fun getVersion(): Int = 2

  override fun getTargetAudienceClients(): List<ClientModel> = emptyList()

  override fun checkRequestedAudiences(responseBuilder: TokenManager.AccessTokenResponseBuilder) = Unit

  /**
   * The overridden code is not feasible because it does not just check audiences.
   *
   * It also disallows public clients, i.e., clients without a client secret. Since we use client_assertion, this is not correct.
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
  private fun verifyCertificate(context: ZetaGuardTokenExchangeContext) =
      either {
        val certificate = context.certificate
        val issuerCertificate = trust.smcb.findIssuerCertificate(certificate)
          ?: raise(invalidToken("Certificate issuer not found: »${certificate.issuerX500Principal}«"))

        validateCertificateSignature(certificate, issuerCertificate.publicKey).mapLeft { invalidToken(it) }.bind()

        validateCertificateChain(issuerCertificate, listOf(certificate)).mapLeft { invalidToken(it) }.bind()

        val httpClient = session.httpClient

        OcspUtil.checkRevoked(
            certificate,
            trust.smcb,
            trust.ocsp,
            httpClient,
            config = ocspConfig,
        )
            .mapLeft { invalidToken(it) }
            .bind()

        context
      }.onLeft { session.reportAttack(it, AUTHENTICATION_BYPASS, context.clientIP) }

  /**
   * Read and check statement data from client_assertion token.
   *
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25644
   */
  private fun handleClientStatementData(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val claims = clientAssertionClaims(context)
    val clientStatement = claims.readClientStatement() ?: raise(invalidClientClaim("Claim »$CLAIM_CLIENT_STATEMENT« not found"))
    val clientStatementData = parseClaim<ClientStatementData>(clientStatement, "client statement").bind()
    val attestationTime = clientStatementData.attestationTimestamp.secondsToLocalDateTime()

    ensure(attestationTime.isAfter(REFERENCE_DATE)) { invalidClientClaim("Invalid attestation timestamp »$attestationTime«") }
    ensure(clientStatementData.clientId == client.clientId) { invalidClientClaim("Invalid client id »${clientStatementData.clientId}«") }

    checkPostureTypeMatchesPlatform(clientStatementData).bind()

    checkPostureType(clientStatementData, context, trust.tpm).onLeft {
      session.reportAttack(it, AUTHENTICATION_BYPASS, context.clientIP)
    }.bind()

    context.clientStatementData = clientStatementData

    context
  }


  /**
   * Validates the given subject token, inspired by [AuthenticationManager.verifyIdentityToken].
   *
   * Additional checks for the issuer, algorithm, ...
   */
  private fun verifySubjectToken(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val verifier = createTokenVerifier(context).bind()

    ensure(verifier.header.algorithm.name == Algorithm.ES256) { invalidToken("Invalid algorithm: »${verifier.header.algorithm.name}«") }
    ensure(verifier.header.type == JWT) { invalidToken("Invalid token type: »${verifier.header.type}«") }

    val token = session.createToken(verifier, context).bind()

    ensure(token.issuer == client.clientId) { invalidToken("Issuer does not match client id") }
    ensure(token.iat >= realm.notBefore) { invalidToken("Identity token expired") }

    context.token = token

    context
  }

  private fun checkIntegrityProvider(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    if (integrityProviderService.isIntegrityProviderEnabled()) {
      ensure(integrityProviderService.isIntegrityProviderRunning()) {
        KeycloakValidationError(SERVER_ERROR, "Integrity provider is not (yet) running", Response.Status.SERVICE_UNAVAILABLE)
      }
    }

    context
  }

  /**
   * Validates data of the certificate, read from "x5c" header.
   *
   * Extract and checks data from certificate extensions, such as profession OID and registration number.
   */
  private fun validateX5CCertificate(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    ensure(context.tokenHeader.x5c != null && context.tokenHeader.x5c.isNotEmpty()) { invalidToken("Invalid x5c claim in token header") }

    val certificate = readCertificate(context).bind()
    val admissionSyntax = certificate.extractExtension<AdmissionSyntax>(admission) ?: raise(invalidCertificate("Invalid admission extension"))
    val admissions = admissionSyntax.firstAdmission() ?: raise(invalidCertificate("Invalid contents of admission extension"))
    val professionInfo = admissions.firstProfessionInfo() ?: raise(invalidCertificate("Invalid profession infos"))
    val professionIdentifier = professionInfo.firstProfession() ?: raise(invalidCertificate("Invalid profession OID"))
    val professionOID = professionIdentifier.id
    val telematikID = professionInfo.registrationNumber ?: raise(invalidCertificate("Invalid registration number"))

    ensure(ProfessionOidValidator.isValidProfessionOidFormat(professionOID)) { invalidCertificate("Invalid profession OID format") }

    // See https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26972
    context.apply {
      this.certificate = certificate
      this.telematikID = telematikID
      this.professionOID = professionOID
      this.subjectCommonName = certificate.subjectCommonName()
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

    ensure(nonceFactory.retrieveNonce(context.token.nonce) != null) {
      invalidNonce().also {
        session.reportAttack(it, AUTHENTICATION_BYPASS, context.clientIP)
      }
    }

    context
  }

  private fun checkSubject(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    ensure(context.telematikID == context.token.subject) { invalidSubject() }

    context
  }

  /**
   * Check OPA policies
   *
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25653 https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25661
   */
  private fun checkOPAPolicies(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val httpClient = session.httpClient
    val input = populateContextAndBuildGateInput(context).mapLeft { internalError(it) }.bind()

    session.tracingProvider.trace(ZetaGuardTokenExchangeProvider::class.java, OPA_TRACER) {
      it.setAttribute("zeta.client.ip", context.clientIP)
      it.setAttribute("zeta.client.id", context.clientId)
      it.setAttribute(ServerAttributes.SERVER_ADDRESS, session.serverHost)
      it.addEvent("opa.enforcer.start")

      when (val outcome = OpaGateEnforcer.enforce(httpClient, input, opaConfig)) {
        is OpaGateEnforcer.Outcome.Skip -> {
          context.accessTokenTTLSeconds = Duration.ofSeconds(-1) // avoid lateinit error
          context.refreshTokenTTLSeconds = Duration.ofSeconds(-1)
        }

        is OpaGateEnforcer.Outcome.Allow -> {
          context.accessTokenTTLSeconds = Duration.ofSeconds(outcome.accessTokenTtl?.toLong() ?: -1)
          context.refreshTokenTTLSeconds = Duration.ofSeconds(outcome.refreshTokenTtl?.toLong() ?: -1)
        }

        is OpaGateEnforcer.Outcome.Deny -> raise(outcome.error)
        is OpaGateEnforcer.Outcome.Error -> raise(outcome.error)
      }

      it.addEvent("opa.enforcer.done")
    }

    context
  }

  private fun populateContextAndBuildGateInput(context: ZetaGuardTokenExchangeContext): Either<Throwable, OpaGateInput> =
      Either.catch {
        val grantType = formParams.getFirst(OAuth2Constants.GRANT_TYPE)
        val scopes = formParams.getFirst(OAuth2Constants.SCOPE)?.split(' ')?.filter { it.isNotBlank() } ?: emptyList()
        val audiences = resolveAudiences(formParams)

        context.opaAudiences = audiences
        context.opaScopes = scopes

        val ipAddress = context.clientIP
        context.previousIpAddress = client.attributes[ATTRIBUTE_LAST_CLIENT_IP] ?: "Unknown"

        context.authenticationMethodsReferences = listOf(AMR_TELEMATIK_SMCB) + (formParams[OAuth2Constants.AUTHENTICATOR_METHOD_REFERENCE] ?: emptyList())
        context.authenticationContextClassReference = ACR_TELEMATIK_SMCB

        val userIdentifier = context.telematikID
        val userProfessionOid = context.professionOID
        val clientModel = context().client
        val clientId = clientModel.clientId
        val clientData = dataService.findClientData(clientId) ?: throw RuntimeException("Could not find client data for ${clientId}«")
        val clientProductID = context.clientStatementData.posture.productId
        val clientProductVersion = context.clientStatementData.posture.productVersion

        context.clientId = clientModel.id
        context.clientPlatform = context.clientStatementData.platform.value
        context.clientRegistrationTimestamp = clientData.lastAccess.toEpochSecond(ZoneOffset.UTC)
        context.postureType = context.clientStatementData.postureType.value

        OpaGateInput(
            clientId = context.clientId,
            clientPlatform = context.clientPlatform,
            clientProductID = clientProductID,
            clientProductVersion = clientProductVersion,
            clientRegistrationTimestamp = context.clientRegistrationTimestamp,
            grantType = grantType,
            scopes = scopes,
            authenticationMethodsReferences = context.authenticationMethodsReferences,
            authenticationContextClassReference = context.authenticationContextClassReference,
            audiences = audiences,
            ipAddress = ipAddress,
            previousIpAddress = context.previousIpAddress,
            postureType = context.postureType,
            userIdentifier = userIdentifier,
            userProfessionOid = userProfessionOid,
            deviceInfo = context.clientStatementData.posture.toOpaDeviceInfo(),
        )
      }

  /**
   * Check valid grant types.
   *
   * Only token exchange and refresh are supported. The latter is not allowed when the client is in state "pending_attestation"
   */
  private fun checkGrantType(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val grantType = context().formParams.getFirst(OIDCLoginProtocol.GRANT_TYPE_PARAM)

    ensure(VALID_GRANT_TYPES.contains(grantType)) { invalidGrantType() }

    val attestationState = dataService.findClientData(context().client.clientId)?.attestationState ?: raise(missingClientState())

    when (attestationState) {
      ClientAttestationState.INVALID -> raise(invalidGrantType())
      ClientAttestationState.PENDING -> ensure(grantType == TOKEN_EXCHANGE_GRANT_TYPE) { invalidGrantType() }
      ClientAttestationState.VALID -> {
        // Nothing to do
      }
    }

    context
  }

  /**
   * Adapted from [org.keycloak.protocol.oidc.tokenexchange.AbstractTokenExchangeProvider.exchangeExternalToken]
   *
   * Handle and categorize exceptions explicitely, since otherwise the stack traces are "lost".
   */
  private fun exchangeExternalToken(context: ZetaGuardTokenExchangeContext): Either<KeycloakValidationError, Response> = either {
    val accessToken = context.subjectToken.toAccessToken()
    val provider = getProvider()
    val model = session.identityProviders().getByAlias(SMCB_IDENTITY_PROVIDER_ID) ?: raise(invalidProviderModel())
    val brokeredIdentityContext = provider.exchangeExternal(context.exchangeProvider, context.context) ?: raise(invalidContext())

    brokeredIdentityContext.setSMCBContext(context)

    val user = importUser(brokeredIdentityContext)
    val userSession =
        UserSessionManager(session).createUserSession(realm, user, user.username, clientConnection.remoteHost, "external-exchange", false, null, null)

    provider.exchangeExternalComplete(userSession, brokeredIdentityContext, formParams)

    userSession.setNote(EXTERNAL_IDENTITY_PROVIDER, model.alias)
    userSession.setNote(FEDERATED_ACCESS_TOKEN, context.subjectToken)
    userSession.setNote(ATTRIBUTE_SMCB_CONTEXT, context.data.toJSON())
    userSession.setNote(ATTRIBUTE_CLIENT_STATEMENT_DATA, context.clientStatementData.toJSON())

    brokeredIdentityContext.addSessionNotesToUserSession(userSession)

    val response = exchangeClientToClient(user, userSession, accessToken)
    val clientModel = context().client
    val clientId = clientModel.clientId
    val clientData = dataService.findClientData(clientId) ?: raise(missingClientData(clientId))

    clientData.attestationState = ClientAttestationState.VALID
    clientData.lastAccess = currentTime()
    clientModel.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, context.clientIP)

    SecurityEventLogger.logTokenExchanged(
        clientId = clientModel.clientId,
        clientOsName = context.clientStatementData.platform.name,
        registrationTimestamp = context.clientRegistrationTimestamp,
        registrationResult = clientData.attestationState.name,
    )

    response
  }

  private fun checkClientPublicKeyConsistency(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    val useJWKSString = client.attributes[USE_JWKS_STRING] ?: raise(invalidClientPublicKey("Invalid client JWKS attribute »$USE_JWKS_STRING«"))
    val attrKeyId = JWTClientAuthenticator.ATTR_PREFIX + "." + CertificateInfoHelper.KID
    val attrKey = JWTClientAuthenticator.ATTR_PREFIX + "." + CertificateInfoHelper.PUBLIC_KEY
    val clientKid = client.attributes[attrKeyId] ?: raise(invalidClientPublicKey("Invalid client JWKS kid attribute »$attrKeyId«"))
    val publicKeyString = client.attributes[attrKey] ?: raise(invalidClientPublicKey("Invalid client public key attribute »$attrKey«"))
    val jwksString = client.attributes[JWKS_STRING] ?: raise(invalidClientPublicKey("Invalid client JWKS attribute »$JWKS_STRING«"))
    val clientPublicKey = publicKeyString.toPublicKey().mapLeft { invalidClientPublicKey(it) }.bind()
    val jwks = jwksString.convertToJWKS().bind().also { ensure(it.keys.isNotEmpty()) { invalidClientClaim("Invalid client JWKS: no keys found") } }
    val jwk = jwks.keys[0]
    val clientKeyWrapper = getClientPublicKeyWrapper()
    val jwkPublicKey = jwk.extractPublicKey().bind()

    // Make sure everything fits together
    ensure(useJWKSString.toBoolean()) { invalidClientPublicKey("Invalid disabled client JWKS attribute »$USE_JWKS_STRING«") }
    ensure(clientKeyWrapper.kid == jwk.keyId) { invalidClientPublicKey("Stored public key ID does not match client JWK key ID") }
    ensure(clientKid == jwk.keyId) { invalidClientPublicKey("Client public key ID does not match client JWK key ID") }
    ensure(clientKeyWrapper.publicKey == jwkPublicKey) { invalidClientPublicKey("Stored public key does not match client JWK public key") }
    ensure(clientPublicKey == jwkPublicKey) { invalidClientPublicKey("Client public key does not match client JWK key") }

    context.clientJWK = jwk

    context
  }

  /**
   * Enforce the SMC-B-signed binding of client key and DPoP key.
   *
   * The subject token carries »$CLAIM_CLIENT_KEY« and »$CLAIM_DPOP_KEY« thumbprints signed by the SMC-B. Without this check, a man-in-the-middle can
   * forward the victim's subject token while presenting his own keys.
   *
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.12.2.5.1
   */
  private fun checkSubjectTokenKeyBindings(context: ZetaGuardTokenExchangeContext): KeycloakValidation = either {
    // invalid_token: the violated binding is the SMC-B-signed thumbprint
    val attestedClientKey = context.token.jktBinding(CLAIM_CLIENT_KEY) ?: raise(invalidToken("Missing »$CLAIM_CLIENT_KEY« binding in subject token"))
    ensure(attestedClientKey == computeThumbprint(context.clientJWK)) { invalidToken("Client key does not match »$CLAIM_CLIENT_KEY« binding") }

    val dPoP = session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP::class.java) ?: raise(invalidToken("DPoP proof is missing"))
    val attestedDpopKey = context.token.jktBinding(CLAIM_DPOP_KEY) ?: raise(invalidToken("Missing »$CLAIM_DPOP_KEY« binding in subject token"))
    ensure(attestedDpopKey == dPoP.thumbprint) { invalidToken("DPoP key does not match »$CLAIM_DPOP_KEY« binding") }

    context
  }

  @Suppress("DEPRECATION")
  private fun Raise<KeycloakValidationError>.getClientPublicKeyWrapper() =
      Either.catch { PublicKeyStorageManager.getClientPublicKeyWrapper(session, client, JWK.Use.SIG, "ES256") }
          .mapLeft { invalidClientPublicKey("Cannot parse JWKS attribute »$JWKS_STRING«") }
          .bind()

  private fun Raise<KeycloakValidationError>.getProvider(): ExchangeExternalToken =
      Either.catch { getIdentityProvider(session, SMCB_IDENTITY_PROVIDER_ID) }.mapLeft { exchangeError(it, "identity_provider") }.bind()
          as ExchangeExternalToken

  private fun Raise<KeycloakValidationError>.exchangeClientToClient(user: UserModel, userSession: UserSessionModel, accessToken: AccessToken) =
      Either.catch { //
        exchangeClientToClient(user, userSession, accessToken, false)
      }
          .mapLeft { if (hasSigningFailureCause(it)) tokenSigningUnavailable(it) else exchangeError(it, "exchange_client") }
          .bind()

  private fun Raise<KeycloakValidationError>.importUser(context: BrokeredIdentityContext): UserModel =
      Either.catch { //
        importUserFromExternalIdentity(context)
      }
          .mapLeft { exchangeError(it, "user_model") }
          .bind()

  private fun Raise<KeycloakValidationError>.clientAssertionClaims(context: ZetaGuardTokenExchangeContext): Map<String, Any> =
      context.clientAssertion.otherClaims ?: raise(invalidClientClaim("No claims found in JWT token"))

  private fun tagRequestSpan() {
    try {
      val span = io.opentelemetry.instrumentation.api.instrumenter.LocalRootSpan.current()
      span.setAttribute("http.request.method_original", session.context.httpRequest.httpMethod)
      span.setAttribute("app.installation.id", context().client.clientId)
    } catch (_: Exception) {
      // Observability must never break the business flow
    }
  }

  internal fun context() = context
}

private fun TokenExchangeContext.isNoAccessToken(): Boolean = unsupportedReason?.contains("supports access tokens only") == true

internal fun BrokeredIdentityContext.setSMCBContext(smcbContext: ZetaGuardTokenExchangeContext) {
  contextData[ATTRIBUTE_SMCB_CONTEXT] = smcbContext
}

internal fun BrokeredIdentityContext.getSMCBContext(): ZetaGuardTokenExchangeContext =
    contextData[ATTRIBUTE_SMCB_CONTEXT] as ZetaGuardTokenExchangeContext?
      ?: error("Value for »$ATTRIBUTE_SMCB_CONTEXT« not found in BrokeredIdentityContext")

@Suppress("UNCHECKED_CAST") //
internal fun Map<String, Any>.readClientStatement() = this[CLAIM_CLIENT_STATEMENT] as? Map<String, Any>

/** Reads the »jkt« thumbprint from a »{ jkt: ... }« binding claim of the SMC-B subject token. */
@Suppress("UNCHECKED_CAST")
private fun IDToken.jktBinding(claimName: String): String? = (otherClaims[claimName] as? Map<String, Any>)?.get(CLAIM_JKT) as? String
