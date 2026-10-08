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
package de.gematik.zeta.zetaguard.keycloak.plugins.accesstoken

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.expirationDate
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ACCESSTOKEN_MAPPERPROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ORGANIZATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_COMMON_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_IP_ADDRESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_ORGANIZATION_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PLATFORM
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import java.time.Duration
import org.jboss.logging.Logger
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper
import org.keycloak.protocol.oidc.mappers.OIDCRefreshTokenMapper
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken
import org.keycloak.representations.IDToken
import org.keycloak.representations.RefreshToken
import org.keycloak.representations.dpop.DPoP
import org.keycloak.services.util.DPoPUtil

private val logger: Logger = Logger.getLogger(ZetaGuardAccessTokenMapper::class.java)

/**
 * Map SMC-B based values into generated token claims as specified by
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/
 *
 * Realm configuration in 12-create-zeta-guard-scope.sh
 */
class ZetaGuardAccessTokenMapper :
    AbstractOIDCProtocolMapper(), OIDCAccessTokenMapper, OIDCIDTokenMapper, OIDCRefreshTokenMapper, OIDCAccessTokenResponseMapper {
  override fun getDisplayCategory() = TOKEN_MAPPER_CATEGORY

  override fun getDisplayType() = "\uD835\uDF75-Guard Access Token Mapper"

  override fun getHelpText() =
      """
      Map SMC-B based values into generated token:
      - Subject (Telematik-ID)
      - Expiration
      """
          .trimIndent()

  override fun getConfigProperties() = listOf<ProviderConfigProperty>()

  override fun getId() = ACCESSTOKEN_MAPPERPROVIDER_ID

  /**
   * Override settings of [org.keycloak.protocol.oidc.mappers.SubMapper],
   *
   * i.e. run last.
   */
  override fun getPriority() = PRIORITY_SCRIPT_MAPPER * 2

  override fun setClaim(
      token: IDToken,
      mappingModel: ProtocolMapperModel,
      userSession: UserSessionModel,
      keycloakSession: KeycloakSession,
      clientSessionCtx: ClientSessionContext,
  ) {
    setClaims(keycloakSession, userSession, token, clientSessionCtx) { access, _ -> access }
  }

  override fun transformRefreshToken(
      token: RefreshToken,
      mappingModel: ProtocolMapperModel,
      session: KeycloakSession,
      userSession: UserSessionModel,
      clientSession: ClientSessionContext,
  ): RefreshToken {
    setClaims(session, userSession, token, clientSession) { _, refresh -> refresh }

    // to conform with A_25663 the thumbprint of DPoP-Key is added to refresh token,
    // Keycloak does this on its own only for public clients,
    // also see https://datatracker.ietf.org/doc/html/rfc9449 section 3. point B.
    val dPoP = session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP::class.java)
    if (dPoP != null) {
      val confirmation = token.confirmation ?: AccessToken.Confirmation().also { token.confirmation = it }
      confirmation.keyThumbprint = dPoP.thumbprint
    }

    return token
  }

  /**
   * Set expiration TTLs, dynamically determined via OPA.
   *
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25664 https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28527
   */
  private fun setClaims(
      session: KeycloakSession,
      userSession: UserSessionModel,
      token: IDToken,
      clientSessionCtx: ClientSessionContext,
      ttl: (access: Duration, refresh: Duration) -> Duration,
  ) {
    val client = clientSessionCtx.clientSession.client
    val smcbContext = userSession.getNote(ATTRIBUTE_SMCB_CONTEXT)
    if (smcbContext != null) {
      val clientStatementString = userSession.getNote(ATTRIBUTE_CLIENT_STATEMENT_DATA) ?: error("Client statement data not found")
      val exchangeData = smcbContext.toObject<ZetaGuardTokenExchangeData>()
      val clientStatement = clientStatementString.toObject<ClientStatementData>()

      token.subject(exchangeData.telematikID)
      token.expirationDate(ttl(exchangeData.accessTokenTTL, exchangeData.refreshTokenTTL))
      token.otherClaims[CLAIM_CLIENT_ID] = client.clientId
      token.otherClaims[CLAIM_PROFESSION_OID] = exchangeData.professionOID
      token.otherClaims[CLAIM_PRODUCT_ID] = clientStatement.posture.productId
      token.otherClaims[CLAIM_PRODUCT_VERSION] = clientStatement.posture.productVersion
      token.otherClaims[CLAIM_PLATFORM] = clientStatement.platform.value
      token.otherClaims[CLAIM_COMMON_NAME] = exchangeData.subjectCommonName
      token.otherClaims[CLAIM_ORGANIZATION_NAME] = exchangeData.subjectOrganisation
      token.otherClaims[CLAIM_IP_ADDRESS] = exchangeData.clientIP
      return
    }

    if (!OidcFlowSettings.isEnabled()) {
      error("SMC-B context not found")
    }

    val kvnr = userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) ?: error("Mobile user KVNR not found")
    token.subject(kvnr)
    token.otherClaims[CLAIM_COMMON_NAME] = kvnr
    userSession.getNote(ATTRIBUTE_MOBILEUSER_ACR)?.let { token.acr = it }
    token.otherClaims[CLAIM_CLIENT_ID] = client.clientId
    session.clientIP.let { token.otherClaims[CLAIM_IP_ADDRESS] = it }
    userSession.getNote(ATTRIBUTE_MOBILEUSER_PROFESSION_OID)?.let { token.otherClaims[CLAIM_PROFESSION_OID] = it }
    userSession.getNote(ATTRIBUTE_MOBILEUSER_ORGANIZATION)?.let { token.otherClaims[CLAIM_ORGANIZATION_NAME] = it }
    client.clientStatement()?.let { token.setClientStatementClaims(it) }
    userSession.opaSessionContext()?.let { token.expirationDate(ttl(it.accessTokenTTL, it.refreshTokenTTL)) }
  }

  private fun IDToken.setClientStatementClaims(clientStatement: ClientStatementData) {
    otherClaims[CLAIM_PRODUCT_ID] = clientStatement.posture.productId
    otherClaims[CLAIM_PRODUCT_VERSION] = clientStatement.posture.productVersion
    otherClaims[CLAIM_PLATFORM] = clientStatement.platform.value
  }

  private fun UserSessionModel.opaSessionContext(): OpaSessionContext? {
    val raw = getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT) ?: return null
    return runCatching { raw.toObject<OpaSessionContext>() }
        .onFailure { logger.warnf(it, "Failed to read OPA session context") }
        .getOrNull()
  }

  private fun ClientModel.clientStatement(): ClientStatementData? {
    val raw = getAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW) ?: return null

    return runCatching { raw.toObject<ClientStatementData>() }
        .onFailure { logger.warnf(it, "Failed to read client statement of client »%s«", clientId) }
        .getOrNull()
  }
}
