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
package de.gematik.zeta.zetaguard.keycloak.plugins.accesstoken

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.expirationDate
import de.gematik.zeta.zetaguard.keycloak.commons.server.ACCESSTOKEN_MAPPERPROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_ASSESSMENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_ACCESS_TOKEN_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import java.time.Duration
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
import org.keycloak.representations.IDToken
import org.keycloak.representations.RefreshToken

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
    setClaims(userSession, token) { it.accessTokenTTL }
  }

  override fun transformRefreshToken(
      token: RefreshToken,
      mappingModel: ProtocolMapperModel,
      session: KeycloakSession,
      userSession: UserSessionModel,
      clientSession: ClientSessionContext,
  ): RefreshToken {
    setClaims(userSession, token) { it.refreshTokenTTL }

    return token
  }

  private fun setClaims(userSession: UserSessionModel, token: IDToken, ttlMapper: (ZetaGuardTokenExchangeData) -> Duration) {
    val contextString = userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) ?: throw IllegalStateException("SMC-B context not found")
    val clientDataString = userSession.getNote(ATTRIBUTE_CLIENT_ASSESSMENT_DATA) ?: throw IllegalStateException("Client assessment data not found")
    val exchangeData = contextString.toObject<ZetaGuardTokenExchangeData>()
    val clientData = ObjectMapper().readValue(clientDataString, Map::class.java)

    token.subject(exchangeData.telematikID)
    token.expirationDate(ttlMapper(exchangeData))
    token.otherClaims[CLAIM_ACCESS_TOKEN_CLIENT_DATA] = clientData
  }
}
