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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.commons.IDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.opa.toOpaDeviceInfo
import de.gematik.zeta.zetaguard.keycloak.commons.resolveClientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.Success
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toThumbprint
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Duration
import kotlin.properties.Delegates
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.representations.IDToken
import org.keycloak.representations.JsonWebToken

/**
 * Collect all relevant data during token exchange.
 *
 * This data will be used for subsequent checks and validations.
 */
class ZetaGuardTokenExchangeContext(val exchangeProvider: ZetaGuardTokenExchangeProvider) : Success {
  lateinit var clientJWK: JWK
  lateinit var token: IDToken
  lateinit var certificate: X509Certificate
  lateinit var telematikID: String
  lateinit var professionOID: String
  lateinit var subjectOrganisation: String
  lateinit var subjectCommonName: String
  lateinit var clientStatementData: ClientStatementData

  // TTLs provided by OPA decision (in seconds)
  lateinit var accessTokenTTLSeconds: Duration
  lateinit var refreshTokenTTLSeconds: Duration

  // Persisted for refresh-path OPA replay.
  var opaAudiences: List<String>? = null
  var opaScopes: List<String>? = null

  lateinit var authenticationMethodsReferences: List<String>
  lateinit var authenticationContextClassReference: String
  lateinit var clientId: String
  lateinit var clientPlatform: String
  var clientRegistrationTimestamp by Delegates.notNull<Long>()
  lateinit var postureType: String
  lateinit var previousIpAddress: String

  val context: TokenExchangeContext
    get() = exchangeProvider.context()

  val subjectToken: String = context.params.subjectToken ?: error("No subject token found")

  val clientAssertionToken: String = context.formParams.getFirst(CLIENT_ASSERTION) ?: error("No client assertion token found")
  val clientAssertion: JsonWebToken by lazy { clientAssertionToken.toJsonWebToken() }
  val certificatePublicKey: PublicKey by lazy { certificate.publicKey }
  val attestationChallenge: String by lazy {
    val nonceBytes = token.nonce.fromBase64()
    val jwkThumbPrint = clientJWK.toThumbprint()

    calculateAttestationChallenge(jwkThumbPrint, nonceBytes)
  }
  private val tokenInfo: IDTokenInfo = subjectToken.toIDTokenInfo()

  val clientIP: String // A_28828
    get() = resolveClientIP(context.clientConnection?.remoteAddr) { httpHeader(it) } ?: error("IP address could not be determined")

  private fun httpHeader(name: String): String? = context.headers.getHeaderString(name)

  val tokenHeader: JWSHeader
    get() = tokenInfo.header

  fun createCertificateKeyWrapper() =
      KeyWrapper().apply {
        this.kid = tokenHeader.keyId
        this.type = "EC"
        this.publicKey = certificatePublicKey
        this.status = KeyStatus.ACTIVE
        this.use = KeyUse.SIG
        this.algorithm = tokenHeader.algorithm.name
      }

  /**
   * Note that this will raise an exception if the values have not been initialized upon usage time.
   *
   * However, at this point of time previous checks should have prevented this case from happening anyway.
   */
  val data: ZetaGuardTokenExchangeData
    get() =
        ZetaGuardTokenExchangeData(
            telematikID = telematikID,
            professionOID = professionOID,
            subjectOrganisation = subjectOrganisation,
            subjectCommonName = subjectCommonName,
            clientIP = clientIP,
            accessTokenTTL = accessTokenTTLSeconds,
            refreshTokenTTL = refreshTokenTTLSeconds,
            audiences = opaAudiences,
            scopes = opaScopes,
            authenticationMethodsReferences = authenticationMethodsReferences,
            authenticationContextClassReference = authenticationContextClassReference,
            clientId = clientId,
            clientPlatform = clientPlatform,
            clientRegistrationTimestamp = clientRegistrationTimestamp,
            postureType = postureType,
            previousIpAddress = previousIpAddress,
            deviceInfo = clientStatementData.posture.toOpaDeviceInfo(),
        )
}
