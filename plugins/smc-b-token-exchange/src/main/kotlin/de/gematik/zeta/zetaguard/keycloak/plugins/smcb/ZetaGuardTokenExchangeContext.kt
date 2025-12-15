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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import de.gematik.zeta.zetaguard.keycloak.commons.IDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.Success
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import java.security.cert.X509Certificate
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.representations.IDToken

/**
 * Collect all relevant data during token exchange.
 *
 * This data will be used for subsequent checks and validations.
 */
class ZetaGuardTokenExchangeContext(val exchangeProvider: ZetaGuardTokenExchangeProvider) : Success {
  lateinit var token: IDToken
  lateinit var certificate: X509Certificate
  lateinit var telematikID: String
  lateinit var professionOID: String
  lateinit var subjectOrganisation: String
  lateinit var subjectName: String

  // Optional TTLs provided by OPA decision (in seconds)
  var accessTokenTtlSeconds: Int? = null
  var refreshTokenTtlSeconds: Int? = null

  val context: TokenExchangeContext
    get() = exchangeProvider.context()

  val subjectToken: String = context.params.subjectToken

  private val tokenInfo: IDTokenInfo = subjectToken.toIDTokenInfo()

  val header: JWSHeader
    get() = tokenInfo.header

  fun createKeyWrapper() =
      KeyWrapper().apply {
        this.kid = header.keyId
        this.type = "EC"
        this.publicKey = this@ZetaGuardTokenExchangeContext.certificate.publicKey
        this.status = KeyStatus.ACTIVE
        this.use = KeyUse.SIG
        this.algorithm = header.algorithm.name
      }
}
