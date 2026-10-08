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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import java.security.KeyPair
import org.keycloak.representations.oidc.OIDCClientRepresentation

class ClientAssertionTokenGenerator(subjectKeyPair: KeyPair = generateKeyPair()) : AbstractTokenGenerator(subjectKeyPair) {
  fun generateClientAssertion(client: OIDCClientRepresentation, nonceString: String): String {
    val registrationAccessToken = client.registrationAccessToken.toAccessToken()
    val clientId = client.clientId
    val audiences = registrationAccessToken.audience.toList()

    return generateClientAssertion(clientId, audiences = audiences, nonceString = nonceString)
  }

  fun generateClientAssertion(
      clientId: String = ZETA_CLIENT,
      subject: String = clientId,
      issuedFor: String = clientId,
      audiences: List<String>,
      nonceString: String,
      postureType: PostureType = PostureType.SOFTWARE,
      otherClaims: Map<String, Any> = createOtherClaims(clientId, nonceString, keys, listOf(leafCertificate, intermediateCertificate), postureType),
  ): String =
      generateToken(issuer = clientId, subject = subject, issuedFor = issuedFor, audiences = audiences, options = TokenOptions(otherClaims = otherClaims))
}
