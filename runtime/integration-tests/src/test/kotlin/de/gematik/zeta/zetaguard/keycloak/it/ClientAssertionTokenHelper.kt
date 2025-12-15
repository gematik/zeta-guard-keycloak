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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import java.security.KeyPair

private const val ZETA_CLIENT_KS_PASSWORD = "IzMjk+PEE2QjZDMUF"

/**
 * Helper class to generate client_assertion JWT
 *
 * Uses self-created keystore zeta-client.p12, see CertificateGeneratorTest. The client "zeta-client" refers to the certificate in there (see
 * zeta-client.json)
 */
object ClientAssertionTokenHelper {
  private val stream = ClientAssertionTokenHelper::class.java.getResourceAsStream("/zeta-client.p12")!!
  private val keystoreService = KeystoreService(stream, ZETA_CLIENT_KS_PASSWORD)
  private val privateKey = keystoreService.getPrivateKey(ZETA_CLIENT, ZETA_CLIENT_KS_PASSWORD)
  private val publicKey = keystoreService.getCertificate(ZETA_CLIENT).publicKey!!
  private val subjectKeyPair = KeyPair(publicKey, privateKey)
  val jwsTokenGenerator = SMCBTokenGenerator(subjectKeyPair = subjectKeyPair)
}
