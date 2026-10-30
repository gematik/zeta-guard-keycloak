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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.getPublicKey
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import java.security.KeyPair

const val SMCB_KEYSTORE_PASSWORD = "tyqvHpFoHdu68yRE+0F4q/I"

/**
 * Helper class to generate SMC-B tokens.
 *
 * Refers to keys and certificates found in smcb-certificates.p12 testing keystore. On the server side the same keystore is used as a truststore for
 * certificate validation.
 */
object SMCBTokenHelper {
  private val stream = SMCBTokenHelper::class.java.getResourceAsStream("/smcb-certificates.p12")!!
  internal val keystoreService = KeystoreService(stream, SMCB_KEYSTORE_PASSWORD)

  val intermediateCertificate = keystoreService.findCertificate(CRT_GEMATIK_INTERMEDIATE)!!
  val leafCertificate = keystoreService.findCertificate(CRT_GEMATIK_LEAF)!!
  val privateKey = keystoreService.getPrivateKey(CRT_GEMATIK_LEAF, SMCB_KEYSTORE_PASSWORD)
  val publicKey = privateKey.getPublicKey()
  val subjectKeyPair = KeyPair(publicKey, privateKey)
  val smcbTokenGenerator = SMCBTokenGenerator(subjectKeyPair)
}
