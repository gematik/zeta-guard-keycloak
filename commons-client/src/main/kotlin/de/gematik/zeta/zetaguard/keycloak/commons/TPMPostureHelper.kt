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

const val TPM_KEYSTORE_PASSWORD = "O3Bdel9P5+cOgzIGANkOPEzBQM3V"

const val CRT_TPM_LEAF = "tpm-leaf"
const val CRT_TPM_INTERMEDIATE = "tpm-intermediate"
const val CRT_TPM_ROOT = "tpm-root"

/**
 * Helper class to generate SMC-B tokens.
 *
 * Refers to keys and certificates found in smcb-certificates.p12 testing keystore. On the server side the same keystore is used as a truststore for
 * certificate validation.
 */
object TPMPostureHelper {
  private val stream = TPMPostureHelper::class.java.getResourceAsStream("/tpm-certificates.p12")!!
  private val keystoreService = KeystoreService("TPM", stream, TPM_KEYSTORE_PASSWORD)

  val intermediateCertificate = keystoreService.findCertificate(CRT_TPM_INTERMEDIATE)!!
  val rootCertificate = keystoreService.findCertificate(CRT_TPM_ROOT)!!
  val leafCertificate = keystoreService.findCertificate(CRT_TPM_LEAF)!!
  val privateKey = keystoreService.getPrivateKey(CRT_TPM_LEAF, TPM_KEYSTORE_PASSWORD)
  val publicKey = privateKey.getPublicKey()
  val subjectKeyPair = KeyPair(publicKey, privateKey)
}
