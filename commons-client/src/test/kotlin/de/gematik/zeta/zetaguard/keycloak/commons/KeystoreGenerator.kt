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

import de.gematik.zeta.zetaguard.keycloak.commons.server.EC_CURVE_P256
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import java.io.File
import java.security.KeyStore
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12

@Suppress("ReplaceSizeCheckWithIsNotEmpty")
fun main(@Suppress("unused") args: Array<String>) {
  setupSecurityProviders()

  val password = if (args.size > 0) args[0] else SMCB_KEYSTORE_PASSWORD
  val rootCertName = if (args.size > 1) args[1] else CRT_GEMATIK_ROOT
  val intermediateCertName = if (args.size > 2) args[2] else CRT_GEMATIK_INTERMEDIATE
  val leafCertName = if (args.size > 3) args[3] else CRT_GEMATIK_LEAF
  val rootCertDN = if (args.size > 4) args[4] else CRT_GEMATIK_ROOT_DN
  val intermediateCertDN = if (args.size > 5) args[5] else CRT_GEMATIK_INTERMEDIATE_DN
  val leafCertDN = if (args.size > 6) args[6] else CRT_GEMATIK_LEAF_DN

  val keyStore = KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply { load(null) }
  val certificateChain = CertificateChain(EC_CURVE_P256, rootCertDN, intermediateCertDN, leafCertDN)

  with(certificateChain) {
    keyStore.setCertificateEntry(rootCertName, rootCert)
    keyStore.setCertificateEntry(intermediateCertName, intermediateCert)
    keyStore.setCertificateEntry(leafCertName, leafCert)
    keyStore.setKeyEntry(leafCertName, leafKeyPair.private, password.toCharArray(), arrayOf(leafCert, intermediateCert, rootCert))
  }
  keyStore.store(File("certificates.p12").outputStream(), password.toCharArray())
}
