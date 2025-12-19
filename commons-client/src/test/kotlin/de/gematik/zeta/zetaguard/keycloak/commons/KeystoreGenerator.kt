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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGeneratorTest.Companion.intermediateCert
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGeneratorTest.Companion.leafCert
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGeneratorTest.Companion.leafKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGeneratorTest.Companion.rootCert
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_INTERMEDIATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_ROOT
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KEYSTORE_PASSWORD
import java.io.File
import java.security.KeyStore
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12

fun main(@Suppress("unused") args: Array<String>) {
  setupBouncyCastle()
  val keyStore = KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply { load(null) }

  keyStore.setCertificateEntry(CRT_GEMATIK_ROOT, rootCert)
  keyStore.setCertificateEntry(CRT_GEMATIK_INTERMEDIATE, intermediateCert)
  keyStore.setCertificateEntry(CRT_GEMATIK_LEAF, leafCert)
  keyStore.setKeyEntry(CRT_GEMATIK_LEAF, leafKeyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(leafCert, intermediateCert, rootCert))

  keyStore.store(File("smcb-certificates.p12").outputStream(), KEYSTORE_PASSWORD.toCharArray())
}
