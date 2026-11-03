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
package de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import java.io.InputStream
import java.math.BigInteger
import java.security.cert.X509Certificate

/**
 * Maintain Google certificate revocation list as specified in https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
 */
class GoogleCertificateStatusService(inputStream: InputStream) {
  private val revokedCertificates: Set<BigInteger> by lazy {
    val keys = inputStream.toObject<GoogleRevocationStatusList>().entries.keys
    // Avoid Hex string representation, because leading "0" may be missing when using BigInteger.toString(16)
    val hexKeys = keys.map { it.toBigInteger(16) }.toSet()
    // File seems to also contain decimal values, although the specification claims »The dictionary-key is the certificate serial number in lowercase hex.«
    val decimalKeys = keys.filter { it.all(Char::isDigit) }.map { it.toBigInteger(10) }.toSet()

    hexKeys + decimalKeys
  }

  fun isValid(serialNumber: BigInteger) = !revokedCertificates.contains(serialNumber)

  fun isValid(certificate: X509Certificate) = isValid(certificate.serialNumber)

  internal fun revokedCertificates() = revokedCertificates.map { it.toString(16) }.toSet()
}
