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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.LinuxProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType.SOFTWARE
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType.TPM
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.subjectKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import java.security.cert.X509Certificate

val platformProductId = LinuxProductId("packaging", "app-id")

// Implement https://ey-fp-dev.atlassian.net/browse/ZETAP-794
fun clientStatementData(
    clientId: String,
    nonceString: String,
    pkidata: PKIData,
    certificateChain: List<X509Certificate> = listOf(leafCertificate, intermediateCertificate),
    postureType: PostureType = SOFTWARE,
    productId: ProductId = platformProductId,
    timeStampSeconds: Long = timeStampSeconds(),
): ClientStatementData {
  val nonceBytes = nonceString.fromBase64()
  val attestationChallenge = calculateAttestationChallenge(pkidata.jwkThumbPrint, nonceBytes)
  val posture =
      when (postureType) {
        SOFTWARE -> generateSoftwarePosture(productId, pkidata, attestationChallenge)
        TPM -> generateTpmPosture(attestationChallenge.fromBase64(), subjectKeyPair, certificateChain)

        else -> error("Unknown posture type: $postureType")
      }

  return ClientStatementData(clientId, Platform.LINUX, postureType, posture, timeStampSeconds)
}

private fun generateSoftwarePosture(productId: ProductId, pkidata: PKIData, attestationChallenge: String): SoftwarePosture =
    SoftwarePosture(productId, PRODUCT_ID, PRODUCT_VERSION, "Linux", "6.12.54-linuxkit", "aarch64", pkidata.publicKeyPEM, attestationChallenge)

private fun timeStampSeconds(): Long = System.currentTimeMillis() / 1000

fun createOtherClaims(
    clientId: String,
    nonceString: String,
    pkidata: PKIData,
    certificateChain: List<X509Certificate> = listOf(leafCertificate, intermediateCertificate),
    postureType: PostureType = SOFTWARE,
) = mapOf(CLAIM_CLIENT_STATEMENT to clientStatementData(clientId, nonceString, pkidata, certificateChain, postureType))
