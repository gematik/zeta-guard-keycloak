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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/** Minimal test PKI for resource server certificates: a CA (optionally with an intermediate) and leaf certificates. */
class TestCa(name: String, private val parent: TestCa? = null) {
  val keyPair: KeyPair = newKeyPair()
  val certificate: X509Certificate = issue(name, keyPair, isCa = true, issuer = parent)

  fun issueLeaf(
      name: String,
      validFrom: Instant = Instant.now().minus(Duration.ofHours(1)),
      validUntil: Instant = Instant.now().plus(Duration.ofDays(1)),
  ) = issue(name, newKeyPair(), isCa = false, issuer = this, validFrom = validFrom, validUntil = validUntil)

  /** The leaf, followed by the intermediates up to (excluding) the root. */
  fun chainOf(leaf: X509Certificate): List<X509Certificate> =
      listOf(leaf) + generateSequence(this) { it.parent }.filter { it.parent != null }.map { it.certificate }

  companion object {
    init {
      if (Security.getProvider(PROVIDER_NAME) == null) Security.addProvider(BouncyCastleProvider())
    }

    private fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun issue(
        name: String,
        subjectKeyPair: KeyPair,
        isCa: Boolean,
        issuer: TestCa?,
        validFrom: Instant = Instant.now().minus(Duration.ofHours(1)),
        validUntil: Instant = Instant.now().plus(Duration.ofDays(1)),
    ): X509Certificate {
      val subject = X500Principal("CN=$name")
      val builder =
          JcaX509v3CertificateBuilder(
                  issuer?.certificate?.subjectX500Principal ?: subject,
                  BigInteger.valueOf(System.nanoTime()),
                  Date.from(validFrom),
                  Date.from(validUntil),
                  subject,
                  subjectKeyPair.public,
              )
              .addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
              .addExtension(Extension.keyUsage, true, KeyUsage(if (isCa) KeyUsage.keyCertSign else KeyUsage.digitalSignature))
      val signer = JcaContentSignerBuilder("SHA256withECDSA").build((issuer?.keyPair ?: subjectKeyPair).private)

      return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }
  }
}
