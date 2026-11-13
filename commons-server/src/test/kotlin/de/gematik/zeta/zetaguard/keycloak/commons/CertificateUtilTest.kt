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

import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.signingAlgorithm
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import io.kotest.matchers.shouldBe
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.TimeUnit
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * A_26972-03: commonName and organizationName are taken from the subject of the SM(C)-B certificate as they are; organizationName only if present.
 *
 * @see [https://gemspec.gematik.de/prereleases/Draft_ZETA_26_2/gemSpec_ZETA_V2.0.0_CC/#A_26972-03]
 */
class CertificateUtilTest : ZetaGuardFunSpec() {
  init {
    listOf(
        "Arztpraxis Ann-Beatrixe Zeta TEST-ONLY",
        "Praxis Dr. Müller, Zahnarzt",
        "Apotheke \"Zur Linde\"",
        "Praxis A+B",
        "Praxis; Labor",
        "Praxis <Nord> = Mitte",
        "Praxis \\ Süd",
        " Praxis ",
    ).forEach { name ->
      test("subject commonName »$name« -> returned unchanged") {
        certificate(subject(cn = name, o = "Praxis GmbH")).subjectCommonName() shouldBe name
      }

      test("subject organizationName »$name« -> returned unchanged") {
        certificate(subject(cn = "Praxis", o = name)).subjectOrganisationName() shouldBe name
      }
    }

    test("subject without organizationName -> no organizationName") {
      certificate(subject(cn = "Praxis Dr. Eisenbart", o = null)).subjectOrganisationName() shouldBe null
    }
  }
}

private fun subject(cn: String, o: String?): X500Name =
    X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.C, "DE")
        .apply { if (o != null) addRDN(BCStyle.O, o) }
        .addRDN(BCStyle.CN, cn)
        .build()

private fun certificate(subject: X500Name): X509Certificate {
  val keyPair = generateKeyPair()
  val now = System.currentTimeMillis()
  val builder = JcaX509v3CertificateBuilder(
      /* issuer = */ subject,
      /* serial = */ BigInteger.ONE,
      /* notBefore = */ Date(now),
      /* notAfter = */ Date(now + TimeUnit.DAYS.toMillis(1)),
      /* subject = */ subject,
      /* publicKey = */ keyPair.public
  )
  val signer = JcaContentSignerBuilder(keyPair.signingAlgorithm()).build(keyPair.private)

  return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}
