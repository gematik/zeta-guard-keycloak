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
package de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit.DAYS
import java.util.Date
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder

private const val PASSWORD = "no_secret_for_trust_only"

private const val META = """[{"friendlyName": "root-ca", "tspName": "root"}]"""

/**
 * What the reload compares, and why it compares bytes.
 *
 * The predecessor of this digest hashed the certificates a truststore parses into, which quietly excluded the TPM
 * truststore: the provisioning processor exports it with `openssl pkcs12 -nokeys -export` and no `-caname`, so its
 * entries carry no `friendlyName` and BouncyCastle reports no aliases for them. Its contribution to that hash was a
 * constant, and a changed TPM truststore was therefore never picked up. Hashing the file bytes has no such blind spot,
 * which is what the first test here nails down.
 */
class TrustMaterialTest : FunSpec() {
  init {
    beforeSpec { if (Security.getProvider(PROVIDER_NAME) == null) Security.addProvider(BouncyCastleProvider()) }

    test("A change confined to the TPM truststore changes the digest") {
      val locations = trustDir()
      val before = TrustMaterial.digest(locations)

      Files.write(Path.of(locations.tpmKeystore), keystoreBytes("tpm-ca", "another-tpm-ca"))

      TrustMaterial.digest(locations) shouldNotBe before
    }

    test("A truststore whose entries carry no friendlyName is invisible to aliases() but not to the digest") {
      // This is what the provisioning processor produces for TPM: `openssl pkcs12 -nokeys -export` without -caname
      // writes cert bags without a friendlyName, and BouncyCastle only enumerates bags that have one. Hashing the
      // parsed certificates therefore saw a constant for this truststore and never noticed a change; hashing the
      // bytes does. The empty alias set below is the finding, the changed digest is why the reload still works.
      val locations = trustDir(tpmKeystore = keystoreBytesWithoutFriendlyNames("tpm-ca"))
      val before = TrustMaterial.digest(locations)

      TrustMaterial.load(locations).tpm.aliases() shouldBe emptySet()

      Files.write(Path.of(locations.tpmKeystore), keystoreBytesWithoutFriendlyNames("tpm-ca", "another-tpm-ca"))

      TrustMaterial.digest(locations) shouldNotBe before
    }

    test("Every trust file is part of the digest") {
      val locations = trustDir()
      val paths = listOfNotNull(locations.smcbKeystore, locations.smcbMeta, locations.tpmKeystore, locations.ocsp?.keystore, locations.ocsp?.meta)

      paths.forEach { path ->
        val before = TrustMaterial.digest(locations)

        Files.write(Path.of(path), Files.readAllBytes(Path.of(path)) + "trailing".toByteArray())

        withClue(path) { TrustMaterial.digest(locations) shouldNotBe before }
      }
    }

    test("Re-exporting identical certificates changes the digest") {
      val keystore = newKeystore("root-ca")
      val locations = trustDir(smcbKeystore = export(keystore))
      val before = TrustMaterial.digest(locations)

      // openssl and BouncyCastle alike pick a fresh salt on every export, so the bytes differ even though nothing about
      // the certificates did. One reload per provisioning run is the accepted price for seeing every real change.
      Files.write(Path.of(locations.smcbKeystore), export(keystore))

      TrustMaterial.digest(locations) shouldNotBe before
    }

    test("Loaded material carries the digest of the files it was parsed from") {
      val locations = trustDir()

      TrustMaterial.load(locations).digest shouldBe TrustMaterial.digest(locations)
    }

    test("Loaded material exposes the certificates of all three truststores") {
      val material = TrustMaterial.load(trustDir())

      material.smcb.aliases() shouldBe setOf("ROOT-CA")
      material.tpm.aliases() shouldBe setOf("TPM-CA")
      material.ocsp?.aliases() shouldBe setOf("OCSP-SIGNER")
    }

    test("A missing trust file is refused rather than silently skipped") {
      val locations = trustDir()

      Files.delete(Path.of(locations.tpmKeystore))

      shouldThrow<IllegalStateException> { TrustMaterial.digest(locations) }
    }

    test("An unparsable truststore fails while loading, not during a later request") {
      val locations = trustDir(smcbKeystore = "not a pkcs12 container".toByteArray())

      // The digest does not care — it never parses. Loading must.
      TrustMaterial.digest(locations)

      shouldThrow<Exception> { TrustMaterial.load(locations) }
    }

    test("Trust material without OCSP files is usable and has its own digest") {
      val withOcsp = trustDir()
      val withoutOcsp = TrustMaterialLocations(withOcsp.smcbKeystore, withOcsp.smcbMeta, PASSWORD, withOcsp.tpmKeystore, PASSWORD, ocsp = null)

      TrustMaterial.load(withoutOcsp).ocsp shouldBe null
      TrustMaterial.digest(withoutOcsp) shouldNotBe TrustMaterial.digest(withOcsp)
    }
  }
}

/** Writes a full set of trust files into a fresh temp directory and points a [TrustMaterialLocations] at them. */
private fun trustDir(
    smcbKeystore: ByteArray = keystoreBytes("root-ca"),
    smcbMeta: ByteArray = META.toByteArray(),
    tpmKeystore: ByteArray = keystoreBytes("tpm-ca"),
): TrustMaterialLocations {
  val root = Files.createTempDirectory("trust-material").apply { toFile().deleteOnExit() }
  fun write(name: String, bytes: ByteArray) = Files.write(root.resolve(name), bytes).toString()

  return TrustMaterialLocations(
      smcbKeystore = write("smcb-trust-roots.p12", smcbKeystore),
      smcbMeta = write("smcb-trust-roots-meta.json", smcbMeta),
      smcbPassword = PASSWORD,
      tpmKeystore = write("tpm-trust-roots.p12", tpmKeystore),
      tpmPassword = PASSWORD,
      ocsp =
          TrustMaterialLocations.Ocsp(
              keystore = write("ocsp-signers.p12", keystoreBytes("ocsp-signer")),
              meta = write("ocsp-signers-meta.json", """[{"friendlyName": "ocsp-signer", "tspName": "root"}]""".toByteArray()),
              password = PASSWORD,
          ),
  )
}

private fun keystoreBytes(vararg aliases: String): ByteArray = export(newKeystore(*aliases))

/** A PKCS12 built the way `openssl pkcs12 -export` builds it without `-caname`: cert bags carrying no friendlyName. */
private fun keystoreBytesWithoutFriendlyNames(vararg commonNames: String): ByteArray =
    PKCS12PfxPduBuilder()
        .apply { commonNames.forEach { addData(JcaPKCS12SafeBagBuilder(selfSignedCertificate(it)).build()) } }
        .build(JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256).setProvider(PROVIDER_NAME), PASSWORD.toCharArray())
        .getEncoded(ASN1Encoding.DER)

private fun newKeystore(vararg aliases: String): KeyStore =
    KeyStore.getInstance("PKCS12", PROVIDER_NAME).apply {
      load(null, null)
      aliases.forEach { setCertificateEntry(it, selfSignedCertificate(it)) }
    }

private fun export(keystore: KeyStore): ByteArray = ByteArrayOutputStream().apply { keystore.store(this, PASSWORD.toCharArray()) }.toByteArray()

private fun selfSignedCertificate(commonName: String): X509Certificate {
  val keyPair = KeyPairGenerator.getInstance("EC", PROVIDER_NAME).apply { initialize(256) }.generateKeyPair()
  val name = X500Name("CN=$commonName")
  val now = Instant.now()
  val certificate =
      JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now.toEpochMilli()), Date.from(now), Date.from(now.plus(1, DAYS)), name, keyPair.public)
          .build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(PROVIDER_NAME).build(keyPair.private))

  return JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificate)
}
