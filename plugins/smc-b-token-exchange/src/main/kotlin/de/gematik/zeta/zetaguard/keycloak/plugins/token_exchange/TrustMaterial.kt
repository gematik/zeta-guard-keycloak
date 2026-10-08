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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_OCSP_KEYSTORE_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_OCSP_KEYSTORE_META_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_OCSP_KEYSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SMCB_KEYSTORE_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SMCB_KEYSTORE_META_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SMCB_KEYSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_TPM_KEYSTORE_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_TPM_KEYSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.server.safeGetenv
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreMetaService
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import java.io.File
import java.lang.System.getenv

/**
 * Where the trust material lives and how to unlock it.
 *
 * Separated from [TrustMaterial] so a test can point at a temp directory instead of having to manipulate the process
 * environment. Production always builds this from [fromEnv].
 */
internal data class TrustMaterialLocations(
    val smcbKeystore: String,
    val smcbMeta: String,
    val smcbPassword: String,
    val tpmKeystore: String,
    val tpmPassword: String,
    val ocsp: Ocsp?,
) {
  /** OCSP is optional and only usable when keystore, meta file and password are all configured. */
  internal data class Ocsp(val keystore: String, val meta: String, val password: String)

  internal companion object {
    fun fromEnv() =
        TrustMaterialLocations(
            smcbKeystore = safeGetenv(ENV_SMCB_KEYSTORE_LOCATION),
            smcbMeta = safeGetenv(ENV_SMCB_KEYSTORE_META_LOCATION),
            smcbPassword = safeGetenv(ENV_SMCB_KEYSTORE_PASSWORD),
            tpmKeystore = safeGetenv(ENV_TPM_KEYSTORE_LOCATION),
            tpmPassword = safeGetenv(ENV_TPM_KEYSTORE_PASSWORD),
            ocsp =
                getenv(ENV_OCSP_KEYSTORE_LOCATION)?.let { keystore ->
                  getenv(ENV_OCSP_KEYSTORE_META_LOCATION)?.let { meta ->
                    getenv(ENV_OCSP_KEYSTORE_PASSWORD)?.let { password -> Ocsp(keystore, meta, password) }
                  }
                },
        )
  }
}

/**
 * An immutable snapshot of all truststores used by the token exchange.
 *
 * The three truststores are held together on purpose. They are published as a single reference (see
 * [ZetaGuardTokenExchangeProviderFactory.trustMaterial]), so a request can never mix a freshly loaded SMC-B truststore
 * with a stale TPM one — which three independently swapped fields would allow.
 */
internal class TrustMaterial(
    val smcb: KeystoreMetaService,
    val tpm: KeystoreService,
    val ocsp: KeystoreMetaService?,
    /**
     * SHA-256 over the raw bytes of exactly the files this snapshot was parsed from — see [TrustFiles.digest].
     *
     * Because hash and parse come from the same read, the two can never describe different states of the directory.
     */
    val digest: String,
) {

  init {
    // Parse everything now, so a corrupt file fails while loading rather than inside a later token exchange. The
    // keystore services only capture their input in the constructor and parse on first use, so something has to touch
    // them; aliasesWithoutMeta pulls the PKCS12 and the meta JSON through the parser in one go.
    tpm.aliases()
    smcb.aliasesWithoutMeta()
    ocsp?.aliasesWithoutMeta()
  }

  /**
   * Keystore aliases whose revocation state cannot be determined, keyed by truststore.
   *
   * Purely diagnostic — see [KeystoreMetaService.aliasesWithoutMeta]. Deliberately not a reason to reject material: an
   * entry without meta can be perfectly legitimate, and the reload guards against half-published runs differently.
   */
  val aliasesWithoutMeta: Map<String, Set<String>> =
      mapOf(SMCB to smcb.aliasesWithoutMeta(), OCSP to (ocsp?.aliasesWithoutMeta() ?: emptySet())).filterValues { it.isNotEmpty() }

  /** Alias counts per truststore, for logging. */
  fun describe() = "$SMCB=${smcb.aliases().size}, $TPM=${tpm.aliases().size}, $OCSP=${ocsp?.aliases()?.size ?: 0}"

  internal companion object {
    const val SMCB = "smcb"
    const val TPM = "tpm"
    const val OCSP = "ocsp"

    /** Reads and parses all truststores. Throws if a file is missing, unreadable or unparsable. */
    fun load(locations: TrustMaterialLocations = TrustMaterialLocations.fromEnv()): TrustMaterial =
        TrustFiles.read(locations).let { files ->
          TrustMaterial(
              KeystoreMetaService(files.smcbKeystore.inputStream(), locations.smcbPassword, files.smcbMeta.inputStream()),
              KeystoreService(files.tpmKeystore.inputStream(), locations.tpmPassword),
              files.ocsp?.let { KeystoreMetaService(it.keystore.inputStream(), it.password, it.meta.inputStream()) },
              files.digest,
          )
        }

    /**
     * Digest of the trust files as they are right now, without parsing them.
     *
     * This is what the reload compares on every tick. Reading ~4 MB is cheap; parsing the ~2000 certificates of the TPM
     * truststore is not, and there is no reason to do it before knowing that anything changed at all.
     */
    fun digest(locations: TrustMaterialLocations = TrustMaterialLocations.fromEnv()): String = TrustFiles.read(locations).digest
  }
}

/** The raw bytes of every trust file, read in one pass, together with the digest over exactly those bytes. */
private class TrustFiles(
    val smcbKeystore: ByteArray,
    val smcbMeta: ByteArray,
    val tpmKeystore: ByteArray,
    val ocsp: OcspFiles?,
) {
  class OcspFiles(val keystore: ByteArray, val meta: ByteArray, val password: String)

  /**
   * Digest over the file *bytes*, not over the certificates parsed from them.
   *
   * Two consequences worth knowing. It sees every change, including one confined to a truststore whose entries carry no
   * `friendlyName` and are therefore invisible to `KeyStore.aliases()` — the TPM truststore is exactly that. And it also
   * reports a change when the provisioning processor re-exports identical certificates, because `openssl pkcs12 -export`
   * picks a fresh salt every run: expect one reload per provisioning run, not one per changed certificate.
   *
   * Each part is fed in as role, byte count and content, so no concatenation of two files can collide with another.
   */
  val digest: String =
      toHash(
              *listOf(
                      TrustMaterial.SMCB to smcbKeystore,
                      "${TrustMaterial.SMCB}-meta" to smcbMeta,
                      TrustMaterial.TPM to tpmKeystore,
                      TrustMaterial.OCSP to ocsp?.keystore,
                      "${TrustMaterial.OCSP}-meta" to ocsp?.meta,
                  )
                  .flatMap { (role, bytes) ->
                    listOf(role.toByteArray(), (bytes?.size ?: -1).toString().toByteArray(), bytes ?: ByteArray(0))
                  }
                  .toTypedArray()
          )
          .toBase64()

  companion object {
    fun read(locations: TrustMaterialLocations) =
        TrustFiles(
            readTrustFile(locations.smcbKeystore),
            readTrustFile(locations.smcbMeta),
            readTrustFile(locations.tpmKeystore),
            locations.ocsp?.let { OcspFiles(readTrustFile(it.keystore), readTrustFile(it.meta), it.password) },
        )

    private fun readTrustFile(path: String): ByteArray {
      val file = File(path)

      check(file.exists() && file.isFile && file.length() > 0) { "No valid data file found using path »$path«" }

      return file.readBytes()
    }
  }
}
