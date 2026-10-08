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
package de.gematik.zeta.zetaguard.keycloak.pkcs12

import com.fasterxml.jackson.annotation.JsonProperty
import java.io.InputStream
import java.security.cert.X509Certificate
import java.util.Date
import org.keycloak.util.JsonSerialization

class KeystoreMetaService(storeStream: InputStream, password: String, metaStream: InputStream) : KeystoreService(storeStream, password) {
  private val meta: Map<String, KeystoreMeta> by lazy {
    metaStream.let { stream ->
      JsonSerialization.mapper.readerForListOf(KeystoreMeta::class.java).readValue<List<KeystoreMeta>>(stream).associateBy {
        it.friendlyName.uppercase()
      }
    }
  }

  /**
   * Aliases held by the keystore for which the meta file carries no entry.
   *
   * Their revocation state cannot be determined: [getRevokedSince] returns `null` for an unknown alias and therefore
   * fails open. Some entries legitimately have no meta — a leaf certificate, for instance — so this is a diagnostic to
   * surface, not a reason to reject the keystore.
   */
  fun aliasesWithoutMeta(): Set<String> = aliases() - meta.keys

  fun getTsp(certificate: X509Certificate): String? = getAlias(certificate)?.let { meta[it]?.tspName }

  fun getRevokedSince(certificate: X509Certificate): Date? = getAlias(certificate)?.let { meta[it]?.revokedSince }

  private fun getAlias(certificate: X509Certificate): String? = aliasBySubject[certificate.subjectX500Principal]

  private data class KeystoreMeta(
      @param:JsonProperty("friendlyName") val friendlyName: String,
      @param:JsonProperty("tspName") val tspName: String,
      @param:JsonProperty("revokedSince") val revokedSince: Date?,
  )
}
