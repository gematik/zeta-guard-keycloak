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
package de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.stream.Stream
import org.keycloak.common.util.KeyUtils
import org.keycloak.component.ComponentModel
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyType
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.keys.KeyProvider
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(HsmTokenSigningKeyProvider::class.java)

/** [KeyProvider] exposing an HSM-backed ES256 key. Private key never leaves the HSM. */
class HsmTokenSigningKeyProvider(private val model: ComponentModel, keyStoreLoader: (endpoint: String, keyId: String) -> KeyStore) : KeyProvider {

  private val keyWrapper: KeyWrapper = buildKeyWrapper(model, keyStoreLoader)

  override fun getKeysStream(): Stream<KeyWrapper> = Stream.of(keyWrapper)

  override fun close() = Unit

  companion object {
    private fun buildKeyWrapper(model: ComponentModel, keyStoreLoader: (String, String) -> KeyStore): KeyWrapper {
      val endpoint = model["endpoint"] ?: throw RuntimeException("HSM endpoint not set in ComponentModel")
      val keyId = model["keyId"] ?: throw RuntimeException("HSM keyId not set in ComponentModel")

      log.debug("Loading HSM token signing key (endpoint={}, keyId={})", endpoint, keyId)

      val keyStore = keyStoreLoader(endpoint, keyId)
      val privateKey = keyStore.getKey(TOKEN_KEY_ALIAS, null) as PrivateKey
      val cert = keyStore.getCertificate(TOKEN_KEY_ALIAS) as X509Certificate
      val publicKey = cert.publicKey

      val status = KeyStatus.from(model["active", true], model["enabled", true])

      return KeyWrapper().apply {
        providerId = model.id
        providerPriority = model["priority", 0L]
        kid = KeyUtils.createKeyId(publicKey)
        algorithm = Algorithm.ES256
        type = KeyType.EC
        use = KeyUse.SIG
        this.status = status
        setPrivateKey(privateKey)
        setPublicKey(publicKey)
        certificate = cert
        curve = "P-256"
      }
    }
  }
}
