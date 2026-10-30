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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.Security
import java.util.Properties
import org.testcontainers.containers.ComposeContainer

/** key_id must end with .p256 — hsm_sim derives the EC key via HKDF using this suffix. */
private const val KEY_ID = "zeta-guard-keycloak-tls-es256-v1.p256"
private const val HSM_SIM_SERVICE = "hsm-sim"
private const val HSM_SIM_PORT = 50051

/**
 * JCA-SPI smoke test for `HSMPROXY` KeyStore against a real `hsm_sim` — **no Keycloak involved**. Runs in the surefire JVM, registers
 * [HsmProxyProvider] manually, and exercises gRPC + `engineLoad` + cert retrieval. Keycloak-side TLS wiring is not covered here; see
 * `keycloak-upgrade-26.6.3.md` for the deferred TLS-termination IT.
 *
 * Starts hsm_sim via Docker Compose; override with `-Dhsm.sim.endpoint=host:port` to reuse a running instance.
 */
class HsmProxyKeycloakFactoryIT : FunSpec() {

  private lateinit var hsmEndpoint: String

  init {
    beforeSpec {
      Security.addProvider(HsmProxyProvider())
      val externalEndpoint = System.getProperty("hsm.sim.endpoint")
      if (externalEndpoint != null) {
        hsmEndpoint = externalEndpoint
      } else {
        hsm.start()
        hsmEndpoint = "${hsm.getServiceHost(HSM_SIM_SERVICE, HSM_SIM_PORT)}:${hsm.getServicePort(HSM_SIM_SERVICE, HSM_SIM_PORT)}"
      }
    }

    afterSpec {
      Security.removeProvider(HsmProxyProvider.NAME)
      if (::hsmEndpoint.isInitialized) hsm.stop()
    }

    test("HSMPROXY KeyStore loads TLS certificate from hsm_sim") {
      val props =
          Properties().apply {
            setProperty("hsm.endpoint", hsmEndpoint)
            setProperty("keys.tls.key_id", KEY_ID)
          }
      val baos = ByteArrayOutputStream()
      props.store(baos, null)

      val keyStore = KeyStore.getInstance(HsmProxyProvider.KEYSTORE_TYPE)
      keyStore.load(baos.toByteArray().inputStream(), null)

      keyStore.containsAlias("tls") shouldBe true
      keyStore.getCertificate("tls") shouldNotBe null
    }
  }

  companion object {
    private val composeFile = HsmProxyKeycloakFactoryIT::class.java.getResource("/docker-compose-hsm-sim-it.yml")!!.toURI().let { java.io.File(it) }

    private val hsm = ComposeContainer(composeFile).withExposedService(HSM_SIM_SERVICE, HSM_SIM_PORT)
  }
}
