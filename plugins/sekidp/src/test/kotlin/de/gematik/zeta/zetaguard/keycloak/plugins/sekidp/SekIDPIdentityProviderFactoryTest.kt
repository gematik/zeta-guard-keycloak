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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import java.io.FileNotFoundException
import org.keycloak.Config

class SekIDPIdentityProviderFactoryTest : ZetaGuardFunSpec() {
  init {
    test("no certificate before init, so the entity statement stays mTLS-free") {
      SekIDPIdentityProviderFactory().mtlsConfig()?.clientCertificate shouldBe null
    }

    test("mTLS switched off leaves the entity statement without a certificate") {
      val factory = SekIDPIdentityProviderFactory().apply { init(mtlsScope(enabled = false)) }

      factory.mtlsConfig()?.clientCertificate shouldBe null
      factory.close()
    }

    test("the keystore is read from the documented SPI location") {
      val scope = mtlsScope(enabled = true, keystoreLocation = "/does/not/exist.p12", keystorePassword = "irrelevant")

      shouldThrow<FileNotFoundException> { SekIDPIdentityProviderFactory.resolveMtlsConfig(scope)?.keystore }.message shouldContain "/does/not/exist.p12"
    }

    test("the mTLS switch without a keystore location fails closed instead of downgrading") {
      val scope = mtlsScope(enabled = true, keystoreLocation = null, keystorePassword = "irrelevant")

      shouldThrow<IllegalArgumentException> { SekIDPIdentityProviderFactory().init(scope) }.message shouldContain "mtlsKeystoreLocation"
    }

    test("the mTLS switch without a keystore password fails closed instead of downgrading") {
      val scope = mtlsScope(enabled = true, keystoreLocation = "/etc/sekidp/client.p12", keystorePassword = null)

      shouldThrow<IllegalArgumentException> { SekIDPIdentityProviderFactory().init(scope) }.message shouldContain "mtlsKeystorePassword"
    }

    test("a complete mTLS config resolves the generated keystore into a published certificate") {
      val scope = mtlsScope(enabled = true, keystoreLocation = CLIENT_KEYSTORE, keystorePassword = CLIENT_KEYSTORE_PASSWORD)
      val factory = SekIDPIdentityProviderFactory().apply { init(scope) }

      factory.mtlsConfig()?.clientCertificate.shouldNotBeNull().subjectX500Principal.name shouldContain "sekidp-mtls-test-client"
      factory.close()
    }

    test("close without init does not fail") {
      shouldNotThrowAny { SekIDPIdentityProviderFactory().close() }
    }
  }
}

/** SPI scope holding the mTLS keys the SekIDP provider factory reads. */
private fun mtlsScope(enabled: Boolean, keystoreLocation: String? = null, keystorePassword: String? = null): Config.Scope {
  val scope = mockk<Config.Scope>()
  every { scope.getBoolean(SekIDPIdentityProviderFactory.CONFIG_MTLS_ENABLED, false) } returns enabled
  every { scope.get(SekIDPIdentityProviderFactory.CONFIG_MTLS_KEYSTORE_LOCATION) } returns keystoreLocation
  every { scope.get(SekIDPIdentityProviderFactory.CONFIG_MTLS_KEYSTORE_PASSWORD) } returns keystorePassword

  return scope
}
