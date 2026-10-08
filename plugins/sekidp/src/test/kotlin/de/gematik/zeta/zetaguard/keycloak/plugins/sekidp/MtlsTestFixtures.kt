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

import io.mockk.every
import io.mockk.mockk
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.Config

/** Keycloak registers BC at start-up (SecurityProviderUtil); reading a PKCS12 keystore needs it in the test JVM too. */
internal fun registerBouncyCastle() {
  if (Security.getProvider(PROVIDER_NAME) == null) Security.addProvider(BouncyCastleProvider())
}

/** SPI scope holding the mTLS keys the SekIDP provider factory reads. */
internal fun mtlsScope(enabled: Boolean, keystoreLocation: String? = null, keystorePassword: String? = null): Config.Scope {
  val scope = mockk<Config.Scope>()
  every { scope.getBoolean(SekIDPIdentityProviderFactory.CONFIG_MTLS_ENABLED, false) } returns enabled
  every { scope.get(SekIDPIdentityProviderFactory.CONFIG_MTLS_KEYSTORE_LOCATION) } returns keystoreLocation
  every { scope.get(SekIDPIdentityProviderFactory.CONFIG_MTLS_KEYSTORE_PASSWORD) } returns keystorePassword

  return scope
}
