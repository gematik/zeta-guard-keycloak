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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME

object SecurityProviderUtil {
  private var initialized = false

  fun setupSecurityProviders() {
    if (!initialized) {
      initialized = true
      setupHSMProxyProvider()
      setupBouncyCastleProvider()
    }
  }

  fun setupHSMProxyProvider() {
    Security.addProvider(HsmProxyProvider())
  }

  private fun setupBouncyCastleProvider() {
    val indexOfBC1 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }

    when (indexOfBC1) {
      0 -> {
        logger.info("☑️ BouncyCastle is set as default security provider")
        return
      }

      -1 -> {
        logger.info("BouncyCastle not found in list")
      }

      else -> {
        logger.info("BouncyCastle found in list, but is not the default security provider")
        Security.removeProvider(PROVIDER_NAME)
      }
    }

    val indexOfBC2 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }
    check(indexOfBC2 < 0) { "💣 BC provider still present in list!" }

    logger.info("🔐 Setting BouncyCastle as default security provider")

    Security.insertProviderAt(BouncyCastleProvider(), 1)

    val indexOfBC3 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }
    check(indexOfBC3 == 0) { "💣 BC provider is still not the default security provider!" }
  }
}
