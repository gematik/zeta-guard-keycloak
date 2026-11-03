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

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.keycloak.cookie.CookieSpi
import org.keycloak.cookie.DefaultCookieProviderFactory
import org.keycloak.provider.ProviderFactory
import org.keycloak.services.DefaultKeycloakSessionFactory

class ZetaCookieProviderFactoryTest : ZetaGuardFunSpec() {

  init {
    test("registers under its own id, distinct from Keycloak's default") {
      ZetaCookieProviderFactory().id shouldNotBe DefaultCookieProviderFactory().id
    }

    test("is what Keycloak picks for the cookie SPI when it stands next to the default provider") {
      // Keycloak's rule: the highest order above 0 wins.
      val factories = mapOf<String, ProviderFactory<*>>("default" to DefaultCookieProviderFactory(), "zeta-guard-cookie" to ZetaCookieProviderFactory())

      DefaultKeycloakSessionFactory.resolveDefaultProvider(factories, CookieSpi()) shouldBe "zeta-guard-cookie"
    }
  }
}
