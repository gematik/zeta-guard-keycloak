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

import org.keycloak.Config
import org.keycloak.cookie.CookieProvider
import org.keycloak.cookie.CookieProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

/** Id of Keycloak's own cookie provider, which [ZetaCookieProvider] wraps. */
private const val DEFAULT_COOKIE_PROVIDER_ID = "default"

/**
 * Replaces Keycloak's cookie provider by registration alone: the cookie SPI runs one provider, and among several
 * factories Keycloak picks the highest [order] above 0, so no `spi-cookie-provider` setting is needed. A deployment
 * can still force `spi-cookie-provider=default`, which then leaves the Redirection Endpoint cookie-bound.
 */
class ZetaCookieProviderFactory : CookieProviderFactory {

  override fun getId() = ZETA_COOKIE_PROVIDER_ID

  override fun order() = ORDER_ABOVE_DEFAULT

  override fun create(session: KeycloakSession): CookieProvider =
      ZetaCookieProvider(session, session.getProvider(CookieProvider::class.java, DEFAULT_COOKIE_PROVIDER_ID))

  override fun init(config: Config.Scope) {
    // no config properties to read
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // this factory does not depend on any other provider.
  }

  override fun close() {
    // no resources held to release
  }

  companion object {
    const val ZETA_COOKIE_PROVIDER_ID = "zeta-guard-cookie"

    /** Keycloak's default provider has order 0; anything above wins the selection. */
    private const val ORDER_ABOVE_DEFAULT = 10
  }
}
