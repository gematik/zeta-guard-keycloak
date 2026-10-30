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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.mockk.mockk
import org.keycloak.provider.KeycloakDeploymentInfo
import org.keycloak.provider.ProviderManager
import org.keycloak.services.DefaultKeycloakSessionFactory
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProviderFactory

class ZetaGuardOIDCClientRegistrationProviderFactoryTest : FunSpec() {
  init {
    test("the factory claims the built-in openid-connect registration provider id") {
      val factory = ZetaGuardOIDCClientRegistrationProviderFactory()

      // The registration endpoint resolves its provider by the last path segment, so any other id would 404 the endpoint for everyone.
      factory.id shouldBe OIDCClientRegistrationProviderFactory.ID
      factory.id shouldBe "openid-connect"

      factory.create(mockk(relaxed = true)).shouldBeInstanceOf<ZetaGuardOIDCClientRegistrationProvider>()
    }

    test("the factory replaces the built-in provider it shadows") {
      val ours = ZetaGuardOIDCClientRegistrationProviderFactory()
      val builtIn = OIDCClientRegistrationProviderFactory()

      ours.order() shouldBeGreaterThan builtIn.order()
      DefaultKeycloakSessionFactory.isInternal(ours) shouldBe false
      DefaultKeycloakSessionFactory.isInternal(builtIn) shouldBe true

      // At equal order Keycloak keeps the factory outside its own packages, whichever one it happens to load first.
      val providerManager = ProviderManager(KeycloakDeploymentInfo.create(), javaClass.classLoader)
      providerManager.compareFactories(builtIn, ours) shouldBeSameInstanceAs ours
      providerManager.compareFactories(ours, builtIn) shouldBeSameInstanceAs ours
    }
  }
}
