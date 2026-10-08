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
package de.gematik.zeta.zetaguard.keycloak.proxy

import net.bytebuddy.ByteBuddy
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy
import net.bytebuddy.implementation.MethodDelegation
import net.bytebuddy.matcher.ElementMatchers.any

inline fun <reified T> createProxy(delegate: T, augmenter: MethodAugmenter<T>): T {
  val targetClass = T::class.java
  val interceptor = DelegatingInterceptor(delegate, augmenter)

  return ByteBuddy()
      .subclass(targetClass)
      .method(any()) // Catch every call to handle it in our logic
      .intercept(MethodDelegation.to(interceptor))
      .make()
      .load(targetClass.classLoader, ClassLoadingStrategy.Default.INJECTION)
      .getLoaded()
      .getDeclaredConstructor()
      .newInstance()
}
