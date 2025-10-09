/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import java.util.concurrent.TimeUnit
import org.rnorth.ducttape.TimeoutException
import org.rnorth.ducttape.unreliables.Unreliables
import org.testcontainers.containers.ContainerLaunchException
import org.testcontainers.containers.wait.strategy.AbstractWaitStrategy

/** Wait strategy that waits for the container to terminate. */
object WaitForTerminationStrategy : AbstractWaitStrategy() {
    override fun waitUntilReady() {
        try {
            Unreliables.retryUntilTrue(startupTimeout.seconds.toInt(), TimeUnit.SECONDS) {
                !waitStrategyTarget.isRunning
            }
        } catch (_: TimeoutException) {
            throw ContainerLaunchException("Timed out waiting for container to terminate.")
        }
    }
}
