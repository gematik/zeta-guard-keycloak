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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.commons.server.MediaTypes
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakTransactionManager

class ProblemOnErrorTest :
    StringSpec({
      lateinit var transactionManager: KeycloakTransactionManager
      lateinit var session: KeycloakSession

      beforeTest {
        transactionManager = mockk(relaxed = true)
        session = mockk { every { this@mockk.transactionManager } returns transactionManager }
      }

      "a regular response passes through untouched" {
        val ok = Response.ok().build()

        session.problemOnError { ok } shouldBeSameInstanceAs ok

        verify(exactly = 0) { transactionManager.setRollbackOnly() }
      }

      "an unexpected exception becomes a 500 problem and rolls back" {
        val response = session.problemOnError { throw IllegalStateException("boom") }

        response.status shouldBe 500
        response.mediaType.toString() shouldBe MediaTypes.PROBLEM_JSON
        verify { transactionManager.setRollbackOnly() }
      }

      "a WebApplicationException is an intended response and is rethrown" {
        shouldThrow<NotFoundException> { session.problemOnError { throw NotFoundException() } }

        verify(exactly = 0) { transactionManager.setRollbackOnly() }
      }
    })
