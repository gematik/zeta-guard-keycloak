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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import java.time.Instant

class ResourceServerCertificateValidatorTest :
    StringSpec({
      val root = TestCa("Root CA")
      val intermediate = TestCa("Intermediate CA", parent = root)

      "a leaf issued by a trusted root is accepted" {
        val leaf = root.issueLeaf("rs")

        ResourceServerCertificateValidator(setOf(root.certificate)).validate(listOf(leaf)) shouldBeRight leaf
      }

      "a leaf issued by an intermediate is accepted when the chain carries the intermediate" {
        val leaf = intermediate.issueLeaf("rs")

        ResourceServerCertificateValidator(setOf(root.certificate)).validate(intermediate.chainOf(leaf)) shouldBeRight leaf
      }

      "a leaf issued by an intermediate is rejected when neither chain nor truststore carry the intermediate" {
        ResourceServerCertificateValidator(setOf(root.certificate)).validate(listOf(intermediate.issueLeaf("rs"))).shouldBeLeft()
      }

      "an intermediate in the truststore is a trust anchor of its own" {
        val leaf = intermediate.issueLeaf("rs")

        ResourceServerCertificateValidator(setOf(intermediate.certificate)).validate(listOf(leaf)) shouldBeRight leaf
      }

      "a pinned leaf certificate is accepted" {
        val leaf = root.issueLeaf("rs")

        ResourceServerCertificateValidator(setOf(leaf)).validate(listOf(leaf)) shouldBeRight leaf
      }

      "an expired pinned leaf certificate is rejected" {
        val leaf = root.issueLeaf("rs", validFrom = Instant.now().minusSeconds(7200), validUntil = Instant.now().minusSeconds(3600))

        ResourceServerCertificateValidator(setOf(leaf)).validate(listOf(leaf)).shouldBeLeft()
      }

      "a certificate that is not yet valid is rejected" {
        val leaf = root.issueLeaf("rs", validFrom = Instant.now().plusSeconds(3600), validUntil = Instant.now().plusSeconds(7200))

        ResourceServerCertificateValidator(setOf(root.certificate)).validate(listOf(leaf)).shouldBeLeft()
      }

      "an untrusted leaf certificate is rejected" {
        ResourceServerCertificateValidator(setOf(root.certificate)).validate(listOf(TestCa("Other CA").issueLeaf("rs"))).shouldBeLeft()
      }

      "an empty chain is rejected" {
        ResourceServerCertificateValidator(setOf(root.certificate)).validate(emptyList()) shouldBeLeft "No client certificate presented"
      }

      "an empty truststore rejects everything" {
        ResourceServerCertificateValidator(emptySet()).validate(listOf(root.issueLeaf("rs"))) shouldBeLeft
            "No truststore configured for resource server access"
      }

      "the error names the rejected subject" {
        val error = ResourceServerCertificateValidator(setOf(root.certificate)).validate(listOf(TestCa("Other CA").issueLeaf("rogue"))).shouldBeLeft()

        error.startsWith("Client certificate »CN=rogue« is not trusted") shouldBe true
      }
    })
