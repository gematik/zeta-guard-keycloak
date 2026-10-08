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
package de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk

/**
 * The reload has one job it must never get wrong: the token exchange must always hold usable trust anchors.
 *
 * So every path that is not "the digest moved and the material read afterwards still matches it" has to leave the
 * material in use untouched.
 */
class TrustMaterialReloaderTest : FunSpec() {
  init {
    test("An unchanged digest publishes nothing") {
      val published = mutableListOf<TrustMaterial>()

      reload(material("same"), published, digests = listOf("same"))

      published shouldBe emptyList()
    }

    test("Nothing is read or parsed beyond the digest when nothing changed") {
      var loaded = false
      var settled = false

      reload(material("same"), mutableListOf(), digests = listOf("same"), onLoad = { loaded = true }, onSettle = { settled = true })

      loaded shouldBe false
      settled shouldBe false
    }

    test("Changed material is published when the load confirms the digest") {
      val confirmed = material("new")
      val published = mutableListOf<TrustMaterial>()

      reload(material("old"), published, digests = listOf("new"), loads = listOf(confirmed))

      published shouldBe listOf(confirmed)
    }

    test("Material that changes between digest and load is not published") {
      val published = mutableListOf<TrustMaterial>()

      // A provisioning run caught midway: what was loaded is not what was measured, so neither is trustworthy.
      reload(material("old"), published, digests = listOf("half-published"), loads = listOf(material("finished")))

      published shouldBe emptyList()
    }

    test("An unreadable truststore leaves the material in use in place") {
      val published = mutableListOf<TrustMaterial>()

      reload(material("old"), published, digests = listOf(null))

      published shouldBe emptyList()
    }

    test("A truststore that becomes unreadable after the digest leaves the material in use in place") {
      val published = mutableListOf<TrustMaterial>()

      reload(material("old"), published, digests = listOf("new"), loads = listOf(null))

      published shouldBe emptyList()
    }
  }
}

/** Only the digest drives the decision; everything else is logging, so a relaxed mock is enough. */
private fun material(digest: String): TrustMaterial = mockk(relaxed = true) { every { this@mockk.digest } returns digest }

private fun reload(
    inUse: TrustMaterial,
    published: MutableList<TrustMaterial>,
    digests: List<String?>,
    loads: List<TrustMaterial?> = emptyList(),
    onSettle: () -> Unit = {},
    onLoad: () -> Unit = {},
) {
  val remainingDigests = digests.toMutableList()
  val remainingLoads = loads.toMutableList()

  reloadTrustMaterial(
      current = { inUse },
      publish = { published += it },
      digest = { remainingDigests.removeFirst() },
      load = {
        onLoad()
        remainingLoads.removeFirst()
      },
      settle = onSettle,
  )
}
