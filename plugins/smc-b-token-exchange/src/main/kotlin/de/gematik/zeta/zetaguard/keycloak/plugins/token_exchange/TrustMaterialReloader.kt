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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_TRUSTSTORE_RELOAD_ENABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_TRUSTSTORE_RELOAD_INTERVAL
import de.gematik.zeta.zetaguard.keycloak.commons.server.TRUSTSTORE_RELOAD_TASK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDateTimePeriod
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDuration
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import java.time.Duration
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory

private val TRUSTSTORE_RELOAD_ENABLED = System.getenv(ENV_TRUSTSTORE_RELOAD_ENABLED)?.toBooleanStrictOrNull() ?: true
private val TRUSTSTORE_RELOAD_INTERVAL = System.getenv(ENV_TRUSTSTORE_RELOAD_INTERVAL) ?: "PT1H"
private val truststoreReloadInterval = TRUSTSTORE_RELOAD_INTERVAL.toDateTimePeriod()

/** How long to wait before confirming a detected change. Generous next to the millisecond window it guards against. */
private val SETTLE_DELAY = Duration.ofSeconds(2)

/**
 * Periodically picks up trust material that the provisioning processor has rewritten, without a Keycloak restart.
 *
 * The task runs node-locally rather than as a cluster singleton, which is what we want: the trust material lives in a
 * volume owned by the pod, so every pod refreshes its own copy. The first check happens one interval after startup,
 * which is what Keycloak's timer SPI offers — it has no way to express a separate initial delay.
 */
internal fun scheduleTrustMaterialReload(sessionFactory: KeycloakSessionFactory, current: () -> TrustMaterial, publish: (TrustMaterial) -> Unit) {
  if (!TRUSTSTORE_RELOAD_ENABLED) {
    logger.info("⏸️ Truststore reload disabled via $ENV_TRUSTSTORE_RELOAD_ENABLED, trust material is only read at startup")

    return
  }

  val intervalMillis = truststoreReloadInterval.toDuration().toMillis()

  // toDateTimePeriod/toDuration silently drop days and larger units, so »P1D« arrives here as zero. Refusing to
  // schedule beats handing that to java.util.Timer, which answers a non-positive period by killing provider startup.
  if (intervalMillis <= 0) {
    logger.error("⚠️ $ENV_TRUSTSTORE_RELOAD_INTERVAL »$TRUSTSTORE_RELOAD_INTERVAL« is not a positive duration of hours or less, truststore reload is off")

    return
  }

  logger.info("⏳ Checking the truststores for changes every $truststoreReloadInterval")

  val timerProviderFactory = sessionFactory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

  KeycloakModelUtils.runJobInTransaction(sessionFactory) { session ->
    timerProviderFactory.create(session).schedule({ safely { reloadTrustMaterial(current, publish) } }, intervalMillis, TRUSTSTORE_RELOAD_TASK_ID)
  }
}

/**
 * Runs [block] and lets nothing escape.
 *
 * Keycloak schedules every task of a node on one shared `java.util.Timer`, and that timer is gone for good after a
 * single uncaught exception — it would take the client expiration task down with it.
 */
private fun safely(block: () -> Unit) =
    try {
      block()
    } catch (e: Exception) {
      logger.error("⚠️ Truststore reload failed unexpectedly, keeping the material currently in use", e)
    }

/**
 * One reload attempt: compare, confirm, load, publish.
 *
 * The comparison is a digest over the file bytes, so the common case — nothing changed — costs one read of roughly 4 MB
 * and parses nothing. Only a digest that actually moved is worth putting the ~2000 certificates of the TPM truststore
 * through the parser.
 *
 * Every rejection path keeps the material currently in use — an unreadable file must never leave the token exchange
 * without trust anchors. Since the publish is a single reference swap and requests read that reference once, in-flight
 * token exchanges finish against the material they started with.
 */
internal fun reloadTrustMaterial(
    current: () -> TrustMaterial,
    publish: (TrustMaterial) -> Unit,
    digest: () -> String? = ::trustMaterialDigest,
    load: () -> TrustMaterial? = ::loadTrustMaterial,
    settle: () -> Unit = { Thread.sleep(SETTLE_DELAY.toMillis()) },
) {
  val inUse = current()
  val candidate = digest() ?: return

  if (candidate == inUse.digest) return

  // No file is ever seen half-written — the processor publishes each result with its own rename, and a rename is
  // atomic. What a reader can catch is a run *between* two of those renames: a new keystore next to the meta file of
  // the previous run, which would hide a freshly revoked CA. Confirming the digest after a short pause rules that out:
  // a run in progress does not hold still, a finished one does. Only reached when something changed, so at most once
  // per provisioning run.
  settle()

  val confirmation = load() ?: return

  if (confirmation.digest != candidate) {
    logger.warn("⚠️ Trust material changed while being read, skipping this reload and retrying at the next interval")

    return
  }

  publish(confirmation)

  logger.info("🔄 Reloaded trust material (${confirmation.describe()})${describeAliasChanges(inUse, confirmation)}")

  if (confirmation.aliasesWithoutMeta.isNotEmpty()) {
    logger.warn("⚠️ No meta entry for ${confirmation.aliasesWithoutMeta}, the revocation check fails open for those")
  }
}

/** Digest of the trust files on disk, turning any failure into `null` so the caller keeps what it already has. */
private fun trustMaterialDigest(): String? = attempt { TrustMaterial.digest() }

/** Reads and parses the trust files, turning any failure into `null` so the caller keeps what it already has. */
private fun loadTrustMaterial(): TrustMaterial? = attempt { TrustMaterial.load() }

private fun <T> attempt(block: () -> T): T? =
    try {
      block()
    } catch (e: Exception) {
      logger.warn("⚠️ Could not read the truststores, keeping the material currently in use: ${e.message}")

      null
    }

/** Which CAs appeared and disappeared — a security-relevant change, so it belongs in the log in readable form. */
private fun describeAliasChanges(previous: TrustMaterial, candidate: TrustMaterial): String =
    listOf(
            TrustMaterial.SMCB to (previous.smcb.aliases() to candidate.smcb.aliases()),
            TrustMaterial.TPM to (previous.tpm.aliases() to candidate.tpm.aliases()),
            TrustMaterial.OCSP to ((previous.ocsp?.aliases() ?: emptySet()) to (candidate.ocsp?.aliases() ?: emptySet())),
        )
        .mapNotNull { (name, aliases) ->
          val (before, after) = aliases
          val added = after - before
          val removed = before - after

          if (added.isEmpty() && removed.isEmpty()) null else "$name added=$added removed=$removed"
        }
        .let { if (it.isEmpty()) "" else ": ${it.joinToString("; ")}" }
