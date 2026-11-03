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

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_FEDERATION_MASTER_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.safeGetenv
import java.io.File
import org.jboss.logging.Logger

private val logger: Logger = Logger.getLogger(FederationMasterConfig::class.java)

/**
 * A_29737: reads the Fedmaster URL from the provisioned `federation-master.json` file.
 *
 * The file is a JSON object `{"fedmasterUrl": "…"}` produced by the provisioning processor.
 */
internal val federationMasterConfig: FederationMasterConfig by lazy { FederationMasterConfig() }

internal class FederationMasterConfig(
  location: String = safeGetenv(ENV_FEDERATION_MASTER_LOCATION),
) {

  val fedmasterUrl: String = requireNotNull(resolveFedmasterUrl(location)) {
    "Fedmaster URL could not be resolved — check $ENV_FEDERATION_MASTER_LOCATION and the file »$location«"
  }
}

internal data class FederationMasterFile
@java.beans.ConstructorProperties("fedmasterUrl")
constructor(@field:com.fasterxml.jackson.annotation.JsonProperty("fedmasterUrl") val fedmasterUrl: String?)

internal fun resolveFedmasterUrl(location: String): String? {
  val file = File(location)
  if (!file.isFile) {
    logger.errorf("Federation master file »%s« does not exist", location)
    return null
  }

  val parsed =
    try {
      file.inputStream().use { it.toObject<FederationMasterFile>() }
    } catch (e: Exception) {
      logger.errorf(e, "Federation master file »%s« could not be parsed", location)
      return null
    }

  val uri = parsed.fedmasterUrl?.trimEnd('/')
  if (uri.isNullOrBlank()) {
    logger.errorf("Federation master file »%s« has no »fedmasterUrl« field", location)
    return null
  }

  logger.infof("Resolved Fedmaster URL from provisioned file: »%s«", uri)
  return uri
}
