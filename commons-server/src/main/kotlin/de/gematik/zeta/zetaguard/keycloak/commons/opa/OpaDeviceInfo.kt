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
package de.gematik.zeta.zetaguard.keycloak.commons.opa

import de.gematik.zeta.zetaguard.keycloak.client_assertion.AndroidPosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ApplePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Posture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import java.beans.ConstructorProperties

/**
 * Device information taken from the attested client statement, persisted for the OPA-input replay on refresh.
 *
 * Feeds `client_registration_data.device_info` of the policy input (A_28793).
 */
data class OpaDeviceInfo
@ConstructorProperties("os", "osVersion", "deviceModel")
constructor(val os: String?, val osVersion: String?, val deviceModel: String?)

fun Posture.toOpaDeviceInfo(): OpaDeviceInfo =
    when (this) {
      is SoftwarePosture -> OpaDeviceInfo(os = os, osVersion = osVersion, deviceModel = null)
      is TPMPosture -> OpaDeviceInfo(os = os, osVersion = osVersion, deviceModel = null)
      is ApplePosture -> OpaDeviceInfo(os = systemName, osVersion = systemVersion, deviceModel = deviceModel)
      // Interim mapping until the gematik schema names an Android source for os/os_version.
      is AndroidPosture -> OpaDeviceInfo(os = "Android", osVersion = build.version.sdkInit.toString(), deviceModel = build.model)
      else -> OpaDeviceInfo(os = null, osVersion = null, deviceModel = null)
    }
