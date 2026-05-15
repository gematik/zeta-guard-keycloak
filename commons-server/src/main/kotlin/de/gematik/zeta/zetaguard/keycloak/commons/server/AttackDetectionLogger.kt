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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import org.jboss.logging.Logger
import org.jboss.logging.MDC

enum class CapecAttackMechanics(val id: Int, val attackName: String) {
    AUTHENTICATION_BYPASS(115, "Authentication Bypass")
}

private const val ATTACK_DETECTION_CAPEC_ID = "attackDetection.capecId"

private const val ATTACK_DETECTION_CAPEC_NAME = "attackDetection.capecName"

private const val ATTACK_DETECTION_DETAIL = "attackDetection.detail"

private const val ATTACK_DETECTION_ORIGIN = "attackDetection.origin"

private const val ATTACK_DETECTION_CLIENT_IP = "attackDetection.clientIP"

object AttackDetectionLogger {
  
  private val logger = Logger.getLogger(AttackDetectionLogger::class.java)

  fun warnWithMDC(cause: Throwable, attack: CapecAttackMechanics, clientIP: String) {
    MDC.put(ATTACK_DETECTION_CAPEC_ID, attack.id)
    MDC.put(ATTACK_DETECTION_CAPEC_NAME, attack.attackName)
    MDC.put(ATTACK_DETECTION_DETAIL, cause.message ?: "no detail available")
    MDC.put(ATTACK_DETECTION_ORIGIN, cause.stackTrace[0] ?: "no detail available")
    MDC.put(ATTACK_DETECTION_CLIENT_IP, clientIP)
    try {
      logger.warn("Möglicher Angriff detektiert")
    } finally {
      MDC.remove(ATTACK_DETECTION_CAPEC_ID)
      MDC.remove(ATTACK_DETECTION_CAPEC_NAME)
      MDC.remove(ATTACK_DETECTION_DETAIL)
      MDC.remove(ATTACK_DETECTION_ORIGIN)
      MDC.remove(ATTACK_DETECTION_CLIENT_IP)
    }
  }
}
