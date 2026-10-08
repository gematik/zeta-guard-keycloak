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

private const val CLIENT_ID = "auth.client_id"
private const val EVENT_TYPE = "event_type"

private const val CLIENT_OS_NAME = "client_registration.client.os.name"
private const val REGISTRATION_DATETIME = "client_registration.datetime"
private const val REGISTRATION_RESULT = "client_registration.result"

private const val REASON = "zeta-client.reason"

/**
 * Logs security events.
 *
 * @see [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.3.2/#A_25738]
 * @see [https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html]
 */
object SecurityEventLogger {
    private val logger = Logger.getLogger(SecurityEventLogger::class.java)

    fun logEmailChanged(clientId: String) =
        logger.info(
            message = "authn_email_change:$clientId",
            attributes =
                mapOf(
                    CLIENT_ID to clientId,
                    EVENT_TYPE to "authn_email_change",
                ),
        )

    fun logClientRegistered(clientId: String) =
        logger.info(
            message = "authn_client_registered:$clientId",
            attributes =
                mapOf(
                    CLIENT_ID to clientId,
                    EVENT_TYPE to "authn_client_registered",
                ),
        )

    /**
     * Logs failed client registration attempts.
     *
     * @see [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25484-03]
     */
    fun logClientRegistrationFail(clientId: String, reason: String) =
        logger.info(
            message = "authn_client_registration_fail:$clientId",
            attributes =
                mapOf(
                    CLIENT_ID to clientId,
                    EVENT_TYPE to "authn_client_registration_fail",
                    REASON to reason,
                ),
        )

    /**
     * Logs the deletion of a client registration by ZETA Guard, e.g. the eviction of the
     * least-recently-used client after the maximum number of clients per user has been exceeded.
     *
     * @see [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25748-02]
     */
    fun logClientDeleted(clientId: String, reason: String) =
        logger.info(
            message = "authn_client_deleted:$clientId",
            attributes =
                mapOf(
                    CLIENT_ID to clientId,
                    EVENT_TYPE to "authn_client_deleted",
                    REASON to reason,
                ),
        )

    fun logTokenExchanged(
        clientId: String,
        clientOsName: String,
        registrationResult: String,
        registrationTimestamp: Long,
    ) =
        logger.info(
            message = "authn_token_created:$clientId",
            attributes =
                mapOf(
                    CLIENT_ID to clientId,
                    CLIENT_OS_NAME to clientOsName,
                    EVENT_TYPE to "authn_token_created",
                    REGISTRATION_DATETIME to registrationTimestamp,
                    REGISTRATION_RESULT to registrationResult,
                ),
        )

    /**
     * Logs an invalid authorization code intended for a sectoral identity provider.
     *
     * @see [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25484-03]
     */
    fun logInvalidAuthorizationCode(reason: String) =
        logger.info(
            message = "authn_authorization_code_invalid",
            attributes =
                mapOf(
                    EVENT_TYPE to "authn_authorization_code_invalid",
                    REASON to reason,
                ),
        )
}
