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

package de.gematik.zeta.zetaguard.keycloak.commons.server

import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE

const val ATTRIBUTE_SMCB_CONTEXT = "zetaguard.smcbContext"
const val ATTRIBUTE_CLIENT_ASSESSMENT_DATA = "zetaguard.clientData"

const val ATTRIBUTE_SMCBUSER_CLIENT_IDS = "zetaguard.smcbuser.client_ids"
const val ATTRIBUTE_SMCBUSER_TELEMATIK_ID = "zetaguard.smcbuser.telematik_id"
const val ATTRIBUTE_SMCBUSER_PROFESSION_OID = "zetaguard.smcbuser.profession_oid"
const val ATTRIBUTE_SMCBUSER_NAME = "zetaguard.smcbuser.name"
const val ATTRIBUTE_SMCBUSER_ORGANISATION = "zetaguard.smcbuser.organisation"

const val ATTRIBUTE_ATTESTATION_STATE = "zeta-guard.client.attestation_state"
const val ATTRIBUTE_CREATED_AT = "zeta-guard.client.created_at"

const val CLAIM_CLIENT_SELF_ASSESSMENT = "urn:telematik:client-self-assessment"
const val CLAIM_ACCESS_TOKEN_CLIENT_DATA = "cdat"

const val ZETA_REALM = "zeta-guard"
const val ZETA_CLIENT = "zeta-client"

// https://www.keycloak.org/securing-apps/client-registration
const val KEYCLOAK_CLIENT_REGISTRATION_PATH = "/realms/{realm-name}/clients-registrations/default"
const val OIDC_CLIENT_REGISTRATION_PATH = "/realms/{realm-name}/clients-registrations/openid-connect"

// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_initial_access
const val INITIAL_ACCESS_TOKEN_PATH = "/admin/realms/{realm-name}/clients-initial-access"
const val WELLKNOWN_BASE_PATH = "/realms/{realm-name}/.well-known"
const val USERINFO_PATH = "/realms/{realm-name}/protocol/openid-connect/userinfo"

const val KEYCLOAK_REALM_PATH = "/realms/{realm-name}"

const val ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID = "zeta-smc-b-token-exchange"
const val SMCB_IDENTITY_PROVIDER_ID = "zeta-smc-b-oidc"

const val ENV_SMCB_KEYSTORE_LOCATION = "SMCB_KEYSTORE_LOCATION"
const val ENV_SMCB_KEYSTORE_PASSWORD = "SMCB_KEYSTORE_PASSWORD"

const val ADMIN_EVENTS_PROVIDER_ID = "zeta-guard-admin-events"
const val ENV_GENESIS_HASH = "GENESIS_HASH"

const val NONCE_PROVIDER_ID = "zeta-guard-nonce"
const val NONCE_PATH = "/{realm-name}/$NONCE_PROVIDER_ID"
const val NONCE_FULL_PATH = "/realms$NONCE_PATH"
const val ENV_NONCE_TTL = "NONCE_TTL"

const val WELLKNOWN_PROVIDER_ID = "zeta-guard-well-known"
const val ENV_SERVICE_DOCUMENTATION_URI = "SERVICE_DOCUMENTATION_URL"

const val ENV_MAX_CLIENTS = "SMCB_USER_MAX_CLIENTS"

const val CLIENT_REGISTRATION_POLICY_PROVIDER_ID = "zeta-client-registration-policy"
const val ENV_CLIENT_REGISTRATION_TTL = "CLIENT_REGISTRATION_TTL"
const val ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL = "CLIENT_REGISTRATION_SCHEDULER_INTERVAL"

const val ATTESTATION_STATE_PENDING = "pending_attestation"
const val ATTESTATION_STATE_VALID = "validated_attestation"

const val ACCESSTOKEN_MAPPERPROVIDER_ID = "zeta-guard-accesstoken-mapper"

//  https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_27799
val VALID_GRANT_TYPES = listOf(REFRESH_TOKEN, TOKEN_EXCHANGE_GRANT_TYPE)

/**
 * Gets the message of a [Throwable].
 *
 * @return The message of the [Throwable] or "<unknown eror>" if the message is null.
 */
fun Throwable.message() = message ?: "<unknown eror>"

val logger: Logger = Logger.getLogger("zeta-guard")
