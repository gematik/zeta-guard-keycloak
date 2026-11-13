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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons.server

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PLATFORM
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_VERSION
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants.AUTHORIZATION_CODE
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.connections.httpclient.HttpClientSpi

/**
 * Non-persistent attributes
 */
const val ATTRIBUTE_SMCB_CONTEXT = "zetaguard.smcbContext"
const val ATTRIBUTE_MOBILE_OPA_CONTEXT = "zetaguard.mobile.opaContext"

// Epoch seconds at which the session ends: exp of the first refresh token after full authentication (A_25662)
const val ATTRIBUTE_SESSION_END = "zetaguard.session.end"
const val ATTRIBUTE_CLIENT_REGISTRATION_DATA = "zetaguard.client.registration_data"
const val ATTRIBUTE_CLIENT_STATEMENT_DATA = "zetaguard.client.client_statement"
const val ATTRIBUTE_CLIENT_STATEMENT_RAW = "zetaguard.client.client_statement_raw"
const val ATTRIBUTE_REQUESTED_SCOPES = "zetaguard.refresh.requested_scopes"

const val ATTRIBUTE_USER_CREATED_AT = "zetaguard.user.created_at"
const val ATTRIBUTE_USER_LAST_ACCESS = "zetaguard.user.last_access"

// New address of a pending identity-wide email change; takes effect once the OTP sent to it is confirmed.
const val ATTRIBUTE_USER_PENDING_EMAIL = "zetaguard.user.pending_email"

// Attribute keys for the mobile user (KVNR context).
const val ATTRIBUTE_MOBILEUSER_KVNR = "zetaguard.mobileuser.kvnr"
const val ATTRIBUTE_MOBILEUSER_ACR = "zetaguard.mobileuser.acr"
const val ATTRIBUTE_MOBILEUSER_AMR = "zetaguard.mobileuser.amr"
const val ATTRIBUTE_MOBILEUSER_PROFESSION_OID = "zetaguard.mobileuser.profession_oid"
const val ATTRIBUTE_MOBILEUSER_ORGANIZATION = "zetaguard.mobileuser.organization"
const val ATTRIBUTE_MOBILEUSER_DISPLAY_NAME = "zetaguard.mobileuser.display_name"
const val ATTRIBUTE_MOBILEUSER_BIRTHDATE = "zetaguard.mobileuser.birthdate"

// No email stored yet -> reduced token carries BOTH. Email already stored -> reduced token carries only email-verify.
const val SCOPE_EMAIL_BINDING = "zeta:email-binding"
const val SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION = "zeta:email-verify"

// Mobile clients only: list/delete the clients of the identity and change its email via the PEP-protected endpoints.
const val SCOPE_CLIENT_MANAGEMENT = "zeta:client-management"
const val EMAIL_BINDING_TOKEN_TTL_SECONDS = 300

// Token-response members of the reduced token telling the client the next step.
const val RESPONSE_MEMBER_BINDING_MODE = "binding_mode"
const val RESPONSE_MEMBER_EMAIL_HINT = "email_hint"

// binding_mode values: collect a new email (identity new) vs verify an OTP sent to the stored address.
const val BINDING_MODE_COLLECT_EMAIL = "collect_email"
const val BINDING_MODE_VERIFY_OTP = "verify_otp"

// Realm resource provider id — owns the /realms/{realm}/zeta/... namespace for ZETA identity endpoints.
const val ZETA_RESOURCE_ID = "zeta"
const val BIND_EMAIL_PATH = "identity/bind-email"
const val BIND_EMAIL_RESEND_PATH = "identity/bind-email/resend"
const val BIND_EMAIL_VERIFY_PATH = "identity/bind-email/verify"
const val CHALLENGE_TYPE_EMAIL_OTP = "email_otp"

// Identity-scoped email change (A_29911/A_29912); the caller is taken from the client data forwarded by the PEP.
const val IDENTITY_EMAIL_PATH = "identity/email"

// Confirmation of a pending email change; same OTP mechanics as bind-email, but only for the change case.
const val IDENTITY_EMAIL_VERIFY_PATH = "identity/email/verify"
const val IDENTITY_EMAIL_RESEND_PATH = "identity/email/resend"

// Pull endpoint releasing the consent-gated email to a Resource Server.
const val USERINFO_EMAIL_PATH = "userinfo/email"
const val EMAIL_STATUS_VERIFIED = "verified"
const val EMAIL_STATUS_PENDING = "pending"

const val CLIENTS_PATH = "clients"
const val CLIENT_PATH = "clients/{id}"

const val ATTRIBUTE_SMCBUSER_TELEMATIK_ID = "zetaguard.smcbuser.telematik_id"
const val ATTRIBUTE_SMCBUSER_PROFESSION_OID = "zetaguard.smcbuser.profession_oid"
const val ATTRIBUTE_SMCBUSER_NAME = "zetaguard.smcbuser.name"
const val ATTRIBUTE_SMCBUSER_ORGANISATION = "zetaguard.smcbuser.organisation"
const val ATTRIBUTE_LAST_CLIENT_IP = "zeta-guard.client.client_ip"

const val CLAIM_CLIENT_STATEMENT = "client_statement"
const val CLAIM_CLIENT_KEY = "client_key"
const val CLAIM_DPOP_KEY = "dpop_key"
const val CLAIM_JKT = "jkt"
const val CLAIM_PROFESSION_OID = "profession_oid"
const val CLAIM_COMMON_NAME = "common_name"
const val CLAIM_ORGANIZATION_NAME = "organization_name"
const val CLAIM_PLATFORM = PROPERTY_PLATFORM
const val CLAIM_PRODUCT_ID = PROPERTY_PRODUCT_ID
const val CLAIM_CLIENT_ID = "client_id"
const val CLAIM_PRODUCT_VERSION = PROPERTY_PRODUCT_VERSION
const val CLAIM_IP_ADDRESS = "ip_address"

const val ZETA_REALM = "zeta-guard"
const val ZETA_CLIENT = "zeta-client"

const val ATTRIBUTE_REALM_CLIENT_JOB_DISABLED = "zeta-guard.realm.client_job.disabled"

const val USE_DPOP_NONCE = "use_dpop_nonce"

// https://www.keycloak.org/securing-apps/client-registration
const val OIDC_CLIENT_REGISTRATION_PATH = "/realms/{realm-name}/clients-registrations/openid-connect"

const val OIDC_CERTIFICATES_PATH = "/realms/{realm-name}/protocol/openid-connect/certs"

// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_initial_access
const val INITIAL_ACCESS_TOKEN_PATH = "/admin/realms/{realm-name}/clients-initial-access"
const val ADMIN_REVOKE_SESSION_PATH = "/admin/realms/{realm-name}/sessions/{session-id}"
const val WELLKNOWN_BASE_PATH = "/realms/{realm-name}/.well-known"
const val USERINFO_PATH = "/realms/{realm-name}/protocol/openid-connect/userinfo"

const val KEYCLOAK_REALM_PATH = "/realms/{realm-name}"

const val ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID = "zeta-smc-b-token-exchange"
const val EMAIL_BINDING_TOKEN_EXCHANGE_PROVIDER_ID = "zeta-email-binding-token-exchange"
const val SMCB_IDENTITY_PROVIDER_ID = "zeta-smc-b-oidc"

const val SEKIDP_IDENTITY_PROVIDER_ID = "zeta-sekidp-oidc"
const val SEKIDP_MTLS_HTTP_CLIENT_ID = "zeta-sekidp-mtls"
const val OPA_HTTP_CLIENT_ID = "zeta-opa-http-client"
const val OCSP_HTTP_CLIENT_ID = "zeta-ocsp-http-client"
const val KEYCLOAK_HTTP_CLIENT_ID = "default"

val KEYCLOAK_DEFAULT_HTTP_SPI_NAME: String = HttpClientSpi().name

const val ZETA_MOBILE_BROWSER_FLOW = "zeta-mobile"
const val OPENID_FEDERATION_ALIAS = "openid-federation"

const val ENV_SMCB_KEYSTORE_LOCATION = "SMCB_KEYSTORE_LOCATION"
const val ENV_SMCB_KEYSTORE_META_LOCATION = "SMCB_KEYSTORE_META_LOCATION"
const val ENV_SMCB_KEYSTORE_PASSWORD = "SMCB_KEYSTORE_PASSWORD"

const val ENV_TPM_KEYSTORE_LOCATION = "TPM_KEYSTORE_LOCATION"
const val ENV_TPM_KEYSTORE_PASSWORD = "TPM_KEYSTORE_PASSWORD"

const val ENV_APPLE_KEYSTORE_LOCATION = "APPLE_KEYSTORE_LOCATION"
const val ENV_APPLE_KEYSTORE_PASSWORD = "APPLE_KEYSTORE_PASSWORD"

const val ENV_GOOGLE_KEYSTORE_LOCATION = "GOOGLE_KEYSTORE_LOCATION"
const val ENV_GOOGLE_CERTIFICATE_STATUS_LOCATION = "GOOGLE_CERTIFICATE_STATUS_LOCATION"
const val ENV_GOOGLE_KEYSTORE_PASSWORD = "GOOGLE_KEYSTORE_PASSWORD"

const val ENV_OCSP_KEYSTORE_LOCATION = "OCSP_KEYSTORE_LOCATION"
const val ENV_OCSP_KEYSTORE_META_LOCATION = "OCSP_KEYSTORE_META_LOCATION"
const val ENV_OCSP_KEYSTORE_PASSWORD = "OCSP_KEYSTORE_PASSWORD"

const val ENV_FEDERATION_MASTER_LOCATION = "FEDERATION_MASTER_LOCATION"

// Periodic reload of the truststores above, so a provisioning run takes effect without restarting Keycloak.
const val ENV_TRUSTSTORE_RELOAD_ENABLED = "TRUSTSTORE_RELOAD_ENABLED"
const val ENV_TRUSTSTORE_RELOAD_INTERVAL = "TRUSTSTORE_RELOAD_INTERVAL"
const val TRUSTSTORE_RELOAD_TASK_ID = "zeta-guard-truststore-reload"
const val TRUST_MATERIAL_SPI_NAME = "zeta-guard-trust-material"
const val TRUST_MATERIAL_PROVIDER_ID = "zeta-guard-trust-material"

const val ADMIN_EVENTS_PROVIDER_ID = "zeta-guard-admin-events"
const val ENV_GENESIS_HASH = "GENESIS_HASH"

const val ENV_APPLE_APP_ATTEST_AAGUID = "APPLE_APP_ATTEST_AAGUID"

const val REVOCATION_PROVIDER_ID = "zeta-guard-revocation"
const val REVOCATION_EVENTLISTENER_PROVIDER_ID = "zeta-guard-revocation-events"
const val REVOCATION_PATH = "/{realm-name}/$REVOCATION_PROVIDER_ID"
const val REVOCATION_FULL_PATH = "/realms$REVOCATION_PATH"

const val NONCE_PROVIDER_ID = "zeta-guard-nonce"
const val NONCE_PATH = "/{realm-name}/$NONCE_PROVIDER_ID"
const val NONCE_FULL_PATH = "/realms$NONCE_PATH"
const val ENV_NONCE_TTL = "NONCE_TTL"

const val WELLKNOWN_PROVIDER_ID = "zeta-guard-well-known"
const val ENV_SERVICE_DOCUMENTATION_URI = "SERVICE_DOCUMENTATION_URL"

const val ENV_IDLE_USER_TTL = "SMCB_IDLE_USER_TTL"
const val ENV_IDLE_CLIENT_TTL = "SMCB_IDLE_CLIENT_TTL"
const val ENV_MAX_CLIENTS = "SMCB_USER_MAX_CLIENTS"
const val ENV_HASHING_PEPPER = "SMCB_HASHING_PEPPER"

const val CLIENT_REGISTRATION_POLICY_PROVIDER_ID = "zeta-client-registration-policy"
const val ENV_CLIENT_REGISTRATION_TTL = "CLIENT_REGISTRATION_TTL"
const val ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL = "CLIENT_REGISTRATION_SCHEDULER_INTERVAL"
const val ENV_CLIENT_REGISTRATION_STARTUP_DELAY = "CLIENT_REGISTRATION_STARTUP_DELAY"
const val ENV_CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE = "CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE"

const val ENV_OIDC_FLOW_ENABLED = "ZETA_OIDC_FLOW_ENABLED"

const val ACCESSTOKEN_MAPPERPROVIDER_ID = "zeta-guard-accesstoken-mapper"

//  https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_27799
val SMC_B_VALID_GRANT_TYPES = listOf(REFRESH_TOKEN, TOKEN_EXCHANGE_GRANT_TYPE)
val SEKIDP_VALID_GRANT_TYPES = listOf(REFRESH_TOKEN, TOKEN_EXCHANGE_GRANT_TYPE, AUTHORIZATION_CODE)

const val APPLE_APP_ATTESTATION_ROOT_CA = "Apple App Attestation Root CA"
const val APPLE_ORGANISATION = "Apple Inc."

/**
 * Gets the message of a [Throwable].
 *
 * @return The message of the [Throwable] or "<unknown eror>" if the message is null.
 */
fun Throwable.message() = message.toErrorMessage() +
    if (cause != null) "↪" + (cause?.message.toErrorMessage()) else ""

private fun String?.toErrorMessage() = this ?: "<unknown error>"

val logger: Logger = Logger.getLogger("zeta-guard")

enum class ClientAttestationState {
  PENDING,
  VALID,
  INVALID,
}

/** How the client authenticates against the ZETA guard: sectoral IDP redirect (mobile) vs. SMC-B smartcard (stationary). */
enum class ClientAuthMethod {
  SMC_B,
  SEK_IDP,
}

enum class ClientRegistrationStatus {
  EMAIL_CONFIRMATION_REQUIRED,
  OTP_PENDING,
  CONFIRMED,
}
