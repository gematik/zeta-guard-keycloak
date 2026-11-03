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

import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.safeGetenv
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.spree.keycloak.commons.getEnvironment
import jakarta.ws.rs.NotFoundException
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.util.KeyUtils
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyType
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.SignatureProvider
import org.keycloak.jose.jwk.JWKBuilder
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.urls.UrlType
import org.keycloak.wellknown.WellKnownProvider

/** Entity-statement TTL. Kept short so realm key rotations propagate quickly to the federation. */
private const val ENTITY_STATEMENT_TTL_SECONDS = 3600L

private const val ENV_ENTITY_STATEMENT_ID_TOKEN_VERSION = "ENTITY_STATEMENT_ID_TOKEN_VERSION"
private const val ENV_ENTITY_STATEMENT_CLIENT_NAME = "ENTITY_STATEMENT_CLIENT_NAME"
private const val ENV_ENTITY_STATEMENT_ORGANIZATION_NAME = "ENTITY_STATEMENT_ORGANIZATION_NAME"
private const val ENV_ENTITY_STATEMENT_CONTACT_EMAIL = "ENTITY_STATEMENT_CONTACT_EMAIL"
private const val ENV_ENTITY_STATEMENT_PRODUCT_TYPE_VERSION = "ENTITY_STATEMENT_PRODUCT_TYPE_VERSION"
private const val ENV_ENTITY_STATEMENT_REDIRECT_URIS = "ENTITY_STATEMENT_REDIRECT_URIS"

private const val DEFAULT_PRODUCT_TYPE_VERSION = "1.0.0"

internal data class EntityStatementConfig(
    val idTokenVersions: List<String>,
    val clientName: String,
    val organizationName: String,
    val contactEmail: String,
    val productTypeVersion: String,
    val redirectUris: List<String> = emptyList(),
)

internal fun resolveEntityStatementConfig(
    env: (String, String) -> String = ::getEnvironment,
    requireEnv: (String) -> String = ::safeGetenv,
): EntityStatementConfig = EntityStatementConfig(
    idTokenVersions = env(ENV_ENTITY_STATEMENT_ID_TOKEN_VERSION, "1.0.0")
        .split(",").map { it.trim() }.filter { it.isNotEmpty() },
    clientName = requireEnv(ENV_ENTITY_STATEMENT_CLIENT_NAME),
    organizationName = requireEnv(ENV_ENTITY_STATEMENT_ORGANIZATION_NAME),
    contactEmail = requireEnv(ENV_ENTITY_STATEMENT_CONTACT_EMAIL),
    productTypeVersion = env(ENV_ENTITY_STATEMENT_PRODUCT_TYPE_VERSION, DEFAULT_PRODUCT_TYPE_VERSION),
    redirectUris = env(ENV_ENTITY_STATEMENT_REDIRECT_URIS, "")
        .split(",").map { it.trim() }.filter { it.isNotEmpty() }.distinct(),
)

/**
 * A statically configured list replaces the redirect URIs derived from the realm's SekIDP clients completely; those are
 * only used when no list is configured.
 */
internal fun effectiveRedirectUris(configured: List<String>, derived: () -> List<String>): List<String> = configured.ifEmpty(derived)

internal val entityStatementConfig: EntityStatementConfig by lazy {
  resolveEntityStatementConfig()
}

private const val productType = "ZETA Guard"

/**
 * Serves the ZETA Guard's own OpenID-Federation entity statement (A_23034-02) under
 * `/realms/{realm}/.well-known/openid-federation`. The realm URL is the federation entity id and
 * the `client_id` towards the SekIDP, which fetches this statement during automatic registration.
 */
class ZetaGuardEntityStatementProvider(private val session: KeycloakSession, private val fedmasterUrl: String) : WellKnownProvider {

  override fun getConfig(): Any {
    val realm = session.context.realm
    val idp =
        session.identityProviders().getByAlias(SEKIDP_IDENTITY_PROVIDER_ID)
          ?: throw NotFoundException(
              "SekIDP identity provider »$SEKIDP_IDENTITY_PROVIDER_ID« is not configured in realm »${realm.name}«"
          )

    val entityId =
        session.context
            .getUri(UrlType.FRONTEND)
            .baseUriBuilder
            .path("realms")
            .path(realm.name)
            .build()
            .toString()

    // A_23034-02
    val sigKey =
        session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256)
          ?: throw NotFoundException(
              "No active ES256 signing key in realm »${realm.name}« — add an »ecdsa-generated« key provider (ecdsaEllipticCurveKey=P-256)"
          )
    val encKey =
        session
            .keys()
            .getKeysStream(realm)
            .filter { it.use == KeyUse.ENC && it.type == KeyType.EC && it.status == KeyStatus.ACTIVE }
            .findFirst()
            .orElseThrow {
              NotFoundException(
                  "No active EC encryption key in realm »${realm.name}« — add an »ecdh-generated« key provider (ecdhAlgorithm=ECDH-ES)")
            }

    // Federation-entity keys (top level): ONLY the key that self-signs this entity statement.
    // The enc key is protocol material and belongs solely into the openid_relying_party metadata.
    val federationJwks =
        mapOf(
            "keys" to
                listOf(
                    JWKBuilder.create().kid(sigKey.kid).algorithm(sigKey.algorithm).ec(sigKey.publicKey, KeyUse.SIG),
                ))

    // RP protocol keys: the ECDH-ES key the SekIDP encrypts the ID token with, plus — when mTLS is
    // enabled — the self-signed TLS client certificate the SekIDP matches at PAR/token (A_23183).
    val mtlsCertificate =
        (session.keycloakSessionFactory.getProviderFactory(IdentityProvider::class.java, SEKIDP_IDENTITY_PROVIDER_ID) as? SekIDPIdentityProviderFactory)
            ?.mtlsClientCertificate
    val relyingPartyJwks =
        mapOf(
            "keys" to
                buildList {
                  add(JWKBuilder.create().kid(encKey.kid).algorithm(encKey.algorithm).ec(encKey.publicKey, KeyUse.ENC))
                  mtlsCertificate?.let { add(JWKBuilder.create().kid(KeyUtils.createKeyId(it.publicKey)).ec(it.publicKey, listOf(it), KeyUse.SIG)) }
                })

    // gemSpec_IDP_Sek, Tab. 28: the entity statement of a Fachdienst carries a federation_entity block.
    val federationEntity =
        mapOf(
            "name" to entityStatementConfig.clientName,
            "organization_name" to entityStatementConfig.organizationName,
        )

    // Field set per A_23034-02 — everything below is REQUIRED,
    // including `scope`: the SekIDP validates the PAR scopes against this list A_29660.
    val openidRelyingParty =
        mapOf(
            "redirect_uris" to redirectUris(realm),
            "response_types" to listOf("code"),
            "grant_types" to listOf("authorization_code"),
            "client_registration_types" to listOf("automatic"),
            "require_pushed_authorization_requests" to true,
            "token_endpoint_auth_method" to "self_signed_tls_client_auth",
            "id_token_signed_response_alg" to Algorithm.ES256,
            "id_token_encrypted_response_alg" to "ECDH-ES",
            "id_token_encrypted_response_enc" to "A256GCM",
            "scope" to idp.config["defaultScope"],
            "jwks" to relyingPartyJwks,
            "ti_features_supported" to mapOf(
                "id_token_version_supported" to entityStatementConfig.idTokenVersions
            ),
            "client_name" to entityStatementConfig.clientName,
            "organization_name" to entityStatementConfig.organizationName,
            "keywords" to listOf(
                "product_type_version:${entityStatementConfig.productTypeVersion}",
                "product_type:$productType",
            ),
            "contacts" to listOf(entityStatementConfig.contactEmail),
            "default_acr_values" to listOf(SEKIDP_DEFAULT_ACR),
        )

    val now = Time.currentTime().toLong()
    val body =
        mapOf(
            "iss" to entityId,
            "sub" to entityId,
            "iat" to now,
            "exp" to now + ENTITY_STATEMENT_TTL_SECONDS,
            "jwks" to federationJwks,
            "authority_hints" to listOf(fedmasterUrl),
            "metadata" to
                mapOf(
                    "federation_entity" to federationEntity,
                    "openid_relying_party" to openidRelyingParty,
                ),
        )

    val signer = session.getProvider(SignatureProvider::class.java, sigKey.algorithmOrDefault).signer(sigKey)
    return JWSBuilder().type("entity-statement+jwt").kid(sigKey.kid).jsonContent(body).sign(signer)
  }

  // A_25656: the redirect URLs of all permitted SekIDP clients.
  private fun redirectUris(realm: RealmModel): List<String> =
      effectiveRedirectUris(entityStatementConfig.redirectUris) { clientRedirectUris(realm) }

  private fun clientRedirectUris(realm: RealmModel): List<String> {
    val sekIdpClientIds = ZetaGuardDataService(DefaultEMCreator(session)).findSekIdpClientIds().toSet()
    return session
        .clients()
        .getClientsStream(realm)
        .filter { it.clientId in sekIdpClientIds }
        .toList()
        .flatMap { client -> client.redirectUris.orEmpty() }
        .distinct()
  }

  override fun close() {
    // No-op
  }
}
