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

// internal: also read by SekIDPIdentityProvider for the trust-chain fetch.
internal const val SEKIDP_CONFIG_FEDMASTER_URL = "fedmasterUrl"

/**
 * Serves the ZETA Guard's own OpenID-Federation entity statement (A_23034-02) under
 * `/realms/{realm}/.well-known/openid-federation`. The realm URL is the federation entity id and
 * the `client_id` towards the SekIDP, which fetches this statement during automatic registration.
 */
class ZetaGuardEntityStatementProvider(private val session: KeycloakSession) : WellKnownProvider {

  override fun getConfig(): Any {
    val realm = session.context.realm
    val idp =
        session.identityProviders().getByAlias(SEKIDP_IDENTITY_PROVIDER_ID)
            ?: throw NotFoundException(
                "SekIDP identity provider »$SEKIDP_IDENTITY_PROVIDER_ID« is not configured in realm »${realm.name}«")

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
                "No active ES256 signing key in realm »${realm.name}« — add an »ecdsa-generated« key provider (ecdsaEllipticCurveKey=P-256)")
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

    // Field set per A_23034-02 — everything below is REQUIRED,
    // including `scope`: the SekIDP validates the PAR scopes against this list A_29660.
    val openidRelyingParty =
        mapOf(
            "redirect_uris" to clientRedirectUris(realm),
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
        )

    val now = Time.currentTime().toLong()
    val body =
        mapOf(
            "iss" to entityId,
            "sub" to entityId,
            "iat" to now,
            "exp" to now + ENTITY_STATEMENT_TTL_SECONDS,
            "jwks" to federationJwks,
            // with A_29737 fedmaster url will be available in the provisioned image
            "authority_hints" to listOf(idp.config[SEKIDP_CONFIG_FEDMASTER_URL]),
            "metadata" to mapOf("openid_relying_party" to openidRelyingParty),
        )

    val signer = session.getProvider(SignatureProvider::class.java, sigKey.algorithmOrDefault).signer(sigKey)
    return JWSBuilder().type("entity-statement+jwt").kid(sigKey.kid).jsonContent(body).sign(signer)
  }

  // A_25656: the redirect URLs of all permitted clients.
  private fun clientRedirectUris(realm: RealmModel): List<String> =
      session
          .clients()
          .getClientsStream(realm)
          .toList()
          .flatMap { client -> client.redirectUris.orEmpty() }
          .distinct()

  override fun close() {
    // No-op
  }
}
