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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPService
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_TARGET_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_USER
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaActor
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.events.logZetaAdminEvent
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.MEDIA_TYPE_PROBLEM_JSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import de.gematik.zeta.zetaguard.keycloak.plugins.revocation.revokeClientSessions
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import jakarta.ws.rs.core.Response
import java.util.Base64
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientProvider
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakTransactionManager
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserProvider

private const val CALLER_ID = "caller-client"
private const val SIBLING_ID = "sibling-client"
private const val SESSION_REVOCATION = "de.gematik.zeta.zetaguard.keycloak.plugins.revocation.SessionRevocationKt"
private const val ZETA_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEventsKt"
private const val ZETA_ADMIN_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaAdminEventsKt"
private const val USER_NAME = "spicy-hash-of-kvnr"
private const val USER_ID = "user-uuid"

/** `GET zeta/clients` and `DELETE zeta/clients/{id}`: the caller's identity, as resolved from the PEP header, scopes both. */
class ClientManagementEndpointsTest :
  StringSpec({
    lateinit var userData: ZetaGuardUserData
    lateinit var realm: RealmModel
    lateinit var clients: ClientProvider
    lateinit var transactionManager: KeycloakTransactionManager
    lateinit var session: KeycloakSession

    fun header(clientId: String = CALLER_ID): String =
        Base64.getUrlEncoder()
            .encodeToString("""{"client_id":"$clientId","product_id":"demo_client","product_version":"0.1.0","platform":"apple"}""".toByteArray())

    fun clientData(id: String, owner: ZetaGuardUserData = userData, authMethod: ClientAuthMethod = ClientAuthMethod.SEK_IDP) =
        ZetaGuardClientData(id, currentTime(), currentTime()).also {
          it.clientAuthMethod = authMethod
          it.attestationState = ClientAttestationState.VALID
          it.registrationStatus = ClientRegistrationStatus.CONFIRMED
          it.userData = owner
          owner.clients.add(it)
        }

    /** A Keycloak client whose internal id differs from its clientId, so mixing them up shows. */
    fun keycloakClient(clientId: String, name: String?): ClientModel =
        mockk<ClientModel> {
          every { id } returns "internal-$clientId"
          every { this@mockk.clientId } returns clientId
          every { this@mockk.name } returns name
        }.also { every { clients.getClientByClientId(realm, clientId) } returns it }

    fun provider() = ZetaEmailBindingResourceProvider(session)

    beforeTest {
      userData = ZetaGuardUserData(USER_NAME, currentTime(), currentTime())
      realm = mockk { every { getClientByClientId(any()) } returns null }
      clients = mockk { every { getClientByClientId(realm, any()) } returns null }
      transactionManager = mockk(relaxed = true)
      val user = mockk<UserModel> { every { id } returns USER_ID }
      val users = mockk<UserProvider> { every { getUserByUsername(realm, USER_NAME) } returns user }
      val context =
          mockk<KeycloakContext> {
            every { this@mockk.realm } returns realm
            every { connection } returns null
          }
      session =
          mockk(relaxed = true) {
            every { this@mockk.context } returns context
            every { clients() } returns clients
            every { users() } returns users
            every { this@mockk.transactionManager } returns transactionManager
          }

      val caller = clientData(CALLER_ID)
      mockkConstructor(ZetaGuardDataService::class)
      every { anyConstructed<ZetaGuardDataService>().findClientData(any()) } returns null
      every { anyConstructed<ZetaGuardDataService>().findClientData(CALLER_ID) } returns caller
      justRun { anyConstructed<ZetaGuardDataService>().deleteClientData(any()) }

      mockkObject(SecurityEventLogger)
      mockkStatic(ZETA_EVENTS)
      mockkStatic(ZETA_ADMIN_EVENTS)
      justRun { logZetaAdminEvent(any(), any(), any(), any(), any(), any()) }
      justRun { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      mockkStatic(SESSION_REVOCATION)
      every { revokeClientSessions(any(), any(), any()) } returns listOf("sid-1")
      mockkObject(EmailOTPService)
      justRun { EmailOTPService.invalidate(any(), any()) }
    }

    afterTest { unmockkAll() }

    "lists the mobile clients of the caller's identity with their Keycloak names" {
      clientData(SIBLING_ID)
      clientData("smcb-client", authMethod = ClientAuthMethod.SMC_B)
      keycloakClient(CALLER_ID, "My phone")
      keycloakClient(SIBLING_ID, null)

      val response = provider().listClients(header())

      response.status shouldBe 200
      @Suppress("UNCHECKED_CAST")
      (response.entity as List<ClientRep>) shouldContainExactlyInAnyOrder listOf(ClientRep(CALLER_ID, "My phone"), ClientRep(SIBLING_ID, null))
    }

    "listing without the PEP header is rejected with 401" {
      val response = provider().listClients(null)

      response.status shouldBe 401
      response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
    }

    "a zeta client without Keycloak client is skipped" {
      clientData(SIBLING_ID)
      keycloakClient(SIBLING_ID, "Old phone")

      val response = provider().listClients(header())

      response.status shouldBe 200
      @Suppress("UNCHECKED_CAST")
      (response.entity as List<ClientRep>) shouldContainExactlyInAnyOrder listOf(ClientRep(SIBLING_ID, "Old phone"))
    }

    "an unexpected error while listing yields a 500 problem and rolls back" {
      every { clients.getClientByClientId(realm, any()) } throws IllegalStateException("db down")

      val response = provider().listClients(header())

      response.status shouldBe 500
      response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
      response.entityMap()["code"] shouldBe ProblemCodes.INTERNAL_ERROR
      verify { transactionManager.setRollbackOnly() }
    }

    "deleting revokes the client's sessions before removing it, then deletes its data and open challenge" {
      clientData(SIBLING_ID)
      val sibling = keycloakClient(SIBLING_ID, "Old phone")
      every { clients.removeClient(realm, "internal-$SIBLING_ID") } returns true

      val response = provider().deleteClient(header(), SIBLING_ID)

      response.status shouldBe 204
      verifyOrder {
        revokeClientSessions(session, realm, sibling)
        clients.removeClient(realm, "internal-$SIBLING_ID")
        anyConstructed<ZetaGuardDataService>().deleteClientData(SIBLING_ID)
        EmailOTPService.invalidate(session, SIBLING_ID)
        fireClientRemoved(session, realm, USER_ID, SIBLING_ID, "Old phone", ClientRemovalReason.USER_REQUEST)
      }
      verify { SecurityEventLogger.logClientDeleted(SIBLING_ID, "user_request") }
      verify {
        logZetaAdminEvent(
            session,
            realm,
            ZetaEvent.CLIENT_REMOVED,
            "clients/internal-$SIBLING_ID",
            match<ZetaActor> { it.userId == USER_ID && it.clientId == null },
            mapOf(DETAIL_ZETA_TARGET_CLIENT_ID to SIBLING_ID, DETAIL_ZETA_USER to USER_NAME),
        )
      }
    }

    "a client may delete itself, and is still named as the actor of the admin event" {
      keycloakClient(CALLER_ID, "My phone")
      every { clients.removeClient(realm, "internal-$CALLER_ID") } answers
          {
            // like in the transaction: once removed, the client can no longer be looked up
            every { clients.getClientByClientId(realm, CALLER_ID) } returns null
            true
          }

      provider().deleteClient(header(), CALLER_ID).status shouldBe 204

      verify { anyConstructed<ZetaGuardDataService>().deleteClientData(CALLER_ID) }
      verify { logZetaAdminEvent(session, realm, ZetaEvent.CLIENT_REMOVED, any(), match { it.clientId == "internal-$CALLER_ID" }, any()) }
    }

    "a client of another identity is not found and nothing is deleted" {
      clientData("foreign-client", owner = ZetaGuardUserData("someone-else", currentTime(), currentTime()))
      keycloakClient("foreign-client", "Not mine")

      val response = provider().deleteClient(header(), "foreign-client")

      response.status shouldBe 404
      response.entityMap()["code"] shouldBe ProblemCodes.NOT_FOUND
      verify(exactly = 0) { revokeClientSessions(any(), any(), any()) }
      verify(exactly = 0) { clients.removeClient(any(), any()) }
      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().deleteClientData(any()) }
      verify(exactly = 0) { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      verify(exactly = 0) { logZetaAdminEvent(any(), any(), any(), any(), any(), any()) }
      verify(exactly = 0) { SecurityEventLogger.logClientDeleted(any(), any()) }
    }

    "a non-mobile client of the same identity is not found" {
      clientData("smcb-client", authMethod = ClientAuthMethod.SMC_B)

      provider().deleteClient(header(), "smcb-client").status shouldBe 404

      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().deleteClientData(any()) }
    }

    "the zeta data is deleted even if the Keycloak client is already gone" {
      clientData(SIBLING_ID)

      provider().deleteClient(header(), SIBLING_ID).status shouldBe 204

      verify(exactly = 0) { revokeClientSessions(any(), any(), any()) }
      verify { anyConstructed<ZetaGuardDataService>().deleteClientData(SIBLING_ID) }
      verify { fireClientRemoved(session, realm, USER_ID, SIBLING_ID, null, ClientRemovalReason.USER_REQUEST) }
    }

    "without a Keycloak user nobody is notified, but the call is logged with the identity's ZETA user" {
      clientData(SIBLING_ID)
      every { session.users().getUserByUsername(realm, USER_NAME) } returns null

      provider().deleteClient(header(), SIBLING_ID).status shouldBe 204

      verify(exactly = 0) { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      verify {
        logZetaAdminEvent(
            session,
            realm,
            ZetaEvent.CLIENT_REMOVED,
            any(),
            match { it.userId == null },
            match { it[DETAIL_ZETA_USER] == USER_NAME },
        )
      }
    }

    "a failing removal yields a 500 problem, rolls back and leaves the zeta data alone" {
      clientData(SIBLING_ID)
      keycloakClient(SIBLING_ID, "Old phone")
      every { clients.removeClient(realm, any()) } throws IllegalStateException("db down")

      val response = provider().deleteClient(header(), SIBLING_ID)

      response.status shouldBe 500
      response.entityMap()["code"] shouldBe ProblemCodes.INTERNAL_ERROR
      verify { transactionManager.setRollbackOnly() }
      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().deleteClientData(any()) }
    }
  })

@Suppress("UNCHECKED_CAST") //
private fun Response.entityMap(): Map<String, Any> = entity as Map<String, Any>
