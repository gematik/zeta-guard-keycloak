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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.oidc

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ClientRegistrationState
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientResponseRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_REGISTRATION_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import jakarta.ws.rs.core.Response
import java.net.URI
import java.util.stream.Stream
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.clientregistration.ClientRegistrationAuth
import org.keycloak.services.clientregistration.ClientRegistrationContext
import org.keycloak.services.clientregistration.oidc.DescriptionConverter
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProvider
import org.keycloak.services.clientregistration.policy.RegistrationAuth
import org.keycloak.services.cors.Cors
import org.keycloak.urls.UrlType
import org.keycloak.utils.KeycloakSessionUtil

private const val CLIENT_ID = "a-client-id"
private const val CLIENT_NAME = "a client"
private const val GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
private const val REALM = "zeta"
private const val ALLOWED_ORIGIN = "https://caller.example"
private val BASE_URI = URI("https://zeta.example/auth")

class ZetaGuardOIDCClientRegistrationProviderTest : FunSpec() {
  init {
    val dcr = javaClass.getResourceAsStream("/apple_dcr.json")!!.toObject<Map<String, Any>>()

    beforeEach {
      mockkStatic(KeycloakSessionUtil::class)
      mockkStatic(DescriptionConverter::class)
    }

    afterEach { unmockkAll() }

    test("A_30086: createOIDC keeps Keycloak's 201 Created with its Location header and adds the status") {
      val mockHelper = MockHelper().also { it.storedRegistration(clientData(ClientAuthMethod.SMC_B, ClientAttestationState.PENDING)) }

      val clientOIDC = dcr.toObject<AppleRegistrationRequest>()
      val response = mockHelper.provider.createOIDC(clientOIDC)

      response.status shouldBe Response.Status.CREATED.statusCode
      response.location shouldBe mockHelper.registrationClientUri.captured
      response.getHeaderString(Cors.ACCESS_CONTROL_ALLOW_ORIGIN) shouldBe ALLOWED_ORIGIN

      val entity = response.entity.shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>()
      entity.status shouldBe ClientRegistrationState.REGISTERED
      entity.clientId shouldBe CLIENT_ID
      entity.clientName shouldBe CLIENT_NAME
      entity.grantTypes shouldBe listOf(GRANT_TYPE)
      // Keycloak sets this after it produced the representation — it can only be here if the copy was taken from the finished response.
      entity.clientIdIssuedAt.shouldNotBeNull()

      verify(exactly = 1) { mockHelper.session.setAttribute(ATTRIBUTE_CLIENT_REGISTRATION_DATA, clientOIDC) }
    }

    test("A_30086: getOIDC reports the status the stored registration is in") {
      val mockHelper = MockHelper()
      mockHelper.storedRegistration(clientData(ClientAuthMethod.SMC_B, ClientAttestationState.VALID))

      val response = mockHelper.provider.getOIDC(CLIENT_ID)

      response.status shouldBe Response.Status.OK.statusCode
      response.getHeaderString(Cors.ACCESS_CONTROL_ALLOW_ORIGIN) shouldBe ALLOWED_ORIGIN
      response.entity.shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>().status shouldBe ClientRegistrationState.ACTIVE
    }

    test("a registration without stored data comes back without a status, not as a different type") {
      val mockHelper = MockHelper()
      mockHelper.storedRegistration(null)

      val response = mockHelper.provider.getOIDC(CLIENT_ID)

      response.status shouldBe Response.Status.OK.statusCode
      val entity = response.entity.shouldBeInstanceOf<ZetaGuardOIDCClientResponseRepresentation>()
      entity.status.shouldBeNull()
      entity.clientId shouldBe CLIENT_ID
      entity.clientName shouldBe CLIENT_NAME
    }

    test("the error Keycloak raises for a client-supplied client id is not turned into a registration response") {
      val mockHelper = MockHelper()

      shouldThrow<ErrorResponseException> { mockHelper.provider.createOIDC(AppleRegistrationRequest().apply { clientId = CLIENT_ID }) }

      verify(exactly = 0) { mockHelper.dataService.findClientData(any()) }
    }

    test("DCR must contain field defined in https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml") {
      val mockHelper = MockHelper().also { it.storedRegistration(clientData(ClientAuthMethod.SMC_B, ClientAttestationState.PENDING)) }

      mockHelper.provider.createOIDC(dcr.toObject<AppleRegistrationRequest>()).status shouldBe Response.Status.CREATED.statusCode

      shouldThrow<ErrorResponseException> { mockHelper.provider.createOIDC(AppleRegistrationRequest()) }
      shouldThrow<ErrorResponseException> { mockHelper.provider.createOIDC(dcr.toObject<AppleRegistrationRequest>().apply { clientName = null }) }
      shouldThrow<ErrorResponseException> { mockHelper.provider.createOIDC(dcr.toObject<AppleRegistrationRequest>().apply { jwks.keys = null }) }
      shouldThrow<ErrorResponseException> {
        mockHelper.provider.createOIDC(
            dcr.toObject<AppleRegistrationRequest>().apply { tokenEndpointAuthMethod = null })
      }
    }
  }
}

/** The mocked realm, session and registration hooks Keycloak's own registration endpoints need to get as far as building a response. */
private class MockHelper {
  val dataService = mockk<ZetaGuardDataService>()
  val session = mockk<KeycloakSession>(relaxed = true)
  val realm = mockk<RealmModel>(relaxed = true)
  val clientModel = mockk<ClientModel>(relaxed = true)
  val auth = mockk<ClientRegistrationAuth>(relaxed = true)
  val cors = mockk<Cors>()
  val registrationClientUri = slot<URI>()
  val provider: ZetaGuardOIDCClientRegistrationProvider

  init {
    every { KeycloakSessionUtil.getKeycloakSession() } returns session
    every { session.getProvider(Cors::class.java) } returns cors
    every { cors.auth() } returns cors
    every { cors.checkAllowedOrigins(any<List<String>>()) } returns cors
    every { cors.add(any<Response.ResponseBuilder>()) } answers
        {
          firstArg<Response.ResponseBuilder>().header(Cors.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN).build()
        }

    every { session.context.realm } returns realm
    every { session.context.getUri(UrlType.BACKEND).baseUri } returns BASE_URI
    every { realm.name } returns REALM
    every { realm.getClientByClientId(CLIENT_ID) } returns clientModel
    // No registration policies are configured, so the request has no allowed origins of its own.
    every { realm.getComponentsStream(any(), any()) } answers { Stream.empty() }
    every { auth.jwt } returns null
    every { auth.resolveRegistrationAuth() } returns RegistrationAuth.ANONYMOUS
    every { clientModel.clientId } returns CLIENT_ID
    // Consumed twice per request (pairwise mappers, then the representation), so every call needs its own stream.
    every { clientModel.protocolMappersStream } answers { Stream.empty() }

    every { DescriptionConverter.toInternal(session, any()) } returns internalRepresentation()
    every { DescriptionConverter.toExternalResponse(session, any(), capture(registrationClientUri)) } returns keycloakRepresentation()

    val delegate = spyk(OIDCClientRegistrationProvider(session))
    provider = ZetaGuardOIDCClientRegistrationProvider(dataService, delegate, session)
    provider.auth = auth
    provider.event = mockk(relaxed = true)

    every { delegate.get(clientModel) } returns internalRepresentation()
    every { delegate.create(any<ClientRegistrationContext>()) } returns internalRepresentation()
    every { delegate.update(CLIENT_ID, any<ClientRegistrationContext>()) } returns internalRepresentation()
    justRun { delegate.validateClient(any<ClientModel>(), any<OIDCClientRepresentation>(), any()) }
  }

  fun storedRegistration(clientData: ZetaGuardClientData?) {
    every { dataService.findClientData(CLIENT_ID) } returns clientData
  }
}

private fun internalRepresentation() =
    ClientRepresentation().apply {
      clientId = CLIENT_ID
      name = CLIENT_NAME
      attributes = mutableMapOf()
    }

private fun keycloakRepresentation() =
    OIDCClientRepresentation().apply {
      clientId = CLIENT_ID
      clientName = CLIENT_NAME
      grantTypes = listOf(GRANT_TYPE)
    }

private fun clientData(
    authMethod: ClientAuthMethod,
    attestation: ClientAttestationState,
    status: ClientRegistrationStatus? = null,
    hasUserData: Boolean = false,
) =
    ZetaGuardClientData(CLIENT_ID, currentTime(), currentTime()).apply {
      clientAuthMethod = authMethod
      attestationState = attestation
      registrationStatus = status
      userData = if (hasUserData) ZetaGuardUserData("a-user", currentTime(), currentTime()) else null
    }
