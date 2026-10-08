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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.net.URI
import java.security.KeyPair
import java.util.UUID
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.Time
import org.keycloak.crypto.KeyType
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.jose.jws.JWSInput
import org.keycloak.keys.loader.PublicKeyStorageManager
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.SingleUseObjectProvider
import org.keycloak.representations.JsonWebToken

private const val CLIENT_ID = "mobile-client-1"
private const val BASE_URI = "http://localhost:8080"
private const val REALM_NAME = "zeta-guard"
private const val EXPECTED_AUDIENCE = "$BASE_URI/realms/$REALM_NAME"
private const val REQUEST_URI = "$BASE_URI/realms/$REALM_NAME/zeta/identity/email"
private const val ES256 = "ES256"

/** Everything the validator needs — client and expected values are passed explicitly, so no context mocking. */
private class Fixture(jtiFresh: Boolean = true) {
  val client: ClientModel =
      mockk<ClientModel> {
        every { clientId } returns CLIENT_ID
        // OIDCAdvancedConfigWrapper reads the signing alg from client attributes; null → any registered alg
        every { getAttribute(any()) } returns null
      }

  val session: KeycloakSession =
      mockk<KeycloakSession> {
        every { singleUseObjects() } returns mockk<SingleUseObjectProvider> { every { putIfAbsent(any(), any()) } returns jtiFresh }
      }

  fun validate(
      assertion: String,
      checks: List<ClientAssertionCheck> =
          ClientAssertionValidator.defaultChecks(
              expectedAudience = EXPECTED_AUDIENCE,
              expectedHttpMethod = "POST",
              expectedTargetUri = URI.create(REQUEST_URI),
          ),
  ): ClientAssertionResult = ClientAssertionValidator(session, checks).validate(assertion, client)
}

class ClientAssertionValidatorTest :
    StringSpec({
      // The server initializes the crypto provider at startup; unit tests must do it themselves (cf. ZetaGuardFunSpec)
      setupSecurityProviders()
      CryptoIntegration.init(ClientAssertionValidatorTest::class.java.classLoader)
      val keyPair = generateKeyPair()

      fun buildAssertion(
          issuer: String = CLIENT_ID,
          subject: String = CLIENT_ID,
          audience: String = EXPECTED_AUDIENCE,
          jti: String? = UUID.randomUUID().toString(),
          lifetimeSeconds: Long = 30,
          iatOffsetSeconds: Long = 0,
          htm: String? = "POST",
          htu: String? = REQUEST_URI,
          typ: String? = "JWT",
          signingKeyPair: KeyPair = keyPair,
      ): String {
        val token =
            JsonWebToken().apply {
              jti?.let { id(it) }
              issuer(issuer)
              subject(subject)
              audience(audience)
              iat(Time.currentTime() + iatOffsetSeconds)
              exp(Time.currentTime() + iatOffsetSeconds + lifetimeSeconds)
              htm?.let { setOtherClaims("htm", it) }
              htu?.let { setOtherClaims("htu", it) }
            }
        return JWSBuilder().type(typ).jsonContent(token).sign(signingKeyPair.createSignerContext())
      }

      fun mockRegisteredInstanceKey(registeredKeyPair: KeyPair = keyPair) {
        mockkStatic(PublicKeyStorageManager::class)
        every { PublicKeyStorageManager.getClientPublicKeyWrapper(any(), any(), any<JWSInput>()) } returns
            KeyWrapper().apply {
              publicKey = registeredKeyPair.public
              type = KeyType.EC
              algorithm = ES256
              use = KeyUse.SIG
            }
      }

      afterTest { unmockkAll() }

      "the check pipeline is pluggable — a custom check list replaces the default policy" {
        val customCheck = ClientAssertionCheck { rejected(ProblemCodes.FACTOR_REQUIRED, "custom rejection") }

        val result = Fixture().validate(buildAssertion(), checks = listOf(customCheck))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.FACTOR_REQUIRED
      }

      "a valid client assertion signed with the registered instance key is accepted" {
        mockRegisteredInstanceKey()
        val result = Fixture().validate(buildAssertion())

        result.shouldBeInstanceOf<ClientAssertionResult.Valid>()
      }

      "an htu with query and fragment still matches (RFC 9449 §4.2 comparison rules)" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(htu = "$REQUEST_URI?x=1#frag"))

        result.shouldBeInstanceOf<ClientAssertionResult.Valid>()
      }

      "a malformed assertion is rejected as invalidSignature" {
        val result = Fixture().validate("not-a-jwt")

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_SIGNATURE
      }

      "a typ header other than JWT is rejected (A_25338-01)" {
        val result = Fixture().validate(buildAssertion(typ = "at+jwt"))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_SIGNATURE
      }

      "iss and sub must both carry the client_id" {
        val result = Fixture().validate(buildAssertion(issuer = "someone-else"))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_SIGNATURE
      }

      "an assertion issued for a different client than the addressed one is rejected" {
        val result = Fixture().validate(buildAssertion(issuer = "other-client", subject = "other-client"))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_SIGNATURE
      }

      "unverifiedClientId extracts the selector only when iss equals sub" {
        ClientAssertionValidator.unverifiedClientId(buildAssertion()) shouldBe CLIENT_ID
        ClientAssertionValidator.unverifiedClientId(buildAssertion(issuer = "someone-else")) shouldBe null
        ClientAssertionValidator.unverifiedClientId("not-a-jwt") shouldBe null
      }

      "an assertion signed with a foreign key is rejected" {
        mockRegisteredInstanceKey(registeredKeyPair = keyPair)

        val result = Fixture().validate(buildAssertion(signingKeyPair = generateKeyPair()))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_SIGNATURE
      }

      "a wrong audience is rejected as wrongAudience" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(audience = "https://other-guard.example/realms/zeta"))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.WRONG_AUDIENCE
      }

      "a missing or wrong htm is rejected as invalidBinding" {
        mockRegisteredInstanceKey()
        val fixture = Fixture()

        fixture.validate(buildAssertion(htm = null))
            .shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_BINDING
        fixture.validate(buildAssertion(htm = "DELETE"))
            .shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_BINDING
      }

      "an htu for a different endpoint is rejected as invalidBinding (no cross-endpoint replay)" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(htu = "$BASE_URI/realms/$REALM_NAME/zeta/clients/other"))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.INVALID_BINDING
      }

      "an expired assertion is rejected as staleRequest" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(lifetimeSeconds = -90))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.STALE_REQUEST
      }

      "an assertion issued longer ago than the 60s max lifetime is rejected as staleRequest" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(iatOffsetSeconds = -120, lifetimeSeconds = 3600))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.STALE_REQUEST
      }

      "an assertion without jti is rejected as staleRequest" {
        mockRegisteredInstanceKey()

        val result = Fixture().validate(buildAssertion(jti = null))

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.STALE_REQUEST
      }

      "a replayed jti is rejected as staleRequest" {
        mockRegisteredInstanceKey()

        val result = Fixture(jtiFresh = false).validate(buildAssertion())

        result.shouldBeInstanceOf<ClientAssertionResult.Invalid>().code shouldBe ProblemCodes.STALE_REQUEST
      }
    })
