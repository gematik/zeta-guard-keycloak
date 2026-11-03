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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import de.gematik.zeta.zetaguard.keycloak.commons.email.verifiedEmail
import de.gematik.zeta.zetaguard.keycloak.commons.maskEmail
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import jakarta.ws.rs.GET
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.NOT_FOUND
import jakarta.ws.rs.core.Response.Status.UNAUTHORIZED
import java.security.cert.X509Certificate
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.services.x509.X509ClientCertificateLookup

private val logger: Logger = Logger.getLogger(UserInfoEmailResource::class.java)

/** A KVNR: one capital letter and nine digits, the last of which is a check digit (not verified here). */
private val KVNR_FORMAT = Regex("""[A-Z]\d{9}""")

/**
 * Pull endpoint releasing the verified email of a user to a resource server, which authenticates via mTLS.
 *
 * The query parameter `id` carries the KVNR, i.e. the identifier the resource server receives from the PEP. Where the client certificate comes
 * from (TLS connection or a header set by the ingress) is decided by Keycloak's `x509cert-lookup` SPI.
 *
 * Answers carry no body: 401 for a missing or untrusted certificate, an undifferentiated 404 for a missing or malformed KVNR, an unknown user
 * and a user without a verified email.
 */
class UserInfoEmailResource(private val session: KeycloakSession, private val validator: ResourceServerCertificateValidator) {

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  fun getEmail(@QueryParam("id") kvnr: String?): Response =
      releaseEmail(kvnr).fold({ Response.status(it.statusCode).build() }, { Response.ok(UserInfoEmailResponse(it)).build() })

  private fun releaseEmail(kvnr: String?): Either<KeycloakError, String> = either {
    val resourceServer = authenticate().bind().subjectX500Principal.name

    ensure(kvnr != null && KVNR_FORMAT.matches(kvnr)) { notFound() }

    val email = session.users().getUserByUsername(session.context.realm, kvnr.toSpicyHash())?.verifiedEmail()

    ensureNotNull(email) {
      logger.infof("userinfo/email: no verified email for the identifier requested by resource server »%s«", resourceServer)
      notFound()
    }

    logger.infof("userinfo/email: released »%s« to resource server »%s«", email.maskEmail(), resourceServer)

    email
  }

  private fun authenticate(): Either<KeycloakError, X509Certificate> =
      Either.catch { session.getProvider(X509ClientCertificateLookup::class.java)?.getCertificateChain(session.context.httpRequest) }
          .mapLeft { "Reading the client certificate failed: ${it.message}" }
          .flatMap { validator.validate(it?.toList().orEmpty()) }
          .mapLeft {
            logger.warnf("userinfo/email rejected: %s", it)
            KeycloakError("unauthorized", "unauthorized", UNAUTHORIZED)
          }

  private fun notFound() = KeycloakError("not_found", "not_found", NOT_FOUND)
}
