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
import arrow.core.raise.either
import arrow.core.raise.ensure
import java.security.cert.CertPathBuilder
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME

/**
 * Authenticates a resource server by its mTLS client certificate: the chain must lead to one of [trustedCertificates].
 *
 * Every certificate of the truststore is a trust anchor, so a CA certificate alone suffices and a resource server certificate may also be pinned
 * directly. Revocation is not checked.
 */
class ResourceServerCertificateValidator(private val trustedCertificates: Set<X509Certificate>) {
  private val trustAnchors = trustedCertificates.map { TrustAnchor(it, null) }.toSet()

  /** The validated client certificate, i.e. the first element of [chain]. */
  fun validate(chain: List<X509Certificate>, at: Date = Date()): Either<String, X509Certificate> = either {
    ensure(trustAnchors.isNotEmpty()) { "No truststore configured for resource server access" }
    ensure(chain.isNotEmpty()) { "No client certificate presented" }

    val clientCertificate = chain.first()

    Either.catch {
          if (clientCertificate in trustedCertificates) {
            clientCertificate.checkValidity(at)
          } else {
            val target = X509CertSelector().apply { certificate = clientCertificate }
            val parameters =
                PKIXBuilderParameters(trustAnchors, target).apply {
                  isRevocationEnabled = false
                  date = at
                  addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(chain), PROVIDER_NAME))
                }

            CertPathBuilder.getInstance("PKIX", PROVIDER_NAME).build(parameters)
          }
        }
        .mapLeft { "Client certificate »${clientCertificate.subjectX500Principal.name}« is not trusted: ${it.message}" }
        .bind()

    clientCertificate
  }
}
