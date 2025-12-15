/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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

import arrow.core.Either
import arrow.core.left
import java.net.URI
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import kotlin.io.encoding.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.util.Base64Url

fun ByteArray.toBase64(): String = Base64Url.encode(this)

fun String.fromBase64(): ByteArray = Base64Url.decode(this)

fun String?.toURI(): Either<Throwable, URI> =
    if (this != null) {
      Either.catch { URI(this) }
    } else {
      NullPointerException().left()
    }

fun String.toCertificate(): X509Certificate {
  val certificateFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME)
  val bytes = Base64.decode(this)

  return certificateFactory.generateCertificate(bytes.inputStream()) as X509Certificate
}

fun LocalDateTime.toISO8601(): String = format(DateTimeFormatter.ISO_DATE_TIME)

fun String.toLocalDateTime(): LocalDateTime = LocalDateTime.parse(this, DateTimeFormatter.ISO_DATE_TIME)

fun String.toDuration(): Duration = Duration.parse(this)

fun currentTime() = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS)
