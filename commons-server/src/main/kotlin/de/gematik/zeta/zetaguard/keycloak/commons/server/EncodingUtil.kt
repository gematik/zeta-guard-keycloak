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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import arrow.core.Either
import arrow.core.left
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.lang.System.getenv
import java.net.URI
import java.security.MessageDigest
import java.time.Duration
import java.time.LocalDateTime
import java.time.Period
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import kotlinx.datetime.DateTimePeriod
import org.keycloak.common.util.Base64Url
import org.keycloak.models.KeycloakUriInfo

const val DIGEST_ALGORITHM = "SHA-256"

val HASHING_PEPPER: String by lazy { safeGetenv(ENV_HASHING_PEPPER) }

fun ByteArray.toBase64(): String = Base64Url.encode(this)

fun String.fromBase64(): ByteArray = Base64Url.decode(this)

fun String?.toURI(): Either<Throwable, URI> =
    if (this != null) {
      Either.catch { URI(this) }
    } else {
      NullPointerException().left()
    }

fun LocalDateTime.toISO8601(): String = format(DateTimeFormatter.ISO_DATE_TIME)

fun String.toLocalDateTime(): LocalDateTime = LocalDateTime.parse(this, DateTimeFormatter.ISO_DATE_TIME)

fun String.toDateTimePeriod() = DateTimePeriod.parse(this)

fun DateTimePeriod.toPeriod(): Period = Period.of(years, months, days)

fun DateTimePeriod.toDuration(): Duration = Duration.ofSeconds(hours * 3600L + minutes * 60L + seconds)

fun LocalDateTime.plus(period: DateTimePeriod): LocalDateTime = plus(period.toPeriod()).plus(period.toDuration())

fun LocalDateTime.minus(period: DateTimePeriod): LocalDateTime = minus(period.toPeriod()).minus(period.toDuration())

fun currentTime(): LocalDateTime = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS)

fun toHash(vararg bytes: ByteArray): ByteArray = MessageDigest.getInstance(DIGEST_ALGORITHM).apply { bytes.forEach { update(it) } }.digest()

fun String.toSpicyHash() = (this + HASHING_PEPPER).toHash()

fun String.toHash() = this.toByteArray().toHash().toBase64()

fun ByteArray.toHash() = toHash(this)

fun safeGetenv(name: String) = getenv(name) ?: error("Missing environment variable »$name«")

fun String.toInputStream(): InputStream {
  val file = File(this)

  check(file.exists() && file.isFile && file.length() > 0) { "No valid data file found using path »$this«" }

  return FileInputStream(file)
}

fun KeycloakUriInfo.baseUrl(): String = this.baseUri.toString().let { if (it.endsWith("/")) it else "$it/" }
