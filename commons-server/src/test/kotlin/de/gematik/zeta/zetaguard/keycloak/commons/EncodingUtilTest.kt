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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDuration
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import de.gematik.zeta.zetaguard.keycloak.commons.server.toLocalDateTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPEM
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Duration
import java.time.LocalDateTime
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWKBuilder

const val certificateString =
    "MIIBhTCCASugAwIBAgIIJYeZrjYFMjwwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLemV0YS1jbGllbnQwHhcNMjUxMTEyMTMxODA5WhcNMzAxMTExMTMxODA5WjAWMRQwEgYDVQQDDAt6ZXRhLWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGTNHQYjYArg4W7RI36QCsFvZ1spE8M+LdNcG0/JLe6qe54Ysa5vYKWTqbAyyJV/IE+h39EvDcYW9GxQt7X5C1SjYzBhMB0GA1UdDgQWBBQEMVq8EZWM+iqIF5ZjW5MxiYrCTjAfBgNVHSMEGDAWgBQEMVq8EZWM+iqIF5ZjW5MxiYrCTjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAhmDEJ4Ibwy+elyh8gEiZEL4kdB1ms6qFRkapZaniPEcCIFqzmqBod4tom3adyY/77zkwyzvIz1lNOB9Vp30rVwN8"

class EncodingUtilTest : FunSpec() {
  init {
    test("ISO-8601 conversion") {
      val dateTime = LocalDateTime.of(2011, 7, 16, 16, 58, 25)
      val iso8601 = "2011-07-16T16:58:25"

      dateTime.toISO8601() shouldBe iso8601
      iso8601.toLocalDateTime() shouldBe dateTime
    }

    test("Duration conversion") {
      val duration = Duration.ofSeconds(5)
      val iso8601 = "PT5S"

      duration.toString() shouldBe iso8601
      iso8601.toDuration() shouldBe duration
    }

    test("Certificate conversion") {
      val certificate = certificateString.toCertificate()
      val jwk = JWKBuilder.create().ec(certificate.publicKey)
      val jwks = JSONWebKeySet().apply { keys = arrayOf(jwk) }
      val jwksJSON = jwks.toJSON()
      val pem = certificate.publicKey.toPEM()

      jwksJSON shouldContain "\"kid\":\"3c9d8y3D2uENHN_loz9JMbJmgIQ_gYfnG7gJruCkv7E\""
      pem shouldContain "-----BEGIN PUBLIC KEY-----"
    }
  }

  companion object {
    init {
      setupSecurityProviders()
    }
  }
}
