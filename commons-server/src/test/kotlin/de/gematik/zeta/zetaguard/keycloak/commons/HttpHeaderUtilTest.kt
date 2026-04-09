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

import io.kotest.matchers.shouldBe

class HttpHeaderUtilTest : ZetaGuardFunSpec() {
  init {
    context(
        """
            Forwarded header format (RFC 7239): https://datatracker.ietf.org/doc/html/rfc7239#section-4"""
    ) {
      test("should extract IPv4 from Forwarded header") {
        "for=192.168.0.1".toForwardedHeader() shouldBe "192.168.0.1"
        "for=192.168.0.1;proto=http".toForwardedHeader() shouldBe "192.168.0.1"
        "for=192.0.2.60;proto=http;by=203.0.113.43;host=example.com".toForwardedHeader() shouldBe "192.0.2.60"
        "for=192.0.2.43, for=198.51.100.17".toForwardedHeader() shouldBe "192.0.2.43"
      }

      test("should extract IPv6 from Forwarded header") {
        "for=[2001:db8:cafe::17]".toForwardedHeader() shouldBe "2001:db8:cafe::17"
        "for=\"[2001:db8:cafe::17]:4711\"".toForwardedHeader() shouldBe "2001:db8:cafe::17"
      }

      test("should return null for invalid Forwarded header") {
        "invalid".toForwardedHeader() shouldBe null
        "proto=http".toForwardedHeader() shouldBe null
      }
    }

    context("""X-Forwarded-For header format:  X-Forwarded-For: client, proxy1, proxy2""") {
      test("should extract first IP from X-Forwarded-For header") {
        "192.168.0.1, 10.0.0.1".toXForwardedForHeader() shouldBe "192.168.0.1"
        "192.168.0.1:8080, 10.0.0.1".toXForwardedForHeader() shouldBe "192.168.0.1"
      }

      test("should extract IPv6 from X-Forwarded-For header") {
        "[2001:db8:cafe::17]:4711, 10.0.0.1".toXForwardedForHeader() shouldBe "2001:db8:cafe::17"
      }
    }

    context("toIPAddress") {
      test("should handle IPv4 with port") { "192.168.0.1:8080".toIPAddress() shouldBe "192.168.0.1" }

      test("should handle IPv6 with port and brackets") {
        "[2001:db8:cafe::17]:4711".toIPAddress() shouldBe "2001:db8:cafe::17"
        "[2001:db8:cafe::17]".toIPAddress() shouldBe "2001:db8:cafe::17"
      }

      test("should handle plain IP") {
        "192.168.0.1".toIPAddress() shouldBe "192.168.0.1"
        "2001:db8:cafe::17".toIPAddress() shouldBe "2001:db8:cafe::17"
      }

      test("should trim whitespace") { "  192.168.0.1  ".toIPAddress() shouldBe "192.168.0.1" }

      test("should return null for blank string") {
        "".toIPAddress() shouldBe null
        "   ".toIPAddress() shouldBe null
      }
    }
  }
}
