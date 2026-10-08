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

private val FORWARDED_PAIR_REGEX = """for=(\S+)""".toRegex(RegexOption.IGNORE_CASE)
private val QUOTED_IPV6_AND_OPTIONAL_PORT_REGEX = """"?\[(\S+)(:\d+)?]"?""".toRegex(RegexOption.IGNORE_CASE)
private val IPV4_AND_OPTIONAL_PORT_REGEX = """(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?""".toRegex(RegexOption.IGNORE_CASE)
/**
 * Bare (unbracketed) IPv6, as it occurs in X-Forwarded-For and X-Real-IP — "Forwarded" requires the bracketed form. Deliberately conservative rather
 * than a full RFC 4291 grammar: hex groups with at least two colons, an optional IPv4-mapped tail and an optional zone id. Anything else is not an
 * address and must not be treated as one.
 */
private val BARE_IPV6_REGEX = """[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}(\.\d{1,3}){0,3}(%[0-9A-Za-z._-]+)?""".toRegex()

/**
 * Parse RFC 7239 "Forwarded" header, looking for IP address
 *
 * @see [RFC 7239](https://datatracker.ietf.org/doc/html/rfc7239#section-4]
 */
fun String.toForwardedHeader(): String? =
    split(";") // forwarded-elements
        .flatMap { it.split(",") } // forwarded-pairs
        .map { it.trim() }
        // First pair that actually carries "for=": RFC 7239 puts no ordering
        // constraint on the pairs of an element, so "for=" is not necessarily the
        // first one (e.g. "by=_proxy;for=192.0.2.60").
        .firstNotNullOfOrNull {
          FORWARDED_PAIR_REGEX.find(it)?.groupValues?.get(1) // value = token / quoted-string
        }
        ?.toIPAddress()

fun String.toXForwardedForHeader(): String? = split(",").firstOrNull()?.toIPAddress()

fun resolveClientIP(remoteAddr: String?, httpHeader: (String) -> String?): String? =
    httpHeader("Forwarded")?.toForwardedHeader()
    ?: httpHeader("X-Forwarded-For")?.toXForwardedForHeader()
        ?: httpHeader("X-Real-IP")?.toIPAddress()
        ?: remoteAddr?.takeIf { it.isNotBlank() }

/**
 * Extract an IP address from a header value, or null if it does not contain one.
 *
 * Returns null rather than the input on no match: the value is client-supplied, and whatever comes out of here ends up as an identity claim that is
 * later compared against the address of every request.
 */
fun String.toIPAddress(): String? =
    trim()
        .let {
          QUOTED_IPV6_AND_OPTIONAL_PORT_REGEX.find(it)?.groupValues?.get(1) // Try IPv6 first
          ?: IPV4_AND_OPTIONAL_PORT_REGEX.find(it)?.groupValues?.get(1) // IPv4
              ?: BARE_IPV6_REGEX.matchEntire(it)?.value // unbracketed IPv6
        }
        ?.takeIf { it.isNotBlank() }
