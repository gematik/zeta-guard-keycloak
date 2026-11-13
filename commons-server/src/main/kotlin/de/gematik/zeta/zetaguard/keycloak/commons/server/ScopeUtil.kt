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

private const val SCOPE_DELIMITER = " "

fun String?.toScopes(): Set<String> = this?.split(SCOPE_DELIMITER)?.filter { it.isNotBlank() }?.toSet() ?: emptySet()

/**
 * Validates a `scope` parameter according to RFC 6749, section 3.3:
 * ```
 * scope       = scope-token *( SP scope-token )
 * scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
 * ```
 * I.e. a non-empty list of tokens separated by exactly one space (no leading/trailing/double spaces), each consisting of
 * printable ASCII characters except space, `"` and `\`.
 *
 * @return the distinct scope tokens in order of appearance (order is irrelevant per RFC 6749), or an `invalid_scope` error
 */
fun String?.isValidScope() = toScopes().none { it.containsInvalidScopeTokenChar() }

/** %x21 / %x23-5B / %x5D-7E */
private fun Char.isValidScopeTokenChar() = this == '!' || this in '#'..'[' || this in ']'..'~'

internal fun String.containsInvalidScopeTokenChar() = any { !it.isValidScopeTokenChar() }

fun Collection<String>.toScope() = joinToString(SCOPE_DELIMITER)
