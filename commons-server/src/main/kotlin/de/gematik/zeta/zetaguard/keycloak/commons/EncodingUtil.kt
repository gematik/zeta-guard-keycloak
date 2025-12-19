/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.SerializationFeature
import org.keycloak.util.JsonSerialization

object EncodingUtil {
  init {
    JsonSerialization.mapper.configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
    @Suppress("DEPRECATION") //
    JsonSerialization.mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
  }

  fun Any.toJSON(): String = JsonSerialization.writeValueAsString(this)

  @Suppress("UNCHECKED_CAST") //
  fun Any.asMap(): Map<String, Any> = JsonSerialization.mapper.convertValue(this, Map::class.java) as Map<String, Any>

  inline fun <reified T> String.toObject(): T = JsonSerialization.readValue(this, T::class.java)

  inline fun <reified T> Map<String, Any>.toObject(): T = JsonSerialization.mapper.convertValue(this, T::class.java)
}
