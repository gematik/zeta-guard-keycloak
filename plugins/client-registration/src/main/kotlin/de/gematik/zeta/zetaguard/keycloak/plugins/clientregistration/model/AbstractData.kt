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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model

import jakarta.persistence.Column
import jakarta.persistence.Id
import jakarta.persistence.MappedSuperclass
import java.time.LocalDateTime
import java.util.Objects
import org.apache.commons.lang3.builder.ToStringBuilder
import org.apache.commons.lang3.builder.ToStringStyle.NO_FIELD_NAMES_STYLE

const val COLUMN_ID = "ID"
const val COLUMN_LAST_ACCESS = "LAST_ACCESS"
const val COLUMN_CREATED_AT = "CREATED_AT"

/**
 * @property id The unique identifier of the entity.
 * @property createdAt The timestamp when the entity was created.
 * @property lastAccess The timestamp when the entity was last accessed.
 */
@Suppress("JpaEntityWithValAttributesInspection")
@MappedSuperclass
abstract class AbstractData(
    @Id @Column(name = COLUMN_ID, nullable = false, updatable = false, length = 255) //
    val id: String,
    @Column(name = COLUMN_CREATED_AT, nullable = false) //
    val createdAt: LocalDateTime,
    @Column(name = COLUMN_LAST_ACCESS, nullable = false) //
    var lastAccess: LocalDateTime,
) {
  override fun equals(other: Any?): Boolean =
      when {
        this === other -> true

        other?.javaClass != this.javaClass -> false

        else -> this.id == (other as AbstractData).id
      }

  override fun hashCode(): Int = Objects.hashCode(id) + javaClass.hashCode()

  override fun toString(): String = ToStringBuilder.reflectionToString(this, NO_FIELD_NAMES_STYLE)
}
