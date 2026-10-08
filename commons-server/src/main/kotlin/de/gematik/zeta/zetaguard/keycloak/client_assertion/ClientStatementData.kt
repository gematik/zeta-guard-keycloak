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
package de.gematik.zeta.zetaguard.keycloak.client_assertion

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import java.beans.ConstructorProperties

const val PROPERTY_PLATFORM = "platform"
const val PROPERTY_CLIENT_SUBJECT = "sub"
const val PROPERTY_POSTURE_TYPE = "posture_type"
const val PROPERTY_POSTURE = "posture"
const val PROPERTY_ATTESTATION_TIMESTAMP = "attestation_timestamp"

/**
 * JSON classes for Client statement
 *
 * The Client Statement is used in the Client Assertion JWT with the ZETA Guard AuthServer. It contains information about the client instance.
 *
 * @see [https://github.com/gematik/zeta/blob/main/src/schemas/client-statement.yaml]
 */
data class ClientStatementData
@ConstructorProperties(PROPERTY_CLIENT_SUBJECT, PROPERTY_PLATFORM, PROPERTY_POSTURE_TYPE, PROPERTY_POSTURE, PROPERTY_ATTESTATION_TIMESTAMP)
constructor(
    @field:JsonProperty(PROPERTY_CLIENT_SUBJECT) val clientId: String,
    @field:JsonProperty(PROPERTY_PLATFORM) val platform: Platform,
    @field:JsonProperty(PROPERTY_POSTURE_TYPE) val postureType: PostureType,
    @field:JsonProperty(PROPERTY_POSTURE)
    @field:JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXTERNAL_PROPERTY, property = PROPERTY_POSTURE_TYPE, visible = true)
    @field:JsonSubTypes(
        value =
            [
                JsonSubTypes.Type(value = AndroidPosture::class, name = "android"),
                JsonSubTypes.Type(value = ApplePosture::class, name = "apple"),
                JsonSubTypes.Type(value = SoftwarePosture::class, name = "software"),
                JsonSubTypes.Type(value = TPMPosture::class, name = "tpm"),
            ]
    )
    val posture: Posture,
    @field:JsonProperty(PROPERTY_ATTESTATION_TIMESTAMP) val attestationTimestamp: Long,
)
