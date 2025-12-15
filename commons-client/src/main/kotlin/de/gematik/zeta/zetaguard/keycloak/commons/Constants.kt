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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

const val KC_HOST = "localhost"
const val KC_PORT = 18080

const val ADMIN_REALM = "master"
const val ADMIN_CLIENT = "admin-cli"

const val USER1 = "user1"
const val USER1_PASSWORD = "password"
const val ADMIN_USER = "zeta"
const val ADMIN_PASSWORD = "sigma"

const val CLIENT_A_ID = "initial-client"
const val CLIENT_A_SCOPE = "audience-requester-scope"

// Client performing the exchange (confidential)
const val CLIENT_B_ID = "requester-client"
const val CLIENT_B_SECRET = "qXpy5mlykWglKNSvs65N8sjNXRZDJDwH"
const val CLIENT_B_SCOPE = "audience-target-scope"

// Target client for the new token (audience)
const val CLIENT_C_ID = "target-client"
const val CLIENT_C_SECRET = "jnG1UuQzWgQROtjhU1ku9YlsRsupzL5o"

const val ZETA = "\uD835\uDEC7"
const val ZETA_GUARD_CLIENT_NAME = "$ZETA-Guard client"

const val VALID_TELEMATIK_ID = "1-10.3.9876540000.10.246"
const val TELEMATIK_ID2 = "1-10.3.9876541000.10.249"
