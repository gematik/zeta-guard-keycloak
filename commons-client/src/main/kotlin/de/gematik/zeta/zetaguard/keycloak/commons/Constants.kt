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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import org.bouncycastle.asn1.ASN1ObjectIdentifier

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

const val TELEMATIK_ID = "1-20014060625"
const val TELEMATIK_ID2 = "1-10.3.9876541000.10.249"

const val CRT_GEMATIK_ROOT = "gem.smcb-ca1_test-only"
const val CRT_GEMATIK_ROOT_DN = "CN=GEM.RCA1 TEST-ONLY, OU=Zentrale Root-CA der Telematikinfrastruktur, O=gematik GmbH NOT-VALID, C=DE"
const val CRT_GEMATIK_INTERMEDIATE = "gem.smcb-ca57_test-only"
const val CRT_GEMATIK_INTERMEDIATE_DN =
    "C=DE, O=gematik GmbH NOT-VALID, OU=Institution des Gesundheitswesens-CA der Telematikinfrastruktur, CN=GEM.SMCB-CA8 TEST-ONLY"
const val CRT_GEMATIK_LEAF = "zeta.c_smcb_aut"
const val CRT_GEMATIK_LEAF_NAME = "Arztpraxis Ann-Beatrixe Zeta TEST-ONLY"
const val CRT_GEMATIK_LEAF_ORGANISATION = "300060625 NOT-VALID"
const val CRT_GEMATIK_LEAF_DN = "C=DE, O=$CRT_GEMATIK_LEAF_ORGANISATION, CN=$CRT_GEMATIK_LEAF_NAME"

const val BETRIEBSSTAETTE_ARZT = "Betriebsstätte Arzt"
const val PRODUCT_ID = "𝛇-Guard client"
const val PRODUCT_VERSION = "3.1415.93"

// https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#3.5.1.3
val betriebsstaetteArzt = ASN1ObjectIdentifier("1.2.276.0.76.4.50")
val gematikPolicy = ASN1ObjectIdentifier("1.2.276.0.76.4.163")
val smcbAuth = ASN1ObjectIdentifier("1.2.276.0.76.4.77")
