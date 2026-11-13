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

/**
 * @see [Tabelle 2: Tab_PKI_402-01 OID-Festlegung Rolle im X.509-Zertifikat für Berufsgruppen](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#polarion___1)
 */
internal const val OID_VERSICHERTER = "1.2.276.0.76.4.49"

/**
 * @see [Tabelle 2: Tab_PKI_402-01 OID-Festlegung Rolle im X.509-Zertifikat für Berufsgruppen](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#polarion___1)
 */
internal val PROFESSION_OIDS = setOf(
    "1.2.276.0.76.4.30",
    "1.2.276.0.76.4.31",
    "1.2.276.0.76.4.32",
    "1.2.276.0.76.4.33",
    "1.2.276.0.76.4.34",
    "1.2.276.0.76.4.35",
    "1.2.276.0.76.4.36",
    "1.2.276.0.76.4.37",
    "1.2.276.0.76.4.38",
    "1.2.276.0.76.4.39",
    "1.2.276.0.76.4.40",
    "1.2.276.0.76.4.41",
    "1.2.276.0.76.4.42",
    "1.2.276.0.76.4.43",
    "1.2.276.0.76.4.44",
    "1.2.276.0.76.4.45",
    "1.2.276.0.76.4.46",
    "1.2.276.0.76.4.47",
    "1.2.276.0.76.4.48",
    OID_VERSICHERTER,
    "1.2.276.0.76.4.178",
    "1.2.276.0.76.4.232",
    "1.2.276.0.76.4.233",
    "1.2.276.0.76.4.234",
    "1.2.276.0.76.4.235",
    "1.2.276.0.76.4.236",
    "1.2.276.0.76.4.237",
    "1.2.276.0.76.4.238",
    "1.2.276.0.76.4.239",
    "1.2.276.0.76.4.240",
    "1.2.276.0.76.4.241",
    "1.2.276.0.76.4.274",
    "1.2.276.0.76.4.275",
    "1.2.276.0.76.4.276",
    "1.2.276.0.76.4.277",
)

/**
 * @see [Tabelle 2: Tab_PKI_402-01 OID-Festlegung Rolle im X.509-Zertifikat für Berufsgruppen](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#polarion___1)
 */
fun String?.isBerufsgruppenOID(): Boolean = this in PROFESSION_OIDS

fun String?.isVersichertenOID(): Boolean = this == OID_VERSICHERTER

/**
 * @see [Tabelle 3: Tab_PKI_403-04 OID-Festlegung Institutionen im X.509-Zertifikat der SMC-B](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#polarion___2)
 */
fun String?.isInstitutsOID(): Boolean = this in ProfessionOidValidator.VALID_PROFESSION_OIDS_SMCB
