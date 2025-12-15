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

object ProfessionOidValidator {
  // https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html
  // At least 5 numbers with 1-3 digits each, separated by dots, Root-OID 1.2.276.0.76
  val PROFESSION_OID_FORMAT = "^(\\d{1,3}\\.){4}\\d{1,3}(\\.\\d{1,3})*$".toRegex()

  fun isValidProfessionOidFormat(professionOid: String) = PROFESSION_OID_FORMAT.matches(professionOid)

  fun isValidProfessionOidSmcb(professionOid: String) = VALID_PROFESSION_OIDS_SMCB.contains(professionOid)

  val VALID_PROFESSION_OIDS_SMCB =
      setOf(
          "1.2.276.0.76.4.50",
          "1.2.276.0.76.4.51",
          "1.2.276.0.76.4.52",
          "1.2.276.0.76.4.53",
          "1.2.276.0.76.4.54",
          "1.2.276.0.76.4.55",
          "1.2.276.0.76.4.56",
          "1.2.276.0.76.4.57",
          "1.2.276.0.76.4.58",
          "1.2.276.0.76.4.59",
          "1.2.276.0.76.4.187",
          "1.2.276.0.76.4.190",
          "1.2.276.0.76.4.210",
          "1.2.276.0.76.4.223",
          "1.2.276.0.76.4.226",
          "1.2.276.0.76.4.227",
          "1.2.276.0.76.4.228",
          "1.2.276.0.76.4.224",
          "1.2.276.0.76.4.225",
          "1.2.276.0.76.4.229",
          "1.2.276.0.76.4.230",
          "1.2.276.0.76.4.231",
          "1.2.276.0.76.4.242",
          "1.2.276.0.76.4.243",
          "1.2.276.0.76.4.244",
          "1.2.276.0.76.4.245",
          "1.2.276.0.76.4.246",
          "1.2.276.0.76.4.247",
          "1.2.276.0.76.4.248",
          "1.2.276.0.76.4.249",
          "1.2.276.0.76.4.250",
          "1.2.276.0.76.4.251",
          "1.2.276.0.76.4.252",
          "1.2.276.0.76.4.253",
          "1.2.276.0.76.4.254",
          "1.2.276.0.76.4.255",
          "1.2.276.0.76.4.256",
          "1.2.276.0.76.4.257",
          "1.2.276.0.76.4.273",
          "1.2.276.0.76.4.262",
          "1.2.276.0.76.4.263",
          "1.2.276.0.76.4.264",
          "1.2.276.0.76.4.265",
          "1.2.276.0.76.4.266",
          "1.2.276.0.76.4.267",
          "1.2.276.0.76.4.268",
          "1.2.276.0.76.4.269",
          "1.2.276.0.76.4.270",
          "1.2.276.0.76.4.271",
          "1.2.276.0.76.4.278",
          "1.2.276.0.76.4.279",
          "1.2.276.0.76.4.280",
          "1.2.276.0.76.4.281",
          "1.2.276.0.76.4.284",
          "1.2.276.0.76.4.285",
          "1.2.276.0.76.4.286",
          "1.2.276.0.76.4.282",
      )
}
