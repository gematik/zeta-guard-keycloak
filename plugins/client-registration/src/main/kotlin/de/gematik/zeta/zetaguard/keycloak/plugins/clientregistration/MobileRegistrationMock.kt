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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

val MOCK_MOBILE_CLIENT_STATEMENT: String =
    """
    {
      "sub": "mock-mobile-client-instance",
      "platform": "apple",
      "posture_type": "apple",
      "attestation_timestamp": 1753272000,
      "posture": {
        "platform_product_id": {
          "platform": "apple",
          "platform_type": "ios",
          "app_bundle_ids": ["de.gematik.epa.ios"]
        },
        "product_id": "demo_client",
        "product_version": "0.1.0",
        "system_version": "17.5.1",
        "system_name": "iOS",
        "device_model": "iPhone15,3",
        "key_id": "AAAAmockKeyIdBase64==",
        "fmt": "apple-appattest",
        "attStmt": {
          "x5c": ["MIIEmockCredentialCert==", "MIIDmockIntermediateCert=="],
          "receipt": "MIImockAppleReceipt=="
        },
        "authData": {
          "rpidHash": "0000mockRelyingPartyIdHash=",
          "flags": "0x41",
          "counter": 0,
          "aaguid": "appattestdevelop",
          "credentialId": "mockCredentialIdPublicKeyHash="
        },
        "signature": "MEUCIQmockAppleAssertionSignature==",
        "assertionAuthenticatorData": {
          "rpidHash": "0000mockRelyingPartyIdHash=",
          "counter": 1
        },
        "client_data_json": "{\"challenge\":\"mock-nonce-from-pdp\"}"
      }
    }
    """
        .trimIndent()
