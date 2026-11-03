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
package de.gematik.zeta.zetaguard.keycloak.commons.clientregistration

/**
 * Legacy / Software Attestation.
 *
 * `attestation_type` is optional here (Jackson's [ZetaGuardOIDCClientRequestRepresentation] discriminator falls back to this type when the property
 * is absent, matching the schema's 1.0.0 → 1.1.0 backward-compatibility note). [signedHashPukClientSig] and [nonce] remain
 * optional for the same legacy-compatibility reason.
 *
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 */
class SoftwareRegistrationRequest : ZetaGuardOIDCClientRequestRepresentation(AttestationType.SOFTWARE)
