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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec

/**
 * Derives the PublicKey from a given PrivateKey.
 *
 * @return The corresponding PublicKey.
 * @throws UnsupportedOperationException if the key type is not RSA or EC.
 */
fun PrivateKey.getPublicKey(): PublicKey {
  return when (this) {
    /**
     * --- RSA KEYS --- We must be able to cast to RSAPrivateCrtKey (CRT stands for Chinese Remainder Theorem). This interface provides access to the
     * modulus AND the public exponent, which are the two components of an RSA public key.
     */
    is RSAPrivateCrtKey -> {
      println("Key is RSA. Using modulus and public exponent.")
      val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
      val pubKeySpec = RSAPublicKeySpec(modulus, publicExponent)

      keyFactory.generatePublic(pubKeySpec)
    }

    /**
     * --- EC (Elliptic Curve) KEYS ---
     *
     * The public key is a point (W) on the curve. This point is calculated by multiplying the curve's generator (G) by the private key's scalar (S).
     *
     * W = G * S
     *
     * We need Bouncy Castle's internal math libraries to perform this elliptic curve point multiplication.
     */
    is ECPrivateKey -> {
      val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
      val point = parameters.g.multiply(d) // g is the generator point, part of the spec.
      val pubKeySpec = ECPublicKeySpec(point, parameters)

      keyFactory.generatePublic(pubKeySpec)
    }

    else -> throw UnsupportedOperationException("Unsupported private key type: $algorithm")
  }
}
