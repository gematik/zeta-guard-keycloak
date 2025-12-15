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

import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.crypto.AsymmetricSignatureSignerContext
import org.keycloak.crypto.AsymmetricSignatureVerifierContext
import org.keycloak.crypto.ECDSASignatureSignerContext
import org.keycloak.crypto.ECDSASignatureVerifierContext
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKBuilder
import org.keycloak.util.JWKSUtils.getKeyWrapper

const val RSA_SIGNATURE_ALGORITHM = "SHA256WithRSA"
const val ECDSA_SIGNATURE_ALGORITHM = "SHA256WithECDSA"
const val CURVE_BRAINPOOL = "brainpoolP256r1"
const val CURVE_DEFAULT = "SECP256R1"

object PKIUtil {
  init {
    setupBouncyCastle()
    CryptoIntegration.init(javaClass.getClassLoader())
  }

  fun generateECKeyPair(curveName: String = CURVE_DEFAULT): KeyPair {
    try {
      val keyGen = CryptoIntegration.getProvider().getKeyPairGen("EC")
      val randomGen = SecureRandom.getInstance("SHA1PRNG")
      val ecSpec = ECGenParameterSpec(curveName)
      keyGen.initialize(ecSpec, randomGen)

      return keyGen.generateKeyPair()
    } catch (e: Exception) {
      throw RuntimeException(e)
    }
  }

  fun generateECKeys(): ECKeys = ECKeys(generateECKeyPair())
}

data class ECKeys(val keypair: KeyPair) {
  val jwk: JWK by lazy { JWKBuilder.create().ec(keypair.public) }
  val jwks: JSONWebKeySet by lazy { JSONWebKeySet().apply { keys = arrayOf(jwk) } }
}

private fun KeyPair.unsupportedOperationException() = public.unsupportedOperationException()

private fun PublicKey.unsupportedOperationException(): UnsupportedOperationException =
    UnsupportedOperationException("Public key type $javaClass not supported.")

fun KeyPair.createVerifierContext(): SignatureVerifierContext {
  val jwk = public.createJWK()
  val key =
      getKeyWrapper(jwk, true).apply {
        publicKey = public
        privateKey = private
      }

  return when (public) {
    is ECPublicKey -> ECDSASignatureVerifierContext(key)
    is RSAPublicKey -> AsymmetricSignatureVerifierContext(key)

    else -> throw unsupportedOperationException()
  }
}

fun KeyPair.createSignerContext(): SignatureSignerContext {
  val jwk = public.createJWK()
  val key =
      getKeyWrapper(jwk, true).apply {
        publicKey = public
        privateKey = private
      }

  return when (public) {
    is ECPublicKey -> ECDSASignatureSignerContext(key)
    is RSAPublicKey -> AsymmetricSignatureSignerContext(key)

    else -> throw unsupportedOperationException()
  }
}

fun PublicKey.createJWK(): JWK =
    when (this) {
      is ECPublicKey -> JWKBuilder.create().ec(this)
      is RSAPublicKey -> JWKBuilder.create().rs256(this)

      else -> throw unsupportedOperationException()
    }

fun KeyPair.signingAlgorithm() =
    when (public) {
      is ECPublicKey -> ECDSA_SIGNATURE_ALGORITHM
      is RSAPublicKey -> RSA_SIGNATURE_ALGORITHM

      else -> throw unsupportedOperationException()
    }
