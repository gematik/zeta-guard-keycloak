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

package de.gematik.zeta.zetaguard.keycloak.commons.server

import arrow.core.Either
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.PemUtils
import org.keycloak.crypto.AsymmetricSignatureSignerContext
import org.keycloak.crypto.AsymmetricSignatureVerifierContext
import org.keycloak.crypto.ECDSASignatureSignerContext
import org.keycloak.crypto.ECDSASignatureVerifierContext
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.jose.jwk.ECPublicJWK
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKBuilder
import org.keycloak.jose.jwk.JWKParser
import org.keycloak.util.JWKSUtils.computeThumbprint
import org.keycloak.util.JWKSUtils.getKeyWrapper

const val RSA_SIGNATURE_ALGORITHM = "SHA256WithRSA"
const val ECDSA_SIGNATURE_ALGORITHM = "SHA256WithECDSA"
const val EC_CURVE_P256 = "SECP256R1"

private const val P256_MAGIC: Byte = 0x04

fun generateKeyPair(curveName: String = EC_CURVE_P256): KeyPair {
  try {
    val keyGen = CryptoIntegration.getProvider().getKeyPairGen(ECPublicJWK.EC)
    val randomGen = SecureRandom()
    val ecSpec = ECGenParameterSpec(curveName)
    keyGen.initialize(ecSpec, randomGen)

    return keyGen.generateKeyPair()
  } catch (e: Exception) {
    throw RuntimeException(e)
  }
}

/**
 * Compute the raw RFC 7638 Thumbprint of a JWK
 *
 * @See [https://datatracker.ietf.org/doc/html/rfc7638]
 * @See [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1]
 */
fun JWK.toThumbprint(): ByteArray = computeThumbprint(this).fromBase64()

fun PublicKey.toThumbprint(): ByteArray = this.toJWK().toThumbprint()

data class PKIData(val keypair: KeyPair) {
  val jwk: JWK by lazy { keypair.toJWK() }
  val jwks: JSONWebKeySet by lazy { JSONWebKeySet().apply { keys = arrayOf(jwk) } }
  val jwkThumbPrint: ByteArray by lazy { jwk.toThumbprint() }
  val publicKeyPEM: String by lazy { keypair.public.toPEM() }
}

fun KeyPair.toJWK(): JWK = public.toJWK()

fun PublicKey.toJWK(): JWK = JWKBuilder.create().ec(this)

/**
 * A DPoP proof header must embed only the mandatory public-key JWK members (RFC 7638: kty/crv/x/y for EC). Keycloak's [JWKBuilder] always
 * populates `kid` and `use` (and sometimes `alg`); strip them so the embedded JWK stays schema-compliant. A fresh JWK is built from the public key,
 * so shared/cached instances are not mutated.
 */
fun PublicKey.toMinimalJWK(): JWK =
    toJWK().apply {
      keyId = null
      algorithm = null
      publicKeyUse = null
    }

fun generatePKIData(): PKIData = PKIData(generateKeyPair())

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
      val keyFactory = KeyFactory.getInstance("RSA", PROVIDER_NAME)
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
      val keyFactory = KeyFactory.getInstance("EC", PROVIDER_NAME)
      val point = parameters.g.multiply(d) // g is the generator point, part of the spec.
      val pubKeySpec = ECPublicKeySpec(point, parameters)

      keyFactory.generatePublic(pubKeySpec)
    }

    else -> throw UnsupportedOperationException("Unsupported private key type: $algorithm")
  }
}

fun PublicKey.createVerifierContext(): SignatureVerifierContext {
  val jwk = createJWK()
  val key = getKeyWrapper(jwk, true).apply { publicKey = this@createVerifierContext }

  return when (this) {
    is ECPublicKey -> ECDSASignatureVerifierContext(key)
    is RSAPublicKey -> AsymmetricSignatureVerifierContext(key)

    else -> throw unsupportedOperationException()
  }
}

fun KeyPair.createSignerContext(includeKid: Boolean = true): SignatureSignerContext {
  val jwk = public.createJWK()
  val key =
      getKeyWrapper(jwk, true).apply {
        publicKey = public
        privateKey = private
        // JWKBuilder auto-populates a kid that JWSBuilder would otherwise emit as the JOSE `kid` header.
        // Clearing it produces a token without `header.kid` (verified via x5c, so no kid is needed).
        if (!includeKid) kid = null
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

fun KeyPair.unsupportedOperationException() = public.unsupportedOperationException()

fun PublicKey.unsupportedOperationException(): UnsupportedOperationException =
    UnsupportedOperationException("Public key type $javaClass not supported.")

fun JWK.toPublicKey(): PublicKey = JWKParser.create(this).toPublicKey()

fun String.toJWKS(): JSONWebKeySet = toObject<JSONWebKeySet>()

/**
 * Convert a string containing either a PEM-encoded public key or a base64-encoded raw/DER EC public key to a Java PublicKey.
 *
 * If the input is in PEM format the Keycloak PemUtils utility is used. Otherwise, this attempts to decode the input as an EC public key (possibly in
 * raw P-256 form).
 */
fun String.toPublicKey(): Either<String, PublicKey> =
    Either.catch {
          if (isPEMFormat()) {
            PemUtils.decodePublicKey(this)
          } else {
            decodeECPublicKey()
          }
        }
        .mapLeft { it.message ?: "Could not extract public key from $this" }

/**
 * Decode a base64-encoded EC public key into a Java PublicKey instance.
 *
 * Supported forms:
 * - Raw P-256 public key without the leading 0x04 magic byte (64 bytes): this function will prepend the 0x04.
 * - Raw P-256 public key with the 0x04 magic byte (65 bytes): used as-is.
 * - Any other length is treated as a full X.509/DER encoded key and parsed via an X509EncodedKeySpec.
 */
private fun String.decodeECPublicKey(): PublicKey {
  val rawBytes = fromBase64()

  val bytes =
      when (rawBytes.size) {
        // Raw P-256 key without magic header
        64 ->
            ByteArray(65).apply {
              this[0] = P256_MAGIC
              System.arraycopy(rawBytes, 0, this, 1, 64)
            }
        // Raw P-256 key
        65 -> {
          require(rawBytes[0] == P256_MAGIC) { "Expected 0x04 byte header for P-256 key" }
          rawBytes
        }
        else -> {
          val spec = X509EncodedKeySpec(rawBytes)
          return KeyFactory.getInstance("EC", PROVIDER_NAME).generatePublic(spec)
        }
      }

  val params = ECNamedCurveTable.getParameterSpec(EC_CURVE_P256)
  val point = params.curve.decodePoint(bytes)
  val spec = ECNamedCurveSpec(EC_CURVE_P256, params.curve, params.g, params.n, params.h, params.seed)
  val keySpec = java.security.spec.ECPublicKeySpec(ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger()), spec)

  return KeyFactory.getInstance("EC", PROVIDER_NAME).generatePublic(keySpec)
}
