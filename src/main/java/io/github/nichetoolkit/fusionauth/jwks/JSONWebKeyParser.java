
package io.github.nichetoolkit.fusionauth.jwks;

import io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyType;
import io.github.nichetoolkit.fusionauth.pem.PEMEncoder;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

import static io.github.nichetoolkit.fusionauth.jwks.JWKUtils.base64DecodeUint;

/**
 * <code>JSONWebKeyParser</code>
 * <p>The json web key parser class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JSONWebKeyParser {

  /**
   * <code>parse</code>
   * <p>The parse method.</p>
   * @param key {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The key parameter is <code>JSONWebKey</code> type.</p>
   * @return {@link java.security.PublicKey} <p>The parse return object is <code>PublicKey</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   * @see java.security.PublicKey
   */
  public PublicKey parse(JSONWebKey key) {
    Objects.requireNonNull(key);

    try {
      // RSA Public key
      if (key.kty == KeyType.RSA) {
        BigInteger modulus = base64DecodeUint(key.n);
        BigInteger publicExponent = base64DecodeUint(key.e);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        // If an x5c is found in the key, verify the public key
        if (key.x5c != null && key.x5c.size() > 0) {
          verifyX5cRSA(key, modulus, publicExponent);
        }

        return publicKey;
      } else if (key.kty == KeyType.EC) {
        // EC Public key
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        switch (key.crv) {
          case "P-256":
            parameters.init(new ECGenParameterSpec("secp256r1"));
            break;
          case "P-384":
            parameters.init(new ECGenParameterSpec("secp384r1"));
            break;
          case "P-521":
            parameters.init(new ECGenParameterSpec("secp521r1"));
            break;
          default:
            throw new UnsupportedOperationException("Unsupported EC algorithm. Support algorithms include P-256, P-384 and P-521.");
        }

        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger xCoordinate = base64DecodeUint(key.x);
        BigInteger yCoordinate = base64DecodeUint(key.y);
        ECPoint ecPoint = new ECPoint(xCoordinate, yCoordinate);
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));

        // If an x5c is found in the key, verify the public key
        if (key.x5c != null && key.x5c.size() > 0) {
          verifyX5cEC(key, xCoordinate, yCoordinate);
        }

        return publicKey;
      }
    } catch (JSONWebKeyParserException e) {
      throw e;
    } catch (Exception e) {
      throw new JSONWebKeyParserException("Failed to parse the provided JSON Web Key", e);
    }

    throw new UnsupportedOperationException("Only RSA or EC JSON Web Keys may be parsed.");
  }

  private void verifyX5cEC(JSONWebKey key, BigInteger expectedXCoordinate, BigInteger expectedYCoordinate) {
    // The first key in this array MUST contain the public key.
    // >  https://tools.ietf.org/html/rfc7517#section-4.7
    String encodedCertificate = key.x5c.get(0);
    String pem = new PEMEncoder().parseEncodedCertificate(encodedCertificate);
    PublicKey actual = PEM.decode(pem).publicKey;
    if (!(actual instanceof ECPublicKey)) {
      throw new JSONWebKeyParserException("The public key found in the [x5c] property does not match the expected key type specified by the [kty] property.");
    }

    ECPublicKey ecPublicKey = (ECPublicKey) actual;
    ECPoint point = ecPublicKey.getW();

    if (!point.getAffineX().equals(expectedXCoordinate)) {
      throw new JSONWebKeyParserException("Expected an x coordinate value of [" + expectedXCoordinate + "] but found [" + point.getAffineX() + "].  The certificate found in [x5c] does not match the [x] coordinate property.");
    }

    //noinspection SuspiciousNameCombination
    if (!point.getAffineY().equals(expectedYCoordinate)) {
      throw new JSONWebKeyParserException("Expected a y coordinate value of [" + expectedYCoordinate + "] but found [" + point.getAffineY() + "].  The certificate found in [x5c] does not match the [y] coordinate property.");
    }
  }


  private void verifyX5cRSA(JSONWebKey key, BigInteger expectedModulus, BigInteger expectedPublicExponent) {
    // The first key in this array MUST contain the public key.
    // >  https://tools.ietf.org/html/rfc7517#section-4.7
    String encodedCertificate = key.x5c.get(0);
    String pem = new PEMEncoder().parseEncodedCertificate(encodedCertificate);
    PublicKey actual = PEM.decode(pem).publicKey;

    if (!(actual instanceof RSAPublicKey)) {
      throw new JSONWebKeyParserException("The public key found in the [x5c] property does not match the expected key type specified by the [kty] property.");
    }

    RSAPublicKey rsaPublicKey = (RSAPublicKey) actual;
    if (!rsaPublicKey.getModulus().equals(expectedModulus)) {
      throw new JSONWebKeyParserException("Expected a modulus value of [" + expectedModulus + "] but found [" + rsaPublicKey.getModulus() + "].  The certificate found in [x5c] does not match the [n] property.");
    }

    if (!rsaPublicKey.getPublicExponent().equals(expectedPublicExponent)) {
      throw new JSONWebKeyParserException("Expected a public exponent value of [" + expectedPublicExponent + "] but found [" + rsaPublicKey.getPublicExponent() + "].  The certificate found in [x5c] does not match the [e] property.");
    }
  }
}
