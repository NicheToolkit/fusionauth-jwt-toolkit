
package io.github.nichetoolkit.fusionauth.jwks;

import io.github.nichetoolkit.fusionauth.der.DerInputStream;
import io.github.nichetoolkit.fusionauth.der.DerValue;
import io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey;
import io.github.nichetoolkit.fusionauth.jwt.JWTUtils;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyType;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;
import io.github.nichetoolkit.fusionauth.security.KeyUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Objects;

import static io.github.nichetoolkit.fusionauth.der.ObjectIdentifier.ECDSA_P256;
import static io.github.nichetoolkit.fusionauth.der.ObjectIdentifier.ECDSA_P384;
import static io.github.nichetoolkit.fusionauth.der.ObjectIdentifier.ECDSA_P521;
import static io.github.nichetoolkit.fusionauth.jwks.JWKUtils.base64EncodeUint;

/**
 * <code>JSONWebKeyBuilder</code>
 * <p>The json web key builder class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JSONWebKeyBuilder {
  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param encodedPEM {@link java.lang.String} <p>The encoded pem parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   */
  public JSONWebKey build(String encodedPEM) {
    Objects.requireNonNull(encodedPEM);
    PEM pem = PEM.decode(encodedPEM);
    if (pem.privateKey != null) {
      return build(pem.privateKey);
    } else if (pem.certificate != null) {
      // Prefer the certificate if available
      return build(pem.certificate);
    } else if (pem.publicKey != null) {
      return build(pem.publicKey);
    }

    throw new JSONWebKeyBuilderException("The provided PEM did not contain a public or private key.");
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.PrivateKey
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   */
  public JSONWebKey build(PrivateKey privateKey) {
    Objects.requireNonNull(privateKey);
    JSONWebKey key = new JSONWebKey();

    key.kty = getKeyType(privateKey);
    key.use = "sig";
    if (privateKey instanceof RSAPrivateKey rsaPrivateKey) {
      key.n = base64EncodeUint(rsaPrivateKey.getModulus());
      key.d = base64EncodeUint(rsaPrivateKey.getPrivateExponent());
    }

    // If this is a CRT (Chinese Remainder Theorem) private key, collect additional information
    if (privateKey instanceof RSAPrivateCrtKey rsaPrivateKey) {
      key.e = base64EncodeUint(rsaPrivateKey.getPublicExponent());
      key.p = base64EncodeUint(rsaPrivateKey.getPrimeP());
      key.q = base64EncodeUint(rsaPrivateKey.getPrimeQ());
      key.qi = base64EncodeUint(rsaPrivateKey.getCrtCoefficient());

      // d mod (p-1)
      BigInteger dp = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeP().subtract(BigInteger.valueOf(1)));
      // d mod (q-1)
      BigInteger dq = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeQ().subtract(BigInteger.valueOf(1)));

      key.dp = base64EncodeUint(dp);
      key.dq = base64EncodeUint(dq);
    }

    if (privateKey instanceof ECPrivateKey ecPrivateKey) {
      key.crv = getCurveOID(privateKey);
      if (key.crv != null) {
        switch (key.crv) {
          case "P-256":
            key.alg = Algorithm.ES256;
            break;
          case "P-384":
            key.alg = Algorithm.ES384;
            break;
          case "P-521":
            key.alg = Algorithm.ES512;
            break;
        }
      }

      int byteLength = getCoordinateLength(ecPrivateKey);
      key.d = base64EncodeUint(ecPrivateKey.getS(), byteLength);
      key.x = base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineX(), byteLength);
      key.y = base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineY(), byteLength);
    }

    return key;
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param publicKey {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.PublicKey
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   */
  public JSONWebKey build(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    JSONWebKey key = new JSONWebKey();

    key.kty = getKeyType(publicKey);
    key.use = "sig";
    if (publicKey instanceof RSAPublicKey rsaPublicKey) {
      key.e = base64EncodeUint(rsaPublicKey.getPublicExponent());
      key.n = base64EncodeUint(rsaPublicKey.getModulus());
    } else if (key.kty == KeyType.EC) {
      ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
      key.crv = getCurveOID(ecPublicKey);

      int length = KeyUtils.getKeyLength(publicKey);
      if (length == 256) {
        key.alg = Algorithm.ES256;
      } else if (length == 384) {
        key.alg = Algorithm.ES384;
      } else if (length == 521) {
        key.alg = Algorithm.ES512;
      }

      int byteLength = getCoordinateLength(ecPublicKey);
      key.x = base64EncodeUint(ecPublicKey.getW().getAffineX(), byteLength);
      key.y = base64EncodeUint(ecPublicKey.getW().getAffineY(), byteLength);
    }

    return key;
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param certificate {@link java.security.cert.Certificate} <p>The certificate parameter is <code>Certificate</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.cert.Certificate
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   */
  public JSONWebKey build(Certificate certificate) {
    Objects.requireNonNull(certificate);
    JSONWebKey key = build(certificate.getPublicKey());
    if (certificate instanceof X509Certificate) {
      if (key.alg == null) {
        key.alg = Algorithm.fromName(((X509Certificate) certificate).getSigAlgName());
      }

      try {
        String encodedCertificate = new String(Base64.getEncoder().encode(certificate.getEncoded()));
        key.x5c = Collections.singletonList(encodedCertificate);
        key.x5t = JWTUtils.generateJWS_x5t(encodedCertificate);
        key.x5t_256 = JWTUtils.generateJWS_x5t("SHA-256", encodedCertificate);
      } catch (CertificateEncodingException e) {
        throw new JSONWebKeyBuilderException("Failed to decode X.509 certificate", e);
      }
    }
    return key;
  }

  private int getCoordinateLength(ECKey key) {
    return (int) Math.ceil(key.getParams().getCurve().getField().getFieldSize() / 8d);
  }

  private KeyType getKeyType(Key key) {
    if (key.getAlgorithm().equals("RSA")) {
      return KeyType.RSA;
    } else if (key.getAlgorithm().equals("EC")) {
      return KeyType.EC;
    }

    return null;
  }

  private String readCurveObjectIdentifier(Key key) {
    try {
      DerValue[] sequence = new DerInputStream(key.getEncoded()).getSequence();
      if (key instanceof PrivateKey) {
        // Read the first value in the sequence, it is the algorithm OID, the second will be the curve
        sequence[1].getOID();
        return sequence[1].getOID().decode();
      } else {
        // Read the first value in the sequence, it is the algorithm OID, the second will be the curve
        sequence[0].getOID();
        return sequence[0].getOID().decode();
      }
    } catch (IOException e) {
      throw new JSONWebKeyBuilderException("Unable to read the Object Identifier of the public key.", e);
    }
  }

  /**
   * <code>getCurveOID</code>
   * <p>The get curve oid getter method.</p>
   * @param key {@link java.security.Key} <p>The key parameter is <code>Key</code> type.</p>
   * @return {@link java.lang.String} <p>The get curve oid return object is <code>String</code> type.</p>
   * @see java.security.Key
   * @see java.lang.String
   */
  String getCurveOID(Key key) {
    // Match up the Curve Object Identifier to a string value
    String oid = readCurveObjectIdentifier(key);
    return switch (oid) {
      case ECDSA_P256 -> "P-256";
      case ECDSA_P384 -> "P-384";
      case ECDSA_P521 -> "P-521";
      default -> null;
    };
  }
}
