
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey;
import io.github.nichetoolkit.fusionauth.jwt.domain.Header;
import io.github.nichetoolkit.fusionauth.jwt.domain.JWT;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyType;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import static io.github.nichetoolkit.fusionauth.jwt.domain.KeyType.EC;

/**
 * <code>JWTUtils</code>
 * <p>The jwt utils class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JWTUtils {
  /**
   * <code>convertFingerprintToThumbprint</code>
   * <p>The convert fingerprint to thumbprint method.</p>
   * @param fingerprint {@link java.lang.String} <p>The fingerprint parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The convert fingerprint to thumbprint return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String convertFingerprintToThumbprint(String fingerprint) {
    byte[] bytes = HexUtils.toBytes(fingerprint);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * <code>convertThumbprintToFingerprint</code>
   * <p>The convert thumbprint to fingerprint method.</p>
   * @param x5tHash {@link java.lang.String} <p>The x 5 t hash parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The convert thumbprint to fingerprint return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String convertThumbprintToFingerprint(String x5tHash) {
    byte[] bytes = Base64.getUrlDecoder().decode(x5tHash.getBytes(StandardCharsets.UTF_8));
    return HexUtils.fromBytes(bytes);
  }

  /**
   * <code>decodeHeader</code>
   * <p>The decode header method.</p>
   * @param encodedJWT {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.Header} <p>The decode header return object is <code>Header</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Header
   */
  public static Header decodeHeader(String encodedJWT) {
    Objects.requireNonNull(encodedJWT);

    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return Mapper.deserialize(Base64.getUrlDecoder().decode(parts[0]), Header.class);
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  /**
   * <code>decodePayload</code>
   * <p>The decode payload method.</p>
   * @param encodedJWT {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode payload return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public static JWT decodePayload(String encodedJWT) {
    Objects.requireNonNull(encodedJWT);

    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return Mapper.deserialize(Base64.getUrlDecoder().decode(parts[1]), JWT.class);
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  /**
   * <code>generate2048_RSAKeyPair</code>
   * <p>The generate 2048 rsa key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 2048 rsa key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate2048_RSAKeyPair() {
    return generateKeyPair(2048, KeyType.RSA);
  }

  /**
   * <code>generate256_ECKeyPair</code>
   * <p>The generate 256 ec key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 256 ec key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate256_ECKeyPair() {
    return generateKeyPair(256, EC);
  }

  /**
   * <code>generate3072_RSAKeyPair</code>
   * <p>The generate 3072 rsa key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 3072 rsa key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate3072_RSAKeyPair() {
    return generateKeyPair(3072, KeyType.RSA);
  }

  /**
   * <code>generate384_ECKeyPair</code>
   * <p>The generate 384 ec key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 384 ec key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate384_ECKeyPair() {
    return generateKeyPair(384, EC);
  }

  /**
   * <code>generate4096_RSAKeyPair</code>
   * <p>The generate 4096 rsa key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 4096 rsa key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate4096_RSAKeyPair() {
    return generateKeyPair(4096, KeyType.RSA);
  }

  /**
   * <code>generate521_ECKeyPair</code>
   * <p>The generate 521 ec key pair method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair} <p>The generate 521 ec key pair return object is <code>KeyPair</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyPair
   */
  public static KeyPair generate521_ECKeyPair() {
    return generateKeyPair(521, EC);
  }

  /**
   * <code>generateJWS_kid</code>
   * <p>The generate jws kid method.</p>
   * @param algorithm {@link java.lang.String} <p>The algorithm parameter is <code>String</code> type.</p>
   * @param key       {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The key parameter is <code>JSONWebKey</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws kid return object is <code>String</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   */
  public static String generateJWS_kid(String algorithm, JSONWebKey key) {
    Map<String, Object> thumbPrint = new LinkedHashMap<>(4);

    if (key.kty == EC) {
      thumbPrint.put("crv", key.crv);
      thumbPrint.put("kty", key.kty);
      thumbPrint.put("x", key.x);
      thumbPrint.put("y", key.y);
    } else {
      thumbPrint.put("e", key.e);
      thumbPrint.put("kty", key.kty);
      thumbPrint.put("n", key.n);
    }

    return digest(algorithm, Mapper.serialize(thumbPrint));
  }

  /**
   * <code>generateJWS_kid</code>
   * <p>The generate jws kid method.</p>
   * @param key {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The key parameter is <code>JSONWebKey</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws kid return object is <code>String</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   * @see java.lang.String
   */
  public static String generateJWS_kid(JSONWebKey key) {
    return generateJWS_kid("SHA-1", key);
  }

  /**
   * <code>generateJWS_kid_S256</code>
   * <p>The generate jws kid s 256 method.</p>
   * @param key {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The key parameter is <code>JSONWebKey</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws kid s 256 return object is <code>String</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey
   * @see java.lang.String
   */
  public static String generateJWS_kid_S256(JSONWebKey key) {
    return generateJWS_kid("SHA-256", key);
  }

  /**
   * <code>generateJWS_x5t</code>
   * <p>The generate jws x 5 t method.</p>
   * @param encodedCertificate {@link java.lang.String} <p>The encoded certificate parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws x 5 t return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateJWS_x5t(String encodedCertificate) {
    return generateJWS_x5t("SHA-1", encodedCertificate);
  }

  /**
   * <code>generateJWS_x5t</code>
   * <p>The generate jws x 5 t method.</p>
   * @param algorithm          {@link java.lang.String} <p>The algorithm parameter is <code>String</code> type.</p>
   * @param encodedCertificate {@link java.lang.String} <p>The encoded certificate parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws x 5 t return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateJWS_x5t(String algorithm, String encodedCertificate) {
    byte[] bytes = Base64.getDecoder().decode(encodedCertificate.getBytes(StandardCharsets.UTF_8));
    return generateJWS_x5t(algorithm, bytes);
  }

  /**
   * <code>generateJWS_x5t</code>
   * <p>The generate jws x 5 t method.</p>
   * @param derEncodedCertificate byte <p>The der encoded certificate parameter is <code>byte</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws x 5 t return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateJWS_x5t(byte[] derEncodedCertificate) {
    return generateJWS_x5t("SHA-1", derEncodedCertificate);
  }

  /**
   * <code>generateJWS_x5t</code>
   * <p>The generate jws x 5 t method.</p>
   * @param algorithm             {@link java.lang.String} <p>The algorithm parameter is <code>String</code> type.</p>
   * @param derEncodedCertificate byte <p>The der encoded certificate parameter is <code>byte</code> type.</p>
   * @return {@link java.lang.String} <p>The generate jws x 5 t return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateJWS_x5t(String algorithm, byte[] derEncodedCertificate) {
    return digest(algorithm, derEncodedCertificate);
  }

  /**
   * <code>generateSHA256_HMACSecret</code>
   * <p>The generate sha 256 hmac secret method.</p>
   * @return {@link java.lang.String} <p>The generate sha 256 hmac secret return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateSHA256_HMACSecret() {
    return generateSecureRandom(32);
  }

  /**
   * <code>generateSHA384_HMACSecret</code>
   * <p>The generate sha 384 hmac secret method.</p>
   * @return {@link java.lang.String} <p>The generate sha 384 hmac secret return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateSHA384_HMACSecret() {
    return generateSecureRandom(48);
  }

  /**
   * <code>generateSHA512_HMACSecret</code>
   * <p>The generate sha 512 hmac secret method.</p>
   * @return {@link java.lang.String} <p>The generate sha 512 hmac secret return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateSHA512_HMACSecret() {
    return generateSecureRandom(64);
  }

  /**
   * <code>generateSecureRandom</code>
   * <p>The generate secure random method.</p>
   * @param bytes int <p>The bytes parameter is <code>int</code> type.</p>
   * @return {@link java.lang.String} <p>The generate secure random return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String generateSecureRandom(int bytes) {
    byte[] buffer = new byte[bytes];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  private static String digest(String algorithm, byte[] bytes) {
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("No such algorithm [" + algorithm + "]");
    }

    byte[] digest = messageDigest.digest(bytes);
    return new String(Base64.getUrlEncoder().withoutPadding().encode(digest));
  }

  private static KeyPair generateKeyPair(int keySize, KeyType keyType) {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyType.name());
      keyPairGenerator.initialize(keySize);
      java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String privateKey = PEM.encode(keyPair.getPrivate(), keyPair.getPublic());
      String publicKey = PEM.encode(keyPair.getPublic());
      return new KeyPair(privateKey, publicKey);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
