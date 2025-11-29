
package io.github.nichetoolkit.fusionauth.jwt.hmac;

import io.github.nichetoolkit.fusionauth.jwt.JWTSigningException;
import io.github.nichetoolkit.fusionauth.jwt.Signer;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * <code>HMACSigner</code>
 * <p>The hmac signer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Signer
 * @since Jdk17
 */
public class HMACSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final byte[] secret;

  private HMACSigner(Algorithm algorithm, byte[] secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);

    this.algorithm = algorithm;
    this.kid = kid;
    this.secret = secret;
  }

  private HMACSigner(Algorithm algorithm, String secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);

    this.algorithm = algorithm;
    this.kid = kid;
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 256 signer return object is <code>HMACSigner</code> type.</p>
   */
  public static HMACSigner newSHA256Signer(byte[] secret) {
    return newSHA256Signer(secret, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 256 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA256Signer(String secret) {
    return newSHA256Signer(secret, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 256 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA256Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 256 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA256Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 384 signer return object is <code>HMACSigner</code> type.</p>
   */
  public static HMACSigner newSHA384Signer(byte[] secret) {
    return newSHA384Signer(secret, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 384 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA384Signer(String secret) {
    return newSHA384Signer(secret, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 384 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA384Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 384 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA384Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 512 signer return object is <code>HMACSigner</code> type.</p>
   */
  public static HMACSigner newSHA512Signer(byte[] secret) {
    return newSHA512Signer(secret, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 512 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA512Signer(String secret) {
    return newSHA512Signer(secret, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param secret byte <p>The secret parameter is <code>byte</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 512 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA512Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @param kid    {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACSigner} <p>The new sha 512 signer return object is <code>HMACSigner</code> type.</p>
   * @see java.lang.String
   */
  public static HMACSigner newSHA512Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getKid() {
    return kid;
  }

  @Override
  public byte[] sign(String message) {
    Objects.requireNonNull(message);

    try {
      Mac mac = Mac.getInstance(algorithm.getName());
      mac.init(new SecretKeySpec(secret, algorithm.getName()));
      return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
