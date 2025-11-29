
package io.github.nichetoolkit.fusionauth.jwt.ec;

import io.github.nichetoolkit.fusionauth.jwt.InvalidKeyTypeException;
import io.github.nichetoolkit.fusionauth.jwt.JWTSigningException;
import io.github.nichetoolkit.fusionauth.jwt.MissingPrivateKeyException;
import io.github.nichetoolkit.fusionauth.jwt.Signer;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * <code>ECSigner</code>
 * <p>The ec signer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Signer
 * @since Jdk17
 */
public class ECSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final ECPrivateKey privateKey;

  private ECSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;

    if (!(privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = (ECPrivateKey) privateKey;
  }

  private ECSigner(Algorithm algorithm, String privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = pem.getPrivateKey();
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 256 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA256Signer(String privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 256 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA256Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 256 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 256 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 384 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA384Signer(String privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 384 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA384Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 384 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 384 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 512 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA512Signer(String privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 512 signer return object is <code>ECSigner</code> type.</p>
   * @see java.lang.String
   */
  public static ECSigner newSHA512Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 512 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECSigner} <p>The new sha 512 signer return object is <code>ECSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
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
      // In later versions of the JDK you can request a non DER encoded signature so we don't have to re-encode it.
      // - We could revisit this in the future if we want to depend on a later version of Java.
      //   To request the version we want, you can append "inP1363Format" to the algorithm name.
      //   Example : ES256inP1363Format instead of ES256.
      Signature signature = Signature.getInstance(algorithm.getName());
      signature.initSign(privateKey);
      signature.update((message).getBytes(StandardCharsets.UTF_8));
      byte[] derEncoded = signature.sign();

      return new ECDSASignature(derEncoded).derDecode(algorithm);
    } catch (InvalidKeyException | IOException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
