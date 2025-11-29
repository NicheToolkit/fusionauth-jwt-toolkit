
package io.github.nichetoolkit.fusionauth.jwt.rsa;

import io.github.nichetoolkit.fusionauth.jwt.InvalidKeyLengthException;
import io.github.nichetoolkit.fusionauth.jwt.InvalidKeyTypeException;
import io.github.nichetoolkit.fusionauth.jwt.JWTSigningException;
import io.github.nichetoolkit.fusionauth.jwt.MissingPrivateKeyException;
import io.github.nichetoolkit.fusionauth.jwt.Signer;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/**
 * <code>RSAPSSSigner</code>
 * <p>The rsapss signer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Signer
 * @since Jdk17
 */
public class RSAPSSSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final RSAPrivateKey privateKey;

  private RSAPSSSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;

    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [RSAPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = (RSAPrivateKey) privateKey;
    int keyLength = this.privateKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }

  private RSAPSSSigner(Algorithm algorithm, String privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [RSAPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = pem.getPrivateKey();
    int keyLength = this.privateKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 256 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA256Signer(String privateKey) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 256 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA256Signer(String privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, kid);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 256 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static RSAPSSSigner newSHA256Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, null);
  }

  /**
   * <code>newSHA256Signer</code>
   * <p>The new sha 256 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 256 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 384 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA384Signer(String privateKey) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 384 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA384Signer(String privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, kid);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 384 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static RSAPSSSigner newSHA384Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, null);
  }

  /**
   * <code>newSHA384Signer</code>
   * <p>The new sha 384 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 384 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 512 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA512Signer(String privateKey) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 512 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA512Signer(String privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, kid);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 512 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static RSAPSSSigner newSHA512Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, null);
  }

  /**
   * <code>newSHA512Signer</code>
   * <p>The new sha 512 signer method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param kid        {@link java.lang.String} <p>The kid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSSigner} <p>The new sha 512 signer return object is <code>RSAPSSSigner</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.lang.String
   */
  public static RSAPSSSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, kid);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getKid() {
    return kid;
  }

  public byte[] sign(String message) {
    Objects.requireNonNull(message);

    try {
      Signature signature = Signature.getInstance("RSASSA-PSS");
      signature.setParameter(new PSSParameterSpec(algorithm.getName(), "MGF1", new MGF1ParameterSpec(algorithm.getName()), algorithm.getSaltLength(), 1));
      signature.initSign(privateKey);
      signature.update(message.getBytes(StandardCharsets.UTF_8));
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException |
             InvalidAlgorithmParameterException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
