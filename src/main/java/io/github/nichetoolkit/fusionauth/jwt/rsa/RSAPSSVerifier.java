
package io.github.nichetoolkit.fusionauth.jwt.rsa;

import io.github.nichetoolkit.fusionauth.jwt.InvalidJWTSignatureException;
import io.github.nichetoolkit.fusionauth.jwt.InvalidKeyLengthException;
import io.github.nichetoolkit.fusionauth.jwt.InvalidKeyTypeException;
import io.github.nichetoolkit.fusionauth.jwt.JWTVerifierException;
import io.github.nichetoolkit.fusionauth.jwt.MissingPublicKeyException;
import io.github.nichetoolkit.fusionauth.jwt.Verifier;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/**
 * <code>RSAPSSVerifier</code>
 * <p>The rsapss verifier class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Verifier
 * @since Jdk17
 */
public class RSAPSSVerifier implements Verifier {
  private final RSAPublicKey publicKey;

  private RSAPSSVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);

    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = (RSAPublicKey) publicKey;
    assertValidKeyLength();
  }

  private RSAPSSVerifier(String publicKey) {
    Objects.requireNonNull(publicKey);

    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }
    if (!(pem.publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
    assertValidKeyLength();
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param publicKey {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSVerifier} <p>The new verifier return object is <code>RSAPSSVerifier</code> type.</p>
   * @see java.security.PublicKey
   */
  public static RSAPSSVerifier newVerifier(PublicKey publicKey) {
    return new RSAPSSVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param publicKey {@link java.lang.String} <p>The public key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSVerifier} <p>The new verifier return object is <code>RSAPSSVerifier</code> type.</p>
   * @see java.lang.String
   */
  public static RSAPSSVerifier newVerifier(String publicKey) {
    return new RSAPSSVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSVerifier} <p>The new verifier return object is <code>RSAPSSVerifier</code> type.</p>
   * @see java.nio.file.Path
   */
  public static RSAPSSVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new RSAPSSVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAPSSVerifier} <p>The new verifier return object is <code>RSAPSSVerifier</code> type.</p>
   */
  public static RSAPSSVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new RSAPSSVerifier((new String(bytes)));
  }

  @Override
  @SuppressWarnings("Duplicates")
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case PS256:
      case PS384:
      case PS512:
        return true;
      default:
        return false;
    }
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Signature verifier = Signature.getInstance("RSASSA-PSS");
      verifier.setParameter(new PSSParameterSpec(algorithm.getName(), "MGF1", new MGF1ParameterSpec(algorithm.getName()), algorithm.getSaltLength(), 1));
      verifier.initVerify(publicKey);
      verifier.update(message);
      if (!verifier.verify(signature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException |
             InvalidAlgorithmParameterException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }

  private void assertValidKeyLength() {
    int keyLength = this.publicKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }
}
