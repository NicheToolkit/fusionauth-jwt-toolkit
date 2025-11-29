
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * <code>RSAVerifier</code>
 * <p>The rsa verifier class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Verifier
 * @since Jdk17
 */
public class RSAVerifier implements Verifier {
  private final RSAPublicKey publicKey;

  private RSAVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);

    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = (RSAPublicKey) publicKey;
    assertValidKeyLength();
  }

  private RSAVerifier(String publicKey) {
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
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAVerifier} <p>The new verifier return object is <code>RSAVerifier</code> type.</p>
   * @see java.security.PublicKey
   */
  public static RSAVerifier newVerifier(PublicKey publicKey) {
    return new RSAVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param publicKey {@link java.lang.String} <p>The public key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAVerifier} <p>The new verifier return object is <code>RSAVerifier</code> type.</p>
   * @see java.lang.String
   */
  public static RSAVerifier newVerifier(String publicKey) {
    return new RSAVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAVerifier} <p>The new verifier return object is <code>RSAVerifier</code> type.</p>
   * @see java.nio.file.Path
   */
  public static RSAVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new RSAVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.rsa.RSAVerifier} <p>The new verifier return object is <code>RSAVerifier</code> type.</p>
   */
  public static RSAVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new RSAVerifier((new String(bytes)));
  }

  @Override
  @SuppressWarnings("Duplicates")
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case RS256:
      case RS384:
      case RS512:
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
      Signature verifier = Signature.getInstance(algorithm.getName());
      verifier.initVerify(publicKey);
      verifier.update(message);
      if (!verifier.verify(signature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }

  private void assertValidKeyLength() {
    int keyLength = this.publicKey.getModulus().bitLength();
    // We would normally expect 2048, but it turns out it is possible for an RSA key to be generated of length 2047.
    if (keyLength < 2047) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }
}
