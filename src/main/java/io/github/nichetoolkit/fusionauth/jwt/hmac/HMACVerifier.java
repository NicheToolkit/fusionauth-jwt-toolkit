
package io.github.nichetoolkit.fusionauth.jwt.hmac;

import io.github.nichetoolkit.fusionauth.jwt.InvalidJWTSignatureException;
import io.github.nichetoolkit.fusionauth.jwt.JWTVerifierException;
import io.github.nichetoolkit.fusionauth.jwt.Verifier;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * <code>HMACVerifier</code>
 * <p>The hmac verifier class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Verifier
 * @since Jdk17
 */
public class HMACVerifier implements Verifier {
  private final byte[] secret;

  private HMACVerifier(String secret) {
    Objects.requireNonNull(secret);
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  private HMACVerifier(byte[] secret) {
    Objects.requireNonNull(secret);
    this.secret = secret;
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param secret {@link java.lang.String} <p>The secret parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACVerifier} <p>The new verifier return object is <code>HMACVerifier</code> type.</p>
   * @see java.lang.String
   */
  public static HMACVerifier newVerifier(String secret) {
    Objects.requireNonNull(secret);
    return new HMACVerifier(secret);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACVerifier} <p>The new verifier return object is <code>HMACVerifier</code> type.</p>
   * @see java.nio.file.Path
   */
  public static HMACVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new HMACVerifier(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.hmac.HMACVerifier} <p>The new verifier return object is <code>HMACVerifier</code> type.</p>
   */
  public static HMACVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new HMACVerifier(bytes);
  }

  @Override
  @SuppressWarnings("Duplicates")
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case HS256:
      case HS384:
      case HS512:
        return true;
      default:
        return false;
    }
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Mac mac = Mac.getInstance(algorithm.getName());
      mac.init(new SecretKeySpec(secret, algorithm.getName()));
      byte[] actualSignature = mac.doFinal(message);

      if (!MessageDigest.isEqual(signature, actualSignature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
