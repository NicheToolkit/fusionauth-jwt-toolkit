
package io.github.nichetoolkit.fusionauth.jwt.ec;

import io.github.nichetoolkit.fusionauth.jwt.InvalidJWTSignatureException;
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
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * <code>ECVerifier</code>
 * <p>The ec verifier class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Verifier
 * @since Jdk17
 */
public class ECVerifier implements Verifier {
  private final ECPublicKey publicKey;

  private ECVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);

    if (!(publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [ECPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = (ECPublicKey) publicKey;
  }

  private ECVerifier(String publicKey) {
    Objects.requireNonNull(publicKey);

    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }

    if (!(pem.publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [ECPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param publicKey {@link java.lang.String} <p>The public key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECVerifier} <p>The new verifier return object is <code>ECVerifier</code> type.</p>
   * @see java.lang.String
   */
  public static ECVerifier newVerifier(String publicKey) {
    return new ECVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param publicKey {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECVerifier} <p>The new verifier return object is <code>ECVerifier</code> type.</p>
   * @see java.security.PublicKey
   */
  public static ECVerifier newVerifier(PublicKey publicKey) {
    return new ECVerifier(publicKey);
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECVerifier} <p>The new verifier return object is <code>ECVerifier</code> type.</p>
   * @see java.nio.file.Path
   */
  public static ECVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new ECVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * <code>newVerifier</code>
   * <p>The new verifier method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.ec.ECVerifier} <p>The new verifier return object is <code>ECVerifier</code> type.</p>
   */
  public static ECVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new ECVerifier(new String(bytes));
  }

  @Override
  @SuppressWarnings("Duplicates")
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case ES256:
      case ES384:
      case ES512:
        return true;
      default:
        return false;
    }
  }

  private void checkFor_CVE_2022_21449(byte[] signature) {
    int half = signature.length / 2;

    boolean rOk = false;
    boolean sOk = false;
    for (int i = 0; i < signature.length; i++) {
      if (i < half) {
        rOk = signature[i] != 0;
        if (rOk) {
          i = half - 1;
        }
      } else {
        sOk = signature[i] != 0;
        if (sOk) {
          break;
        }
      }
    }

    if (!rOk || !sOk) {
      throw new InvalidJWTSignatureException();
    }
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    checkFor_CVE_2022_21449(signature);

    try {
      Signature verifier = Signature.getInstance(algorithm.getName());
      verifier.initVerify(publicKey);
      verifier.update(message);

      byte[] derEncoded = new ECDSASignature(signature).derEncode();
      if (!(verifier.verify(derEncoded))) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | IOException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
