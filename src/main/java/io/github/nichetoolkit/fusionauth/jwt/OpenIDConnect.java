
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * <code>OpenIDConnect</code>
 * <p>The open id connect class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class OpenIDConnect {

  /**
   * <code>at_hash</code>
   * <p>The at hash method.</p>
   * @param accessToken {@link java.lang.String} <p>The access token parameter is <code>String</code> type.</p>
   * @param algorithm   {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @return {@link java.lang.String} <p>The at hash return object is <code>String</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  public static String at_hash(String accessToken, Algorithm algorithm) {
    return generate_hash(accessToken, algorithm);
  }

  /**
   * <code>c_hash</code>
   * <p>The c hash method.</p>
   * @param authorizationCode {@link java.lang.String} <p>The authorization code parameter is <code>String</code> type.</p>
   * @param algorithm         {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @return {@link java.lang.String} <p>The c hash return object is <code>String</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  public static String c_hash(String authorizationCode, Algorithm algorithm) {
    return generate_hash(authorizationCode, algorithm);
  }

  private static String generate_hash(String string, Algorithm algorithm) {
    Objects.requireNonNull(string);
    Objects.requireNonNull(algorithm);

    int leftMostBits;
    MessageDigest messageDigest;
    switch (algorithm) {
      case ES256:
      case HS256:
      case RS256:
        messageDigest = getDigest("SHA-256");
        leftMostBits = 128;
        break;
      case ES384:
      case HS384:
      case RS384:
        messageDigest = getDigest("SHA-384");
        leftMostBits = 192;
        break;
      case ES512:
      case HS512:
      case RS512:
        messageDigest = getDigest("SHA-512");
        leftMostBits = 256;
        break;
      default:
        throw new IllegalArgumentException("You specified an unsupported algorithm. The algorithm [" + algorithm + "]"
            + " is not supported. You must use ES256, ES384, ES512,  HS256, HS384, HS512, RS256, RS384 or RS512.");
    }

    byte[] digest = string.getBytes(StandardCharsets.UTF_8);
    digest = messageDigest.digest(digest);

    int toIndex = Math.min(digest.length, leftMostBits / 8);
    byte[] leftMostBytes = Arrays.copyOfRange(digest, 0, toIndex);

    return new String(Base64.getUrlEncoder().withoutPadding().encode(leftMostBytes));
  }

  private static MessageDigest getDigest(String digest) {
    try {
      return MessageDigest.getInstance(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
