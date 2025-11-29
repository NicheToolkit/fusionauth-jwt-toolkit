
package io.github.nichetoolkit.fusionauth.jwks;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * <code>JWKUtils</code>
 * <p>The jwk utils class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JWKUtils {
  /**
   * <code>base64DecodeUint</code>
   * <p>The base 64 decode uint method.</p>
   * @param encoded {@link java.lang.String} <p>The encoded parameter is <code>String</code> type.</p>
   * @return {@link java.math.BigInteger} <p>The base 64 decode uint return object is <code>BigInteger</code> type.</p>
   * @see java.lang.String
   * @see java.math.BigInteger
   */
  public static BigInteger base64DecodeUint(String encoded) {
    byte[] bytes = Base64.getUrlDecoder().decode(encoded);
    if (bytes.length % 8 == 0 && bytes[0] != 0) {
      byte[] copy = new byte[bytes.length + 1];
      copy[0] = 0;
      System.arraycopy(bytes, 0, copy, 1, bytes.length);
      return new BigInteger(copy);
    }

    return new BigInteger(bytes);
  }

  /**
   * <code>base64EncodeUint</code>
   * <p>The base 64 encode uint method.</p>
   * @param value {@link java.math.BigInteger} <p>The value parameter is <code>BigInteger</code> type.</p>
   * @return {@link java.lang.String} <p>The base 64 encode uint return object is <code>String</code> type.</p>
   * @see java.math.BigInteger
   * @see java.lang.String
   */
  public static String base64EncodeUint(BigInteger value) {
    return base64EncodeUint(value, -1);
  }

  /**
   * <code>base64EncodeUint</code>
   * <p>The base 64 encode uint method.</p>
   * @param value         {@link java.math.BigInteger} <p>The value parameter is <code>BigInteger</code> type.</p>
   * @param minimumLength int <p>The minimum length parameter is <code>int</code> type.</p>
   * @return {@link java.lang.String} <p>The base 64 encode uint return object is <code>String</code> type.</p>
   * @see java.math.BigInteger
   * @see java.lang.String
   */
  public static String base64EncodeUint(BigInteger value, int minimumLength) {
    if (value.signum() < 0) {
      throw new JSONWebKeyBuilderException("Illegal parameter, cannot encode a negative number.", new IllegalArgumentException());
    }

    byte[] bytes = value.toByteArray();
    if ((value.bitLength() % 8 == 0) && (bytes[0] == 0) && bytes.length > 1) {
      bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
    }

    if (minimumLength != -1) {
      if (bytes.length < minimumLength) {
        byte[] buf = new byte[minimumLength];
        System.arraycopy(bytes, 0, buf, (minimumLength - bytes.length), bytes.length);
        bytes = buf;
      }
    }

    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
