

package io.github.nichetoolkit.fusionauth.security;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;

/**
 * <code>KeyUtils</code>
 * <p>The key utils class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class KeyUtils {

  /**
   * <code>getKeyLength</code>
   * <p>The get key length getter method.</p>
   * @param key {@link java.security.Key} <p>The key parameter is <code>Key</code> type.</p>
   * @return int <p>The get key length return object is <code>int</code> type.</p>
   * @see java.security.Key
   */
  public static int getKeyLength(Key key) {
    if (key instanceof ECKey) {
      int bytes;
      if (key instanceof ECPublicKey ecPublicKey) {
        bytes = ecPublicKey.getW().getAffineX().toByteArray().length;
      } else {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
        bytes = ecPrivateKey.getS().toByteArray().length;
      }

      if (bytes >= 63 && bytes <= 66) {
        return 521;
      }

      // If bytes is not a multiple of 8, add the difference to get to the next 8 byte boundary
      int mod = bytes % 8;
      // Adjust the length for a mod count of anything equal to or greater than 2.
      if (mod >= 2) {
        bytes = bytes + (8 - mod);
      }

      return ((bytes / 8) * 8) * 8;
    } else if (key instanceof RSAKey rsaKey) {
      return rsaKey.getModulus().bitLength();
    }

    throw new IllegalArgumentException();
  }
}
