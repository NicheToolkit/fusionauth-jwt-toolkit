
package io.github.nichetoolkit.fusionauth.jwt.domain;

import java.util.Objects;

import static io.github.nichetoolkit.fusionauth.der.ObjectIdentifier.EC_ENCRYPTION;
import static io.github.nichetoolkit.fusionauth.der.ObjectIdentifier.RSA_ENCRYPTION;

/**
 * <code>KeyType</code>
 * <p>The key type enumeration.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public enum KeyType {
  /**
   * <code>RSA</code>
   * <p>The rsa key type field.</p>
   */
  RSA,
  /**
   * <code>EC</code>
   * <p>The ec key type field.</p>
   */
  EC;

  /**
   * <code>getKeyTypeFromOid</code>
   * <p>The get key type from oid getter method.</p>
   * @param oid {@link java.lang.String} <p>The oid parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyType} <p>The get key type from oid return object is <code>KeyType</code> type.</p>
   * @see java.lang.String
   */
  public static KeyType getKeyTypeFromOid(String oid) {
    Objects.requireNonNull(oid);

    switch (oid) {
      case EC_ENCRYPTION:
        return EC;
      case RSA_ENCRYPTION:
        return RSA;
      default:
        return null;
    }
  }
}
