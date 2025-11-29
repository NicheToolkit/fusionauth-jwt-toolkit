
package io.github.nichetoolkit.fusionauth.jwt.domain;

import java.util.Locale;

/**
 * <code>Algorithm</code>
 * <p>The algorithm enumeration.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public enum Algorithm {
  /**
   * <code>ES256</code>
   * <p>The es 256 algorithm field.</p>
   */
  ES256("SHA256withECDSA"),

  /**
   * <code>ES384</code>
   * <p>The es 384 algorithm field.</p>
   */
  ES384("SHA384withECDSA"),

  /**
   * <code>ES512</code>
   * <p>The es 512 algorithm field.</p>
   */
  ES512("SHA512withECDSA"),

  /**
   * <code>HS256</code>
   * <p>The hs 256 algorithm field.</p>
   */
  HS256("HmacSHA256"),

  /**
   * <code>HS384</code>
   * <p>The hs 384 algorithm field.</p>
   */
  HS384("HmacSHA384"),

  /**
   * <code>HS512</code>
   * <p>The hs 512 algorithm field.</p>
   */
  HS512("HmacSHA512"),

  /**
   * <code>PS256</code>
   * <p>The ps 256 algorithm field.</p>
   */
  PS256("SHA-256"),

  /**
   * <code>PS384</code>
   * <p>The ps 384 algorithm field.</p>
   */
  PS384("SHA-384"),

  /**
   * <code>PS512</code>
   * <p>The ps 512 algorithm field.</p>
   */
  PS512("SHA-512"),

  /**
   * <code>RS256</code>
   * <p>The rs 256 algorithm field.</p>
   */
  RS256("SHA256withRSA"),

  /**
   * <code>RS384</code>
   * <p>The rs 384 algorithm field.</p>
   */
  RS384("SHA384withRSA"),

  /**
   * <code>RS512</code>
   * <p>The rs 512 algorithm field.</p>
   */
  RS512("SHA512withRSA"),

  /**
   * <code>none</code>
   * <p>The none algorithm field.</p>
   */
  none("None");

  /**
   * <code>algorithm</code>
   * {@link java.lang.String} <p>The <code>algorithm</code> field.</p>
   * @see java.lang.String
   */
  public final String algorithm;

  Algorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * <code>fromName</code>
   * <p>The from name method.</p>
   * @param name {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The from name return object is <code>Algorithm</code> type.</p>
   * @see java.lang.String
   */
  public static Algorithm fromName(String name) {
    for (Algorithm alg : Algorithm.values()) {
      if (alg.getName().toUpperCase(Locale.ROOT).equals(name.toUpperCase(Locale.ROOT))) {
        return alg;
      }
    }

    return null;
  }

  /**
   * <code>getName</code>
   * <p>The get name getter method.</p>
   * @return {@link java.lang.String} <p>The get name return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String getName() {
    return algorithm;
  }

  /**
   * <code>getSaltLength</code>
   * <p>The get salt length getter method.</p>
   * @return int <p>The get salt length return object is <code>int</code> type.</p>
   */
  public int getSaltLength() {
    switch (this) {
      case PS256:
        return 32;
      case PS384:
        return 48;
      case PS512:
        return 64;
      default:
        throw new IllegalStateException("An incompatible algorithm was provided, this method is only used for RSASSA-PSS algorithms.");
    }
  }
}
