
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

/**
 * <code>Signer</code>
 * <p>The signer interface.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public interface Signer {

  /**
   * <code>getAlgorithm</code>
   * <p>The get algorithm getter method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The get algorithm return object is <code>Algorithm</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  Algorithm getAlgorithm();

  /**
   * <code>getKid</code>
   * <p>The get kid getter method.</p>
   * @return {@link java.lang.String} <p>The get kid return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  default String getKid() {
    throw new UnsupportedOperationException();
  }

  /**
   * <code>sign</code>
   * <p>The sign method.</p>
   * @param payload {@link java.lang.String} <p>The payload parameter is <code>String</code> type.</p>
   * @return byte <p>The sign return object is <code>byte</code> type.</p>
   * @see java.lang.String
   */
  byte[] sign(String payload);
}
