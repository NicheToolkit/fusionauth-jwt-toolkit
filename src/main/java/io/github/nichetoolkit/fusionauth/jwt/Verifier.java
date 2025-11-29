
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

/**
 * <code>Verifier</code>
 * <p>The verifier interface.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public interface Verifier {
  /**
   * <code>canVerify</code>
   * <p>The can verify method.</p>
   * @param algorithm {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @return boolean <p>The can verify return object is <code>boolean</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  boolean canVerify(Algorithm algorithm);

  /**
   * <code>verify</code>
   * <p>The verify method.</p>
   * @param algorithm {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @param message   byte <p>The message parameter is <code>byte</code> type.</p>
   * @param signature byte <p>The signature parameter is <code>byte</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  void verify(Algorithm algorithm, byte[] message, byte[] signature);
}
