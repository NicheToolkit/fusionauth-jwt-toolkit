
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

/**
 * <code>UnsecuredSigner</code>
 * <p>The unsecured signer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.Signer
 * @since Jdk17
 */
public class UnsecuredSigner implements Signer {
  @Override
  public Algorithm getAlgorithm() {
    return Algorithm.none;
  }

  @Override
  public String getKid() {
    return null;
  }

  @Override
  public byte[] sign(String payload) {
    return new byte[0];
  }
}
