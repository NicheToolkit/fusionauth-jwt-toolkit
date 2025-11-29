
package io.github.nichetoolkit.fusionauth.jwt.domain;

import io.github.nichetoolkit.fusionauth.domain.Buildable;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.util.Objects;

/**
 * <code>KeyPair</code>
 * <p>The key pair class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.domain.Buildable
 * @since Jdk17
 */
public class KeyPair implements Buildable<KeyPair> {
  /**
   * <code>pem</code>
   * {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The <code>pem</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.pem.domain.PEM
   */
  public PEM pem;

  /**
   * <code>privateKey</code>
   * {@link java.lang.String} <p>The <code>privateKey</code> field.</p>
   * @see java.lang.String
   */
  public String privateKey;

  /**
   * <code>publicKey</code>
   * {@link java.lang.String} <p>The <code>publicKey</code> field.</p>
   * @see java.lang.String
   */
  public String publicKey;

  /**
   * <code>KeyPair</code>
   * <p>Instantiates a new key pair.</p>
   * @param privateKey {@link java.lang.String} <p>The private key parameter is <code>String</code> type.</p>
   * @param publicKey  {@link java.lang.String} <p>The public key parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public KeyPair(String privateKey, String publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    KeyPair that = (KeyPair) o;
    return Objects.equals(pem, that.pem) &&
        Objects.equals(privateKey, that.privateKey) &&
        Objects.equals(publicKey, that.publicKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(pem, privateKey, publicKey);
  }
}
