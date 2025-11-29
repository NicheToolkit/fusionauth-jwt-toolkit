
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>MissingPublicKeyException</code>
 * <p>The missing public key exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class MissingPublicKeyException extends JWTException {
  /**
   * <code>MissingPublicKeyException</code>
   * <p>Instantiates a new missing public key exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public MissingPublicKeyException(String message) {
    super(message);
  }
}
