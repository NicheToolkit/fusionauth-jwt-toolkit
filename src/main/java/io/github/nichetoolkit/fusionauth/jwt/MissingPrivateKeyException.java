
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>MissingPrivateKeyException</code>
 * <p>The missing private key exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class MissingPrivateKeyException extends JWTException {
  /**
   * <code>MissingPrivateKeyException</code>
   * <p>Instantiates a new missing private key exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public MissingPrivateKeyException(String message) {
    super(message);
  }
}
