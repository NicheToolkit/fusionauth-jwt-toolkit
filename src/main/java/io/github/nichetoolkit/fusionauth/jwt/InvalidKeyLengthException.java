
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>InvalidKeyLengthException</code>
 * <p>The invalid key length exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class InvalidKeyLengthException extends JWTException {
  /**
   * <code>InvalidKeyLengthException</code>
   * <p>Instantiates a new invalid key length exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public InvalidKeyLengthException(String message) {
    super(message);
  }
}
