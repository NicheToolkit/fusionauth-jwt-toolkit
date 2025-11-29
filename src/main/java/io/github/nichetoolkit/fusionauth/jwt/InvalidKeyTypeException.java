
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>InvalidKeyTypeException</code>
 * <p>The invalid key type exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class InvalidKeyTypeException extends JWTException {
  /**
   * <code>InvalidKeyTypeException</code>
   * <p>Instantiates a new invalid key type exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public InvalidKeyTypeException(String message) {
    super(message);
  }
}
