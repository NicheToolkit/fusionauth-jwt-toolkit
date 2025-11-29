
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>InvalidJWTException</code>
 * <p>The invalid jwt exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class InvalidJWTException extends JWTException {
  /**
   * <code>InvalidJWTException</code>
   * <p>Instantiates a new invalid jwt exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public InvalidJWTException(String message) {
    super(message);
  }

  /**
   * <code>InvalidJWTException</code>
   * <p>Instantiates a new invalid jwt exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public InvalidJWTException(String message, Throwable cause) {
    super(message, cause);
  }
}
