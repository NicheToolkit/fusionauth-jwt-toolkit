
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>JWTException</code>
 * <p>The jwt exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.lang.RuntimeException
 * @since Jdk17
 */
public class JWTException extends RuntimeException {
  /**
   * <code>JWTException</code>
   * <p>Instantiates a new jwt exception.</p>
   */
  public JWTException() {
  }

  /**
   * <code>JWTException</code>
   * <p>Instantiates a new jwt exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public JWTException(String message) {
    super(message);
  }

  /**
   * <code>JWTException</code>
   * <p>Instantiates a new jwt exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public JWTException(String message, Throwable cause) {
    super(message, cause);
  }
}
