
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>JWTSigningException</code>
 * <p>The jwt signing exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class JWTSigningException extends JWTException {
  /**
   * <code>JWTSigningException</code>
   * <p>Instantiates a new jwt signing exception.</p>
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public JWTSigningException() {
  }

  /**
   * <code>JWTSigningException</code>
   * <p>Instantiates a new jwt signing exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public JWTSigningException(String message, Throwable cause) {
    super(message, cause);
  }
}
