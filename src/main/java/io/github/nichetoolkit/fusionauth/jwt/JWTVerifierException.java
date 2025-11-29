
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>JWTVerifierException</code>
 * <p>The jwt verifier exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class JWTVerifierException extends JWTException {
  /**
   * <code>JWTVerifierException</code>
   * <p>Instantiates a new jwt verifier exception.</p>
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public JWTVerifierException() {
  }

  /**
   * <code>JWTVerifierException</code>
   * <p>Instantiates a new jwt verifier exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public JWTVerifierException(String message, Throwable cause) {
    super(message, cause);
  }
}
