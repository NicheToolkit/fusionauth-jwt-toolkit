
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>MissingSignatureException</code>
 * <p>The missing signature exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class MissingSignatureException extends JWTException {
  /**
   * <code>MissingSignatureException</code>
   * <p>Instantiates a new missing signature exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public MissingSignatureException(String message) {
    super(message);
  }
}
