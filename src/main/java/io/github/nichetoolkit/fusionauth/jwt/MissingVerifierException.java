
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>MissingVerifierException</code>
 * <p>The missing verifier exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTException
 * @since Jdk17
 */
public class MissingVerifierException extends JWTException {
  /**
   * <code>MissingVerifierException</code>
   * <p>Instantiates a new missing verifier exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public MissingVerifierException(String message) {
    super(message);
  }
}
