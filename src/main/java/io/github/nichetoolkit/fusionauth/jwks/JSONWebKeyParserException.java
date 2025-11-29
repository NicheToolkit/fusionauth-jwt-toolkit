
package io.github.nichetoolkit.fusionauth.jwks;

/**
 * <code>JSONWebKeyParserException</code>
 * <p>The json web key parser exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.lang.RuntimeException
 * @since Jdk17
 */
public class JSONWebKeyParserException extends RuntimeException {
  /**
   * <code>JSONWebKeyParserException</code>
   * <p>Instantiates a new json web key parser exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public JSONWebKeyParserException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * <code>JSONWebKeyParserException</code>
   * <p>Instantiates a new json web key parser exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public JSONWebKeyParserException(String message) {
    super(message);
  }
}
