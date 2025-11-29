
package io.github.nichetoolkit.fusionauth.jwks;

/**
 * <code>JSONWebKeyBuilderException</code>
 * <p>The json web key builder exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.lang.RuntimeException
 * @since Jdk17
 */
public class JSONWebKeyBuilderException extends RuntimeException {
  /**
   * <code>JSONWebKeyBuilderException</code>
   * <p>Instantiates a new json web key builder exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public JSONWebKeyBuilderException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * <code>JSONWebKeyBuilderException</code>
   * <p>Instantiates a new json web key builder exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public JSONWebKeyBuilderException(String message) {
    super(message);
  }
}
