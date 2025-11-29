
package io.github.nichetoolkit.fusionauth.pem;

/**
 * <code>PEMDecoderException</code>
 * <p>The pem decoder exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.lang.RuntimeException
 * @since Jdk17
 */
public class PEMDecoderException extends RuntimeException {
  /**
   * <code>PEMDecoderException</code>
   * <p>Instantiates a new pem decoder exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   */
  public PEMDecoderException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * <code>PEMDecoderException</code>
   * <p>Instantiates a new pem decoder exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public PEMDecoderException(String message) {
    super(message);
  }

  /**
   * <code>PEMDecoderException</code>
   * <p>Instantiates a new pem decoder exception.</p>
   * @param cause {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.Throwable
   */
  public PEMDecoderException(Throwable cause) {
    super(cause);
  }
}
