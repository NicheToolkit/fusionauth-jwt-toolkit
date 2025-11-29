
package io.github.nichetoolkit.fusionauth.pem;

/**
 * <code>PEMEncoderException</code>
 * <p>The pem encoder exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.lang.RuntimeException
 * @since Jdk17
 */
public class PEMEncoderException extends RuntimeException {
  /**
   * <code>PEMEncoderException</code>
   * <p>Instantiates a new pem encoder exception.</p>
   * @param cause {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.Throwable
   */
  public PEMEncoderException(Throwable cause) {
    super(cause);
  }
}
