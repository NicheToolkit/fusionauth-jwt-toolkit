
package io.github.nichetoolkit.fusionauth.der;

import java.io.IOException;

/**
 * <code>DerEncodingException</code>
 * <p>The der encoding exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.io.IOException
 * @since Jdk17
 */
public class DerEncodingException extends IOException {
  /**
   * <code>DerEncodingException</code>
   * <p>Instantiates a new der encoding exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public DerEncodingException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * <code>DerEncodingException</code>
   * <p>Instantiates a new der encoding exception.</p>
   * @param cause {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.Throwable
   */
  public DerEncodingException(Throwable cause) {
    super(cause);
  }

  /**
   * <code>DerEncodingException</code>
   * <p>Instantiates a new der encoding exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public DerEncodingException(String message) {
    super(message);
  }
}
