
package io.github.nichetoolkit.fusionauth.der;

import java.io.IOException;

/**
 * <code>DerDecodingException</code>
 * <p>The der decoding exception class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see java.io.IOException
 * @since Jdk17
 */
public class DerDecodingException extends IOException {
  /**
   * <code>DerDecodingException</code>
   * <p>Instantiates a new der decoding exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Throwable
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public DerDecodingException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * <code>DerDecodingException</code>
   * <p>Instantiates a new der decoding exception.</p>
   * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public DerDecodingException(String message) {
    super(message);
  }

  /**
   * <code>DerDecodingException</code>
   * <p>Instantiates a new der decoding exception.</p>
   * @param cause {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
   * @see java.lang.Throwable
   */
  public DerDecodingException(Throwable cause) {
    super(cause);
  }
}
