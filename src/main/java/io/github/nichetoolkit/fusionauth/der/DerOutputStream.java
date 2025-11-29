
package io.github.nichetoolkit.fusionauth.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * <code>DerOutputStream</code>
 * <p>The der output stream class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class DerOutputStream {
  private final ByteArrayOutputStream os;

  /**
   * <code>DerOutputStream</code>
   * <p>Instantiates a new der output stream.</p>
   */
  public DerOutputStream() {
    os = new ByteArrayOutputStream();
  }

  /**
   * <code>toByteArray</code>
   * <p>The to byte array method.</p>
   * @return byte <p>The to byte array return object is <code>byte</code> type.</p>
   */
  public byte[] toByteArray() {
    return os.toByteArray();
  }

  /**
   * <code>writeValue</code>
   * <p>The write value method.</p>
   * @param value {@link io.github.nichetoolkit.fusionauth.der.DerValue} <p>The value parameter is <code>DerValue</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.der.DerOutputStream} <p>The write value return object is <code>DerOutputStream</code> type.</p>
   * @throws DerEncodingException {@link io.github.nichetoolkit.fusionauth.der.DerEncodingException} <p>The der encoding exception is <code>DerEncodingException</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.der.DerValue
   * @see io.github.nichetoolkit.fusionauth.der.DerEncodingException
   */
  public DerOutputStream writeValue(DerValue value) throws DerEncodingException {
    try {
      os.write(value.tag.rawByte);
      writeLength(value.getLength());
      os.write(value.toByteArray());
      return this;
    } catch (IOException e) {
      throw new DerEncodingException(e);
    }
  }

  private void writeLength(int length) {
    // When the length is less than 128, the length can be represented in a single byte
    // - additional bytes are necessary for values greater than or equal to 128
    if (length < 128) {
      os.write((byte) length);
    } else if (length < 256) {
      os.write(-127); // 10000001 - 1 byte to follow
      os.write((byte) length);
    } else if (length < 65536) {
      os.write(-126); // 10000010 - 2 bytes to follow
      os.write((byte) (length >> 8));
      os.write((byte) length);
    } else if (length < 16777216) {
      os.write(-125); // 10000011 - 3 bytes to follow
      os.write((byte) (length >> 16));
      os.write((byte) (length >> 8));
      os.write((byte) length);
    } else {
      os.write(-124); // 10000100 - 4 bytes to follow
      os.write((byte) (length >> 24));
      os.write((byte) (length >> 16));
      os.write((byte) (length >> 8));
      os.write((byte) length);
    }
  }
}
