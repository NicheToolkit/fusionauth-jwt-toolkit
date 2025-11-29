
package io.github.nichetoolkit.fusionauth.der;

import io.github.nichetoolkit.fusionauth.domain.Buildable;

import java.util.Arrays;
import java.util.Objects;

/**
 * <code>ObjectIdentifier</code>
 * <p>The object identifier class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.domain.Buildable
 * @since Jdk17
 */
public class ObjectIdentifier implements Buildable<ObjectIdentifier> {
  /**
   * <code>ECDSA_P256</code>
   * {@link java.lang.String} <p>The constant <code>ECDSA_P256</code> field.</p>
   * @see java.lang.String
   */
  public static final String ECDSA_P256 = "1.2.840.10045.3.1.7";

  /**
   * <code>ECDSA_P384</code>
   * {@link java.lang.String} <p>The constant <code>ECDSA_P384</code> field.</p>
   * @see java.lang.String
   */
  public static final String ECDSA_P384 = "1.3.132.0.34";

  /**
   * <code>ECDSA_P521</code>
   * {@link java.lang.String} <p>The constant <code>ECDSA_P521</code> field.</p>
   * @see java.lang.String
   */
  public static final String ECDSA_P521 = "1.3.132.0.35";

  /**
   * <code>EC_ENCRYPTION</code>
   * {@link java.lang.String} <p>The constant <code>EC_ENCRYPTION</code> field.</p>
   * @see java.lang.String
   */
  public static final String EC_ENCRYPTION = "1.2.840.10045.2.1";

  /**
   * <code>RSA_ENCRYPTION</code>
   * {@link java.lang.String} <p>The constant <code>RSA_ENCRYPTION</code> field.</p>
   * @see java.lang.String
   */
  public static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

  /**
   * <code>RSA_SHA256</code>
   * {@link java.lang.String} <p>The constant <code>RSA_SHA256</code> field.</p>
   * @see java.lang.String
   */
  public static final String RSA_SHA256 = "1.2.840.113549.1.1.11";

  /**
   * <code>RSA_SHA384</code>
   * {@link java.lang.String} <p>The constant <code>RSA_SHA384</code> field.</p>
   * @see java.lang.String
   */
  public static final String RSA_SHA384 = "1.2.840.113549.1.1.12";

  /**
   * <code>RSA_SHA512</code>
   * {@link java.lang.String} <p>The constant <code>RSA_SHA512</code> field.</p>
   * @see java.lang.String
   */
  public static final String RSA_SHA512 = "1.2.840.113549.1.1.13";

  /**
   * <code>value</code>
   * <p>The <code>value</code> field.</p>
   */
  public byte[] value;

  private String decoded;

  /**
   * <code>ObjectIdentifier</code>
   * <p>Instantiates a new object identifier.</p>
   * @param value byte <p>The value parameter is <code>byte</code> type.</p>
   */
  public ObjectIdentifier(byte[] value) {
    this.value = value;
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @return {@link java.lang.String} <p>The decode return object is <code>String</code> type.</p>
   * @throws DerDecodingException {@link io.github.nichetoolkit.fusionauth.der.DerDecodingException} <p>The der decoding exception is <code>DerDecodingException</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.der.DerDecodingException
   */
  public String decode() throws DerDecodingException {
    if (decoded == null) {
      _decode();
    }

    return decoded;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ObjectIdentifier)) return false;
    ObjectIdentifier that = (ObjectIdentifier) o;
    return Arrays.equals(value, that.value) &&
        Objects.equals(decoded, that.decoded);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(decoded);
    result = 31 * result + Arrays.hashCode(value);
    return result;
  }

  @Override
  public String toString() {
    try {
      return decode();
    } catch (DerDecodingException e) {
      return "Failed to _decode this object, unable to produce a string.";
    }
  }

  private void _decode() throws DerDecodingException {
    StringBuilder sb = new StringBuilder(value.length * 4);
    int index = 0;

    for (int i = 0; i < value.length; i++) {
      // We are not currently handling OIDs that have a node larger than 4 bytes
      if (i - index + 1 > 4) {
        throw new DerDecodingException("The object identifier contains a node that is larger than 4 bytes. This is not currently supported using this library.");
      }

      byte b = value[i];

      // Skip multi-byte length leading bytes, we'll handle them on the next pass
      if ((b & 128) != 0) {
        continue;
      }

      // Add a separator between nodes
      if (index != 0) {
        sb.append('.');
      }

      // Use an int to build the next node value, it may be made up of multiple bytes
      int node = 0;

      // Make at least one pass, optionally catch up the index to the cursor 'i' if we skipped a byte
      for (int j = index; j <= i; ++j) {
        node = node << 7;
        node = node | value[j] & 127;
      }

      // The first two nodes are encoded in a single byte when the node is less than 0x50 (80 decimal)
      if (index == 0) {
        if (node < 0x50) {
          sb.append(node / 40)
              .append('.')
              .append(node % 40);
        } else {
          sb.append("2.")
              .append(node - 80);
        }
      } else {
        sb.append(node);
      }

      index = i + 1;
    }

    decoded = sb.toString();
  }
}
