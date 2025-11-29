
package io.github.nichetoolkit.fusionauth.der;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * <code>DerValue</code>
 * <p>The der value class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class DerValue {
  private final DerInputStream value;

  /**
   * <code>tag</code>
   * {@link io.github.nichetoolkit.fusionauth.der.Tag} <p>The <code>tag</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.der.Tag
   */
  public Tag tag;

  /**
   * <code>DerValue</code>
   * <p>Instantiates a new der value.</p>
   * @param tag   {@link io.github.nichetoolkit.fusionauth.der.Tag} <p>The tag parameter is <code>Tag</code> type.</p>
   * @param value byte <p>The value parameter is <code>byte</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.der.Tag
   */
  public DerValue(Tag tag, byte[] value) {
    this.tag = tag;
    this.value = new DerInputStream(value);
  }

  /**
   * <code>DerValue</code>
   * <p>Instantiates a new der value.</p>
   * @param tag   int <p>The tag parameter is <code>int</code> type.</p>
   * @param value byte <p>The value parameter is <code>byte</code> type.</p>
   */
  public DerValue(int tag, byte[] value) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(value);
  }

  /**
   * <code>DerValue</code>
   * <p>Instantiates a new der value.</p>
   * @param integer {@link java.math.BigInteger} <p>The integer parameter is <code>BigInteger</code> type.</p>
   * @see java.math.BigInteger
   */
  public DerValue(BigInteger integer) {
    this.tag = new Tag(Tag.Integer);
    this.value = new DerInputStream(integer.toByteArray());
  }

  /**
   * <code>DerValue</code>
   * <p>Instantiates a new der value.</p>
   * @param tag int <p>The tag parameter is <code>int</code> type.</p>
   * @param os  {@link io.github.nichetoolkit.fusionauth.der.DerOutputStream} <p>The os parameter is <code>DerOutputStream</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.der.DerOutputStream
   */
  public DerValue(int tag, DerOutputStream os) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(os.toByteArray());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DerValue)) return false;
    DerValue derValue = (DerValue) o;
    return tag == derValue.tag &&
        Arrays.equals(value.toByteArray(), derValue.value.toByteArray());
  }

  /**
   * <code>getBigInteger</code>
   * <p>The get big integer getter method.</p>
   * @param signed boolean <p>The signed parameter is <code>boolean</code> type.</p>
   * @return {@link java.math.BigInteger} <p>The get big integer return object is <code>BigInteger</code> type.</p>
   * @see java.math.BigInteger
   */
  public BigInteger getBigInteger(boolean signed) {
    return signed ? new BigInteger(value.toByteArray()) : new BigInteger(1, value.toByteArray());
  }

  /**
   * <code>getBigInteger</code>
   * <p>The get big integer getter method.</p>
   * @return {@link java.math.BigInteger} <p>The get big integer return object is <code>BigInteger</code> type.</p>
   * @see java.math.BigInteger
   */
  public BigInteger getBigInteger() {
    return getBigInteger(true);
  }

  /**
   * <code>getBitString</code>
   * <p>The get bit string getter method.</p>
   * @return {@link java.lang.String} <p>The get bit string return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String getBitString() {
    if (tag.value != Tag.BitString) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    byte[] bytes = value.toByteArray();

    // Strip off the ignore byte and decode the Bit String
    int ignoreByte = bytes[0];
    for (int i = 1; i < bytes.length; i++) {
      if (i == bytes.length - 1 && ignoreByte != 0) {
        // If ignore byte is not 0, then on the last byte ignore the last n bits
        int b = (bytes[i] & 0xFF) >> ignoreByte;
        sb.append(String.format("%" + (8 - ignoreByte) + "s", (Integer.toBinaryString(b))).replace(' ', '0'));
      } else {
        sb.append(String.format("%8s", (Integer.toBinaryString(bytes[i] & 0xFF))).replace(' ', '0'));
      }
    }

    return sb.toString();
  }

  /**
   * <code>getLength</code>
   * <p>The get length getter method.</p>
   * @return int <p>The get length return object is <code>int</code> type.</p>
   */
  public int getLength() {
    return value.length;
  }

  /**
   * <code>getOID</code>
   * <p>The get oid getter method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.der.ObjectIdentifier} <p>The get oid return object is <code>ObjectIdentifier</code> type.</p>
   * @throws IOException {@link java.io.IOException} <p>The io exception is <code>IOException</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.der.ObjectIdentifier
   * @see java.io.IOException
   */
  public ObjectIdentifier getOID() throws IOException {
    return value.getOID();
  }

  /**
   * <code>getPositiveBigInteger</code>
   * <p>The get positive big integer getter method.</p>
   * @return {@link java.math.BigInteger} <p>The get positive big integer return object is <code>BigInteger</code> type.</p>
   * @see java.math.BigInteger
   */
  public BigInteger getPositiveBigInteger() {
    return getBigInteger(false);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(tag);
    result = 31 * result + Arrays.hashCode(value.toByteArray());
    return result;
  }

  /**
   * <code>toByteArray</code>
   * <p>The to byte array method.</p>
   * @return byte <p>The to byte array return object is <code>byte</code> type.</p>
   */
  public byte[] toByteArray() {
    return value.toByteArray();
  }

  @Override
  public String toString() {
    if (tag.tagClass == TagClass.ContextSpecific) {
      return tag.toString();
    }

    return tag.getName() + ", length=" + value.length;
  }
}
