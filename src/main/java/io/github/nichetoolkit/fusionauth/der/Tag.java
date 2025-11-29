

package io.github.nichetoolkit.fusionauth.der;

import java.util.Objects;

/**
 * <code>Tag</code>
 * <p>The tag class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class Tag {
  /**
   * <code>BitString</code>
   * <p>The constant <code>BitString</code> field.</p>
   */
  public static final int BitString = 3;

  /**
   * <code>Integer</code>
   * <p>The constant <code>Integer</code> field.</p>
   */
  public static final int Integer = 2;

  /**
   * <code>Null</code>
   * <p>The constant <code>Null</code> field.</p>
   */
  public static final int Null = 5;

  /**
   * <code>ObjectIdentifier</code>
   * <p>The constant <code>ObjectIdentifier</code> field.</p>
   */
  public static final int ObjectIdentifier = 6;

  /**
   * <code>OctetString</code>
   * <p>The constant <code>OctetString</code> field.</p>
   */
  public static final int OctetString = 4;

  /**
   * <code>PrintableString</code>
   * <p>The constant <code>PrintableString</code> field.</p>
   */
  public static final int PrintableString = 19;

  /**
   * <code>Sequence</code>
   * <p>The constant <code>Sequence</code> field.</p>
   */
  public static final int Sequence = 48;

  /**
   * <code>Set</code>
   * <p>The constant <code>Set</code> field.</p>
   */
  public static final int Set = 17;

  /**
   * <code>UTCTime</code>
   * <p>The constant <code>UTCTime</code> field.</p>
   */
  public static final int UTCTime = 23;

  /**
   * <code>primitive</code>
   * <p>The <code>primitive</code> field.</p>
   */
  public final boolean primitive;

  /**
   * <code>rawByte</code>
   * <p>The <code>rawByte</code> field.</p>
   */
  public final byte rawByte;

  /**
   * <code>tagClass</code>
   * {@link io.github.nichetoolkit.fusionauth.der.TagClass} <p>The <code>tagClass</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.der.TagClass
   */
  public final TagClass tagClass;

  /**
   * <code>value</code>
   * <p>The <code>value</code> field.</p>
   */
  public final int value;

  /**
   * <code>Tag</code>
   * <p>Instantiates a new tag.</p>
   * @param value int <p>The value parameter is <code>int</code> type.</p>
   */
  public Tag(int value) {
    // Hold the raw value provided
    rawByte = (byte) value;
    tagClass = setTagClass(value);

    // The 6th bit indicates if this tag is primitive or constructed
    primitive = (rawByte & 0b00100000) == 0;

    // The last 5 bits are the tag
    this.value = value & 0b00011111;
  }

  /**
   * <code>hexString</code>
   * <p>The hex string method.</p>
   * @param value int <p>The value parameter is <code>int</code> type.</p>
   * @return {@link java.lang.String} <p>The hex string return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  static String hexString(int value) {
    return "0x" + String.format("%02x", value).toUpperCase();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Tag tag)) return false;
      return rawByte == tag.rawByte;
  }

  /**
   * <code>getName</code>
   * <p>The get name getter method.</p>
   * @return {@link java.lang.String} <p>The get name return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String getName() {
    switch (rawByte) {
      case Integer:
        return "Integer";
      case BitString:
        return "Bit String";
      case Null:
        return "Null";
      case ObjectIdentifier:
        return "Object Identifier";
      case OctetString:
        return "Octet String";
      case PrintableString:
        return "PrintableString";
      case Sequence:
        return "Sequence";
      case Set:
        return "Set";
      case UTCTime:
        return "UTCTime";
      default:
        return "Other";
    }
  }

  @Override
  public int hashCode() {
    return Objects.hash(rawByte);
  }

  /**
   * <code>is</code>
   * <p>The is method.</p>
   * @param tag int <p>The tag parameter is <code>int</code> type.</p>
   * @return boolean <p>The is return object is <code>boolean</code> type.</p>
   */
  public boolean is(int tag) {
    return value == (tag & 0b00011111);
  }

  /**
   * <code>isConstructed</code>
   * <p>The is constructed method.</p>
   * @return boolean <p>The is constructed return object is <code>boolean</code> type.</p>
   */
  public boolean isConstructed() {
    return !primitive;
  }

  /**
   * <code>isPrimitive</code>
   * <p>The is primitive method.</p>
   * @return boolean <p>The is primitive return object is <code>boolean</code> type.</p>
   */
  public boolean isPrimitive() {
    return primitive;
  }

  @Override
  public String toString() {
    if (tagClass == TagClass.ContextSpecific) {
      return "[" + value + "]";
    }

    return value + " [" + getName() + ", " + hexString() + "]";
  }

  private TagClass setTagClass(int value) {
    TagClass tagClass = null;
    for (TagClass tc : TagClass.values()) {
      if ((value & 0b11000000) == tc.value) {
        tagClass = tc;
        break;
      }
    }

    if (tagClass == null) {
      throw new IllegalArgumentException("Invalid tag value " + value + ", the tag does not appear to fit into one of the expected classes");
    }

    return tagClass;
  }

  /**
   * <code>hexString</code>
   * <p>The hex string method.</p>
   * @return {@link java.lang.String} <p>The hex string return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  String hexString() {
    return "0x" + String.format("%02x", value).toUpperCase();
  }
}
