
package io.github.nichetoolkit.fusionauth.jwt;

/**
 * <code>HexUtils</code>
 * <p>The hex utils class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class HexUtils {
  @SuppressWarnings("SpellCheckingInspection")
  private final static char[] HEX = "0123456789ABCDEF".toCharArray();

  /**
   * <code>fromBytes</code>
   * <p>The from bytes method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link java.lang.String} <p>The from bytes return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public static String fromBytes(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      hexChars[i * 2] = HEX[v >>> 4];
      hexChars[i * 2 + 1] = HEX[v & 0x0F];
    }
    return new String(hexChars);
  }

  /**
   * <code>toBytes</code>
   * <p>The to bytes method.</p>
   * @param hexString {@link java.lang.String} <p>The hex string parameter is <code>String</code> type.</p>
   * @return byte <p>The to bytes return object is <code>byte</code> type.</p>
   * @see java.lang.String
   */
  public static byte[] toBytes(String hexString) {
    int len = hexString.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
          + Character.digit(hexString.charAt(i + 1), 16));
    }
    return data;
  }
}
