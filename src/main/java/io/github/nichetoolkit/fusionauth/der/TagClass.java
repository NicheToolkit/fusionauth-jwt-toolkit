
package io.github.nichetoolkit.fusionauth.der;

/**
 * <code>TagClass</code>
 * <p>The tag class enumeration.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public enum TagClass {
  /**
   * <code>Universal</code>
   * <p>The universal tag class field.</p>
   */
  Universal(0b00000000), // 0
  /**
   * <code>Application</code>
   * <p>The application tag class field.</p>
   */
  Application(0b01000000), // 64

  /**
   * <code>ContextSpecific</code>
   * <p>The context specific tag class field.</p>
   */
  ContextSpecific(0b10000000), // 128

  /**
   * <code>Private</code>
   * <p>The private tag class field.</p>
   */
  Private(0b11000000); // 192

  /**
   * <code>value</code>
   * <p>The <code>value</code> field.</p>
   */
  public final int value;

  TagClass(int value) {
    this.value = value;
  }
}
