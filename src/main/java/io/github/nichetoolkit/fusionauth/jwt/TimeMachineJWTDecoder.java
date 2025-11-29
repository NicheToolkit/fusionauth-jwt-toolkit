
package io.github.nichetoolkit.fusionauth.jwt;

import java.time.ZonedDateTime;

/**
 * <code>TimeMachineJWTDecoder</code>
 * <p>The time machine jwt decoder class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.jwt.JWTDecoder
 * @since Jdk17
 */
public class TimeMachineJWTDecoder extends JWTDecoder {
  private final ZonedDateTime now;

  /**
   * <code>TimeMachineJWTDecoder</code>
   * <p>Instantiates a new time machine jwt decoder.</p>
   * @param now {@link java.time.ZonedDateTime} <p>The now parameter is <code>ZonedDateTime</code> type.</p>
   * @see java.time.ZonedDateTime
   */
  public TimeMachineJWTDecoder(ZonedDateTime now) {
    this.now = now;
  }

  @Override
  protected ZonedDateTime now() {
    return now;
  }
}
