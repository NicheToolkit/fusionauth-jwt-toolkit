
package io.github.nichetoolkit.fusionauth.domain;

import java.util.function.Consumer;

/**
 * <code>Buildable</code>
 * <p>The buildable interface.</p>
 * @param <T> {@link java.lang.Object} <p>The parameter can be of any type.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public interface Buildable<T> {
  /**
   * <code>with</code>
   * <p>The with method.</p>
   * @param consumer {@link java.util.function.Consumer} <p>The consumer parameter is <code>Consumer</code> type.</p>
   * @return T <p>The with return object is <code>T</code> type.</p>
   * @see java.util.function.Consumer
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unchecked")
  default T with(Consumer<T> consumer) {
    consumer.accept((T) this);
    return (T) this;
  }
}