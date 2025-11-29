
package io.github.nichetoolkit.fusionauth.jwt.json;


import tools.jackson.databind.module.SimpleModule;

import java.time.ZonedDateTime;

/**
 * <code>JacksonModule</code>
 * <p>The jackson module class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see tools.jackson.databind.module.SimpleModule
 * @since Jdk17
 */
public class JacksonModule extends SimpleModule {
  /**
   * <code>JacksonModule</code>
   * <p>Instantiates a new jackson module.</p>
   */
  public JacksonModule() {
    // Deserializers
    addDeserializer(ZonedDateTime.class, new ZonedDateTimeDeserializer());

    // Serializers
    addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer());
  }
}
