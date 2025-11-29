
package io.github.nichetoolkit.fusionauth.jwt.json;


import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdScalarSerializer;

import java.time.ZonedDateTime;

/**
 * <code>ZonedDateTimeSerializer</code>
 * <p>The zoned date time serializer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see tools.jackson.databind.ser.std.StdScalarSerializer
 * @since Jdk17
 */
public class ZonedDateTimeSerializer extends StdScalarSerializer<ZonedDateTime> {
  /**
   * <code>ZonedDateTimeSerializer</code>
   * <p>Instantiates a new zoned date time serializer.</p>
   */
  public ZonedDateTimeSerializer() {
    super(ZonedDateTime.class);
  }

  @Override
  public void serialize(ZonedDateTime value, JsonGenerator jsonGenerator, SerializationContext context) throws JacksonException {
    if (value == null) {
      jsonGenerator.writeNull();
    } else {
      jsonGenerator.writeNumber(value.toEpochSecond());
    }
  }
}
