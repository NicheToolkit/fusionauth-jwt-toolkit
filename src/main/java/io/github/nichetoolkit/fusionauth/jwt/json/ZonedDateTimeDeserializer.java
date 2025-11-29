
package io.github.nichetoolkit.fusionauth.jwt.json;


import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdScalarDeserializer;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * <code>ZonedDateTimeDeserializer</code>
 * <p>The zoned date time deserializer class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see tools.jackson.databind.deser.std.StdScalarDeserializer
 * @since Jdk17
 */
public class ZonedDateTimeDeserializer extends StdScalarDeserializer<ZonedDateTime> {
  /**
   * <code>ZonedDateTimeDeserializer</code>
   * <p>Instantiates a new zoned date time deserializer.</p>
   */
  public ZonedDateTimeDeserializer() {
    super(Long.TYPE);
  }

  @Override
  public ZonedDateTime deserialize(JsonParser jsonParser, DeserializationContext context) throws JacksonException {
    JsonToken t = jsonParser.currentToken();
    long value;
    if (t == JsonToken.VALUE_NUMBER_INT || t == JsonToken.VALUE_NUMBER_FLOAT) {
      value = jsonParser.getLongValue();
    } else if (t == JsonToken.VALUE_STRING) {
      String str = jsonParser.getString().trim();
      if (str.isEmpty()) {
        return null;
      }
      try {
        value = Long.parseLong(str);
      } catch (NumberFormatException e) {
        throw context.weirdStringException(str,Long.class,e.getMessage());
      }
    } else {
      throw context.instantiationException(handledType(),"must be number of 'Long' type");
    }
    return Instant.ofEpochSecond(value).atZone(ZoneOffset.UTC);
  }
}
