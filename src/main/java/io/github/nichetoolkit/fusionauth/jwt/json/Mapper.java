

package io.github.nichetoolkit.fusionauth.jwt.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.InputStream;

/**
 * <code>Mapper</code>
 * <p>The mapper class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class Mapper {
  private final static ObjectMapper OBJECT_MAPPER;

  static {
    JsonMapper.Builder builder = JsonMapper.builder();
    builder.changeDefaultPropertyInclusion((value)-> {
      value.withValueInclusion(JsonInclude.Include.NON_NULL);
      return value.withContentInclusion(JsonInclude.Include.NON_NULL);
    });
    builder.configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true);
    builder.configure(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS, true);
    builder.addModule(new JacksonModule());
    OBJECT_MAPPER = builder.build();
  }
  /**
   * <code>deserialize</code>
   * <p>The deserialize method.</p>
   * @param <T>   {@link java.lang.Object} <p>The parameter can be of any type.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @param type  {@link java.lang.Class} <p>The type parameter is <code>Class</code> type.</p>
   * @return T <p>The deserialize return object is <code>T</code> type.</p>
   * @throws InvalidJWTException {@link io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException} <p>The invalid jwt exception is <code>InvalidJWTException</code> type.</p>
   * @see java.lang.Class
   * @see io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException
   */
  public static <T> T deserialize(byte[] bytes, Class<T> type) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.readValue(bytes, type);
    } catch (JacksonException e) {
      throw new InvalidJWTException("The JWT could not be de-serialized.", e);
    }
  }

  /**
   * <code>deserialize</code>
   * <p>The deserialize method.</p>
   * @param <T>  {@link java.lang.Object} <p>The parameter can be of any type.</p>
   * @param is   {@link java.io.InputStream} <p>The is parameter is <code>InputStream</code> type.</p>
   * @param type {@link java.lang.Class} <p>The type parameter is <code>Class</code> type.</p>
   * @return T <p>The deserialize return object is <code>T</code> type.</p>
   * @throws InvalidJWTException {@link io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException} <p>The invalid jwt exception is <code>InvalidJWTException</code> type.</p>
   * @see java.io.InputStream
   * @see java.lang.Class
   * @see io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException
   */
  public static <T> T deserialize(InputStream is, Class<T> type) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.readValue(is, type);
    } catch (JacksonException e) {
      throw new InvalidJWTException("The input stream could not be de-serialized.", e);
    }
  }

  /**
   * <code>prettyPrint</code>
   * <p>The pretty print method.</p>
   * @param object {@link java.lang.Object} <p>The object parameter is <code>Object</code> type.</p>
   * @return byte <p>The pretty print return object is <code>byte</code> type.</p>
   * @throws InvalidJWTException {@link io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException} <p>The invalid jwt exception is <code>InvalidJWTException</code> type.</p>
   * @see java.lang.Object
   * @see io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException
   */
  public static byte[] prettyPrint(Object object) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(object);
    } catch (JacksonException e) {
      throw new InvalidJWTException("The object could not be serialized.", e);
    }
  }

  /**
   * <code>serialize</code>
   * <p>The serialize method.</p>
   * @param object {@link java.lang.Object} <p>The object parameter is <code>Object</code> type.</p>
   * @return byte <p>The serialize return object is <code>byte</code> type.</p>
   * @throws InvalidJWTException {@link io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException} <p>The invalid jwt exception is <code>InvalidJWTException</code> type.</p>
   * @see java.lang.Object
   * @see io.github.nichetoolkit.fusionauth.jwt.InvalidJWTException
   */
  public static byte[] serialize(Object object) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.writeValueAsBytes(object);
    } catch (JacksonException e) {
      throw new InvalidJWTException("The JWT could not be serialized.", e);
    }
  }


}
