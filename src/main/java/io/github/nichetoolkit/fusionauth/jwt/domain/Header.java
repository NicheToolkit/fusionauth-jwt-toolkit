
package io.github.nichetoolkit.fusionauth.jwt.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * <code>Header</code>
 * <p>The header class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class Header {
  /**
   * <code>algorithm</code>
   * {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The <code>algorithm</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("alg")
  public Algorithm algorithm;

  /**
   * <code>properties</code>
   * {@link java.util.Map} <p>The <code>properties</code> field.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public Map<String, Object> properties = new LinkedHashMap<>();

  /**
   * <code>type</code>
   * {@link java.lang.String} <p>The <code>type</code> field.</p>
   * @see java.lang.String
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("typ")
  public String type = "JWT";

  /**
   * <code>Header</code>
   * <p>Instantiates a new header.</p>
   */
  public Header() {
  }

  /**
   * <code>Header</code>
   * <p>Instantiates a new header.</p>
   * @param algorithm {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  public Header(Algorithm algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * <code>anyGetter</code>
   * <p>The any getter method.</p>
   * @return {@link java.util.Map} <p>The any getter return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnyGetter
   */
  @JsonAnyGetter
  public Map<String, Object> anyGetter() {
    return properties;
  }

  /**
   * <code>getString</code>
   * <p>The get string getter method.</p>
   * @param name {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The get string return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String getString(String name) {
    Object result = properties.get(name);
    return result != null ? result.toString() : null;
  }

  /**
   * <code>get</code>
   * <p>The get method.</p>
   * @param name {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Object} <p>The get return object is <code>Object</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   */
  public Object get(String name) {
    return properties.get(name);
  }

  /**
   * <code>set</code>
   * <p>The set method.</p>
   * @param name  {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @param value {@link java.lang.Object} <p>The value parameter is <code>Object</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.Header} <p>The set return object is <code>Header</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   * @see com.fasterxml.jackson.annotation.JsonAnySetter
   */
  @JsonAnySetter
  public Header set(String name, Object value) {
    if (name == null || value == null) {
      return this;
    }

    properties.put(name, value);
    return this;
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Header header = (Header) o;
    return algorithm == header.algorithm &&
        Objects.equals(properties, header.properties) &&
        Objects.equals(type, header.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, properties, type);
  }
}
