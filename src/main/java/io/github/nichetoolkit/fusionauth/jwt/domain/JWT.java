
package io.github.nichetoolkit.fusionauth.jwt.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.nichetoolkit.fusionauth.jwt.JWTDecoder;
import io.github.nichetoolkit.fusionauth.jwt.JWTEncoder;
import io.github.nichetoolkit.fusionauth.jwt.TimeMachineJWTDecoder;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;
import io.github.nichetoolkit.fusionauth.jwt.json.ZonedDateTimeDeserializer;
import io.github.nichetoolkit.fusionauth.jwt.json.ZonedDateTimeSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <code>JWT</code>
 * <p>The jwt class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JWT {
  /**
   * <code>header</code>
   * {@link io.github.nichetoolkit.fusionauth.jwt.domain.Header} <p>The <code>header</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Header
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public Header header;

  /**
   * <code>audience</code>
   * {@link java.lang.Object} <p>The <code>audience</code> field.</p>
   * @see java.lang.Object
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("aud")
  public Object audience;

  /**
   * <code>expiration</code>
   * {@link java.time.ZonedDateTime} <p>The <code>expiration</code> field.</p>
   * @see java.time.ZonedDateTime
   * @see com.fasterxml.jackson.annotation.JsonProperty
   * @see tools.jackson.databind.annotation.JsonDeserialize
   * @see tools.jackson.databind.annotation.JsonSerialize
   */
  @JsonProperty("exp")
  @JsonDeserialize(using = ZonedDateTimeDeserializer.class)
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime expiration;

  /**
   * <code>issuedAt</code>
   * {@link java.time.ZonedDateTime} <p>The <code>issuedAt</code> field.</p>
   * @see java.time.ZonedDateTime
   * @see com.fasterxml.jackson.annotation.JsonProperty
   * @see tools.jackson.databind.annotation.JsonDeserialize
   * @see tools.jackson.databind.annotation.JsonSerialize
   */
  @JsonProperty("iat")
  @JsonDeserialize(using = ZonedDateTimeDeserializer.class)
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime issuedAt;

  /**
   * <code>issuer</code>
   * {@link java.lang.String} <p>The <code>issuer</code> field.</p>
   * @see java.lang.String
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("iss")
  public String issuer;

  /**
   * <code>notBefore</code>
   * {@link java.time.ZonedDateTime} <p>The <code>notBefore</code> field.</p>
   * @see java.time.ZonedDateTime
   * @see com.fasterxml.jackson.annotation.JsonProperty
   * @see tools.jackson.databind.annotation.JsonDeserialize
   * @see tools.jackson.databind.annotation.JsonSerialize
   */
  @JsonProperty("nbf")
  @JsonDeserialize(using = ZonedDateTimeDeserializer.class)
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime notBefore;

  /**
   * <code>otherClaims</code>
   * {@link java.util.Map} <p>The <code>otherClaims</code> field.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnySetter
   */
  @JsonAnySetter
  public Map<String, Object> otherClaims = new LinkedHashMap<>();

  /**
   * <code>subject</code>
   * {@link java.lang.String} <p>The <code>subject</code> field.</p>
   * @see java.lang.String
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("sub")
  public String subject;

  /**
   * <code>uniqueId</code>
   * {@link java.lang.String} <p>The <code>uniqueId</code> field.</p>
   * @see java.lang.String
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("jti")
  public String uniqueId;

  /**
   * <code>getDecoder</code>
   * <p>The get decoder getter method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.JWTDecoder} <p>The get decoder return object is <code>JWTDecoder</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.JWTDecoder
   */
  public static JWTDecoder getDecoder() {
    return new JWTDecoder();
  }

  /**
   * <code>getTimeMachineDecoder</code>
   * <p>The get time machine decoder getter method.</p>
   * @param now {@link java.time.ZonedDateTime} <p>The now parameter is <code>ZonedDateTime</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.JWTDecoder} <p>The get time machine decoder return object is <code>JWTDecoder</code> type.</p>
   * @see java.time.ZonedDateTime
   * @see io.github.nichetoolkit.fusionauth.jwt.JWTDecoder
   */
  public static JWTDecoder getTimeMachineDecoder(ZonedDateTime now) {
    return new TimeMachineJWTDecoder(now);
  }

  /**
   * <code>getEncoder</code>
   * <p>The get encoder getter method.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.JWTEncoder} <p>The get encoder return object is <code>JWTEncoder</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.JWTEncoder
   */
  public static JWTEncoder getEncoder() {
    return new JWTEncoder();
  }

  /**
   * <code>getHeaderClaim</code>
   * <p>The get header claim getter method.</p>
   * @param name {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Object} <p>The get header claim return object is <code>Object</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public Object getHeaderClaim(String name) {
    return header != null ? header.get(name) : null;
  }

  /**
   * <code>addClaim</code>
   * <p>The add claim method.</p>
   * @param name  {@link java.lang.String} <p>The name parameter is <code>String</code> type.</p>
   * @param value {@link java.lang.Object} <p>The value parameter is <code>Object</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The add claim return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   */
  public JWT addClaim(String name, Object value) {
    if (value == null) {
      return this;
    }

    switch (name) {
      case "aud":
        this.audience = value;
        break;
      case "exp":
        this.expiration = toZonedDateTime("exp", value);
        break;
      case "iat":
        this.issuedAt = toZonedDateTime("iat", value);
        break;
      case "iss":
        this.issuer = (String) value;
        break;
      case "jti":
        this.uniqueId = (String) value;
        break;
      case "nbf":
        this.notBefore = toZonedDateTime("nbf", value);
        break;
      case "sub":
        this.subject = (String) value;
        break;
      default:
        if (value instanceof Double || value instanceof Float) {
          value = BigDecimal.valueOf(((Number) value).doubleValue());
        } else if (value instanceof Integer || value instanceof Long) {
          value = BigInteger.valueOf(((Number) value).longValue());
        }
        otherClaims.put(name, value);
        break;
    }
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    JWT jwt = (JWT) o;
    return Objects.equals(audience, jwt.audience) &&
        Objects.equals(otherClaims, jwt.otherClaims) &&
        Objects.equals(expiration, jwt.expiration) &&
        Objects.equals(issuedAt, jwt.issuedAt) &&
        Objects.equals(issuer, jwt.issuer) &&
        Objects.equals(notBefore, jwt.notBefore) &&
        Objects.equals(subject, jwt.subject) &&
        Objects.equals(uniqueId, jwt.uniqueId);
  }

  /**
   * <code>getAllClaims</code>
   * <p>The get all claims getter method.</p>
   * @return {@link java.util.Map} <p>The get all claims return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public Map<String, Object> getAllClaims() {
    Map<String, Object> rawClaims = new HashMap<>(otherClaims);

    if (audience != null) {
      rawClaims.put("aud", audience);
    }

    if (expiration != null) {
      rawClaims.put("exp", expiration);
    }

    if (issuedAt != null) {
      rawClaims.put("iat", issuedAt);
    }

    if (issuer != null) {
      rawClaims.put("iss", issuer);
    }

    if (notBefore != null) {
      rawClaims.put("nbf", notBefore);
    }

    if (subject != null) {
      rawClaims.put("sub", subject);
    }

    if (uniqueId != null) {
      rawClaims.put("jti", uniqueId);
    }

    return rawClaims;
  }

  /**
   * <code>getBigDecimal</code>
   * <p>The get big decimal getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.math.BigDecimal} <p>The get big decimal return object is <code>BigDecimal</code> type.</p>
   * @see java.lang.String
   * @see java.math.BigDecimal
   */
  public BigDecimal getBigDecimal(String key) {
    return (BigDecimal) lookupClaim(key);
  }

  /**
   * <code>getBigInteger</code>
   * <p>The get big integer getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.math.BigInteger} <p>The get big integer return object is <code>BigInteger</code> type.</p>
   * @see java.lang.String
   * @see java.math.BigInteger
   */
  public BigInteger getBigInteger(String key) {
    return (BigInteger) lookupClaim(key);
  }

  /**
   * <code>getBoolean</code>
   * <p>The get boolean getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Boolean} <p>The get boolean return object is <code>Boolean</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Boolean
   */
  public Boolean getBoolean(String key) {
    return (Boolean) lookupClaim(key);
  }

  /**
   * <code>getDouble</code>
   * <p>The get double getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Double} <p>The get double return object is <code>Double</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Double
   */
  public Double getDouble(String key) {
    BigDecimal value = (BigDecimal) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.doubleValue();
  }

  /**
   * <code>getFloat</code>
   * <p>The get float getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Float} <p>The get float return object is <code>Float</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Float
   */
  public Float getFloat(String key) {
    BigDecimal value = (BigDecimal) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.floatValue();
  }

  /**
   * <code>getInteger</code>
   * <p>The get integer getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Integer} <p>The get integer return object is <code>Integer</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Integer
   */
  public Integer getInteger(String key) {
    BigInteger value = (BigInteger) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.intValue();
  }

  /**
   * <code>getList</code>
   * <p>The get list getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.util.List} <p>The get list return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.List
   */
  public List<Object> getList(String key) {
    //noinspection unchecked
    return (List<Object>) otherClaims.get(key);
  }

  /**
   * <code>getLong</code>
   * <p>The get long getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Long} <p>The get long return object is <code>Long</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Long
   */
  public Long getLong(String key) {
    BigInteger value = (BigInteger) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.longValue();
  }

  /**
   * <code>getMap</code>
   * <p>The get map getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.util.Map} <p>The get map return object is <code>Map</code> type.</p>
   * @see java.lang.String
   * @see java.util.Map
   */
  public Map<String, Object> getMap(String key) {
    //noinspection unchecked
    return (Map<String, Object>) lookupClaim(key);
  }

  /**
   * <code>getNumber</code>
   * <p>The get number getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Number} <p>The get number return object is <code>Number</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Number
   */
  public Number getNumber(String key) {
    return (Number) lookupClaim(key);
  }

  /**
   * <code>getObject</code>
   * <p>The get object getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.Object} <p>The get object return object is <code>Object</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   */
  public Object getObject(String key) {
    return lookupClaim(key);
  }

  /**
   * <code>getOtherClaims</code>
   * <p>The get other claims getter method.</p>
   * @return {@link java.util.Map} <p>The get other claims return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnyGetter
   */
  @JsonAnyGetter
  public Map<String, Object> getOtherClaims() {
    return otherClaims;
  }

  /**
   * <code>getRawClaims</code>
   * <p>The get raw claims getter method.</p>
   * @return {@link java.util.Map} <p>The get raw claims return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public Map<String, Object> getRawClaims() {
    Map<String, Object> rawClaims = new HashMap<>(otherClaims);

    if (audience != null) {
      rawClaims.put("aud", audience);
    }

    if (expiration != null) {
      rawClaims.put("exp", expiration.toEpochSecond());
    }

    if (issuedAt != null) {
      rawClaims.put("iat", issuedAt.toEpochSecond());
    }

    if (issuer != null) {
      rawClaims.put("iss", issuer);
    }

    if (notBefore != null) {
      rawClaims.put("nbf", notBefore.toEpochSecond());
    }

    if (subject != null) {
      rawClaims.put("sub", subject);
    }

    if (uniqueId != null) {
      rawClaims.put("jti", uniqueId);
    }

    return rawClaims;
  }

  /**
   * <code>getString</code>
   * <p>The get string getter method.</p>
   * @param key {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @return {@link java.lang.String} <p>The get string return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String getString(String key) {
    return (String) lookupClaim(key);
  }

  @Override
  public int hashCode() {
    return Objects.hash(audience, otherClaims, expiration, issuedAt, issuer, notBefore, subject, uniqueId);
  }

  /**
   * <code>isExpired</code>
   * <p>The is expired method.</p>
   * @return boolean <p>The is expired return object is <code>boolean</code> type.</p>
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public boolean isExpired() {
    return isExpired(ZonedDateTime.now(ZoneOffset.UTC));
  }

  /**
   * <code>isExpired</code>
   * <p>The is expired method.</p>
   * @param now {@link java.time.ZonedDateTime} <p>The now parameter is <code>ZonedDateTime</code> type.</p>
   * @return boolean <p>The is expired return object is <code>boolean</code> type.</p>
   * @see java.time.ZonedDateTime
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public boolean isExpired(ZonedDateTime now) {
    return expiration != null && expiration.isBefore(now);
  }

  /**
   * <code>isUnavailableForProcessing</code>
   * <p>The is unavailable for processing method.</p>
   * @param now {@link java.time.ZonedDateTime} <p>The now parameter is <code>ZonedDateTime</code> type.</p>
   * @return boolean <p>The is unavailable for processing return object is <code>boolean</code> type.</p>
   * @see java.time.ZonedDateTime
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public boolean isUnavailableForProcessing(ZonedDateTime now) {
    return notBefore != null && notBefore.isAfter(now);
  }

  /**
   * <code>isUnavailableForProcessing</code>
   * <p>The is unavailable for processing method.</p>
   * @return boolean <p>The is unavailable for processing return object is <code>boolean</code> type.</p>
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public boolean isUnavailableForProcessing() {
    return isUnavailableForProcessing(ZonedDateTime.now(ZoneOffset.UTC));
  }

  /**
   * <code>setAudience</code>
   * <p>The set audience setter method.</p>
   * @param audience {@link java.lang.Object} <p>The audience parameter is <code>Object</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set audience return object is <code>JWT</code> type.</p>
   * @see java.lang.Object
   */
  public JWT setAudience(Object audience) {
    this.audience = audience;
    return this;
  }

  /**
   * <code>setExpiration</code>
   * <p>The set expiration setter method.</p>
   * @param expiration {@link java.time.ZonedDateTime} <p>The expiration parameter is <code>ZonedDateTime</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set expiration return object is <code>JWT</code> type.</p>
   * @see java.time.ZonedDateTime
   */
  public JWT setExpiration(ZonedDateTime expiration) {
    this.expiration = expiration;
    return this;
  }

  /**
   * <code>setIssuedAt</code>
   * <p>The set issued at setter method.</p>
   * @param issuedAt {@link java.time.ZonedDateTime} <p>The issued at parameter is <code>ZonedDateTime</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set issued at return object is <code>JWT</code> type.</p>
   * @see java.time.ZonedDateTime
   */
  public JWT setIssuedAt(ZonedDateTime issuedAt) {
    this.issuedAt = issuedAt;
    return this;
  }

  /**
   * <code>setIssuer</code>
   * <p>The set issuer setter method.</p>
   * @param issuer {@link java.lang.String} <p>The issuer parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set issuer return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   */
  public JWT setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  /**
   * <code>setNotBefore</code>
   * <p>The set not before setter method.</p>
   * @param notBefore {@link java.time.ZonedDateTime} <p>The not before parameter is <code>ZonedDateTime</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set not before return object is <code>JWT</code> type.</p>
   * @see java.time.ZonedDateTime
   */
  public JWT setNotBefore(ZonedDateTime notBefore) {
    this.notBefore = notBefore;
    return this;
  }

  /**
   * <code>setSubject</code>
   * <p>The set subject setter method.</p>
   * @param subject {@link java.lang.String} <p>The subject parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set subject return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   */
  public JWT setSubject(String subject) {
    this.subject = subject;
    return this;
  }

  /**
   * <code>setUniqueId</code>
   * <p>The set unique id setter method.</p>
   * @param uniqueId {@link java.lang.String} <p>The unique id parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The set unique id return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   */
  public JWT setUniqueId(String uniqueId) {
    this.uniqueId = uniqueId;
    return this;
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }

  private Object lookupClaim(String key) {
      return switch (key) {
          case "aud" -> audience;
          case "exp" -> expiration;
          case "iat" -> issuedAt;
          case "iss" -> issuer;
          case "jti" -> uniqueId;
          case "nbf" -> notBefore;
          case "sub" -> subject;
          default -> otherClaims.get(key);
      };
  }

  private ZonedDateTime toZonedDateTime(String claim, Object value) {
    if (value instanceof ZonedDateTime) {
      return (ZonedDateTime) value;
    } else if (value instanceof Number) {
      return Instant.ofEpochSecond(((Number) value).longValue()).atZone(ZoneOffset.UTC);
    } else {
      throw new IllegalArgumentException("Invalid numeric value for [" + claim + "] claim");
    }
  }
}
