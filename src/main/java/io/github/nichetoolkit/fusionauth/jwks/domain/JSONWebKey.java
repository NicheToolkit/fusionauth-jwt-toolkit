
package io.github.nichetoolkit.fusionauth.jwks.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.nichetoolkit.fusionauth.domain.Buildable;
import io.github.nichetoolkit.fusionauth.jwks.JSONWebKeyBuilder;
import io.github.nichetoolkit.fusionauth.jwks.JSONWebKeyBuilderException;
import io.github.nichetoolkit.fusionauth.jwks.JSONWebKeyParser;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyType;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <code>JSONWebKey</code>
 * <p>The json web key class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.domain.Buildable
 * @since Jdk17
 */
public class JSONWebKey implements Buildable<JSONWebKey> {
  /**
   * <code>alg</code>
   * {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The <code>alg</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   */
  public Algorithm alg;

  /**
   * <code>crv</code>
   * {@link java.lang.String} <p>The <code>crv</code> field.</p>
   * @see java.lang.String
   */
  public String crv;

  /**
   * <code>d</code>
   * {@link java.lang.String} <p>The <code>d</code> field.</p>
   * @see java.lang.String
   */
  public String d;

  /**
   * <code>dp</code>
   * {@link java.lang.String} <p>The <code>dp</code> field.</p>
   * @see java.lang.String
   */
  public String dp;

  /**
   * <code>dq</code>
   * {@link java.lang.String} <p>The <code>dq</code> field.</p>
   * @see java.lang.String
   */
  public String dq;

  /**
   * <code>e</code>
   * {@link java.lang.String} <p>The <code>e</code> field.</p>
   * @see java.lang.String
   */
  public String e;

  /**
   * <code>kid</code>
   * {@link java.lang.String} <p>The <code>kid</code> field.</p>
   * @see java.lang.String
   */
  public String kid;

  /**
   * <code>kty</code>
   * {@link io.github.nichetoolkit.fusionauth.jwt.domain.KeyType} <p>The <code>kty</code> field.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.KeyType
   */
  public KeyType kty;

  /**
   * <code>n</code>
   * {@link java.lang.String} <p>The <code>n</code> field.</p>
   * @see java.lang.String
   */
  public String n;

  /**
   * <code>other</code>
   * {@link java.util.Map} <p>The <code>other</code> field.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnySetter
   */
  @JsonAnySetter
  public Map<String, Object> other = new LinkedHashMap<>();

  /**
   * <code>p</code>
   * {@link java.lang.String} <p>The <code>p</code> field.</p>
   * @see java.lang.String
   */
  public String p;

  /**
   * <code>q</code>
   * {@link java.lang.String} <p>The <code>q</code> field.</p>
   * @see java.lang.String
   */
  public String q;

  /**
   * <code>qi</code>
   * {@link java.lang.String} <p>The <code>qi</code> field.</p>
   * @see java.lang.String
   */
  public String qi;

  /**
   * <code>use</code>
   * {@link java.lang.String} <p>The <code>use</code> field.</p>
   * @see java.lang.String
   */
  public String use;

  /**
   * <code>x</code>
   * {@link java.lang.String} <p>The <code>x</code> field.</p>
   * @see java.lang.String
   */
  public String x;

  /**
   * <code>x5c</code>
   * {@link java.util.List} <p>The <code>x5c</code> field.</p>
   * @see java.util.List
   */
  public List<String> x5c;

  /**
   * <code>x5t</code>
   * {@link java.lang.String} <p>The <code>x5t</code> field.</p>
   * @see java.lang.String
   */
  public String x5t;

  /**
   * <code>x5t_256</code>
   * {@link java.lang.String} <p>The <code>x5t_256</code> field.</p>
   * @see java.lang.String
   * @see com.fasterxml.jackson.annotation.JsonProperty
   */
  @JsonProperty("x5t#S256")
  public String x5t_256;

  /**
   * <code>y</code>
   * {@link java.lang.String} <p>The <code>y</code> field.</p>
   * @see java.lang.String
   */
  public String y;

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param encodedPEM {@link java.lang.String} <p>The encoded pem parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.lang.String
   */
  public static JSONWebKey build(String encodedPEM) {
    return new JSONWebKeyBuilder().build(encodedPEM);
  }

  /**
   * <code>parse</code>
   * <p>The parse method.</p>
   * @param key {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The key parameter is <code>JSONWebKey</code> type.</p>
   * @return {@link java.security.PublicKey} <p>The parse return object is <code>PublicKey</code> type.</p>
   * @see java.security.PublicKey
   */
  public static PublicKey parse(JSONWebKey key) {
    return new JSONWebKeyParser().parse(key);
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param certificate {@link java.security.cert.Certificate} <p>The certificate parameter is <code>Certificate</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.cert.Certificate
   */
  public static JSONWebKey build(Certificate certificate) {
    return new JSONWebKeyBuilder().build(certificate);
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.PrivateKey
   */
  public static JSONWebKey build(PrivateKey privateKey) {
    return new JSONWebKeyBuilder().build(privateKey);
  }

  /**
   * <code>build</code>
   * <p>The build method.</p>
   * @param publicKey {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The build return object is <code>JSONWebKey</code> type.</p>
   * @see java.security.PublicKey
   */
  public static JSONWebKey build(PublicKey publicKey) {
    return new JSONWebKeyBuilder().build(publicKey);
  }

  /**
   * <code>add</code>
   * <p>The add method.</p>
   * @param key   {@link java.lang.String} <p>The key parameter is <code>String</code> type.</p>
   * @param value {@link java.lang.Object} <p>The value parameter is <code>Object</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey} <p>The add return object is <code>JSONWebKey</code> type.</p>
   * @see java.lang.String
   * @see java.lang.Object
   * @see com.fasterxml.jackson.annotation.JsonIgnore
   */
  @JsonIgnore
  public JSONWebKey add(String key, Object value) {
    if (key == null || value == null) {
      return this;
    }

    switch (key) {
      case "alg":
      case "crv":
      case "d":
      case "dp":
      case "dq":
      case "e":
      case "kid":
      case "kty":
      case "n":
      case "p":
      case "q":
      case "qi":
      case "use":
      case "x":
      case "x5c":
      case "x5t":
      case "x5t_256":
      case "y":
        throw new JSONWebKeyBuilderException("You can not add a named property. Use the field for [" + key + "] instead.", new IllegalArgumentException());
      default:
        other.put(key, value);
    }

    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JSONWebKey)) return false;
    JSONWebKey that = (JSONWebKey) o;
    return alg == that.alg &&
        Objects.equals(crv, that.crv) &&
        Objects.equals(d, that.d) &&
        Objects.equals(dp, that.dp) &&
        Objects.equals(dq, that.dq) &&
        Objects.equals(e, that.e) &&
        Objects.equals(kid, that.kid) &&
        kty == that.kty &&
        Objects.equals(n, that.n) &&
        Objects.equals(p, that.p) &&
        Objects.equals(q, that.q) &&
        Objects.equals(qi, that.qi) &&
        Objects.equals(use, that.use) &&
        Objects.equals(x, that.x) &&
        Objects.equals(x5c, that.x5c) &&
        Objects.equals(x5t, that.x5t) &&
        Objects.equals(x5t_256, that.x5t_256) &&
        Objects.equals(y, that.y);
  }

  /**
   * <code>getOther</code>
   * <p>The get other getter method.</p>
   * @return {@link java.util.Map} <p>The get other return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnyGetter
   */
  @JsonAnyGetter
  public Map<String, Object> getOther() {
    return other;
  }

  @Override
  public int hashCode() {
    return Objects.hash(alg, crv, d, dp, dq, e, kid, kty, n, p, q, qi, use, x, x5c, x5t, x5t_256, y);
  }

  /**
   * <code>toJSON</code>
   * <p>The to json method.</p>
   * @return {@link java.lang.String} <p>The to json return object is <code>String</code> type.</p>
   * @see java.lang.String
   */
  public String toJSON() {
    return new String(Mapper.serialize(this));
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }
}
