
package io.github.nichetoolkit.fusionauth.jwks;

import io.github.nichetoolkit.fusionauth.http.AbstractHttpHelper;
import io.github.nichetoolkit.fusionauth.jwks.domain.JSONWebKey;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;
import tools.jackson.databind.JsonNode;

import java.net.HttpURLConnection;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * <code>JSONWebKeySetHelper</code>
 * <p>The json web key set helper class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.http.AbstractHttpHelper
 * @since Jdk17
 */
public class JSONWebKeySetHelper extends AbstractHttpHelper {
  /**
   * <code>retrieveKeysFromIssuer</code>
   * <p>The retrieve keys from issuer method.</p>
   * @param issuer {@link java.lang.String} <p>The issuer parameter is <code>String</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from issuer return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer) {
    return retrieveKeysFromIssuer(issuer, null);
  }

  /**
   * <code>retrieveKeysFromIssuer</code>
   * <p>The retrieve keys from issuer method.</p>
   * @param issuer   {@link java.lang.String} <p>The issuer parameter is <code>String</code> type.</p>
   * @param consumer {@link java.util.function.Consumer} <p>The consumer parameter is <code>Consumer</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from issuer return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.function.Consumer
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer, Consumer<HttpURLConnection> consumer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveKeysFromWellKnownConfiguration(issuer + "/.well-known/openid-configuration", consumer);
  }

  /**
   * <code>retrieveKeysFromWellKnownConfiguration</code>
   * <p>The retrieve keys from well known configuration method.</p>
   * @param httpURLConnection {@link java.net.HttpURLConnection} <p>The http url connection parameter is <code>HttpURLConnection</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from well known configuration return object is <code>List</code> type.</p>
   * @see java.net.HttpURLConnection
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection,
        is -> {
          JsonNode response = Mapper.deserialize(is, JsonNode.class);
          JsonNode jwksURI = response.at("/jwks_uri");
          if (jwksURI.isMissingNode()) {
            String endpoint = httpURLConnection.getURL().toString();
            throw new JSONWebKeySetException("The well-known endpoint [" + endpoint + "] has not defined a JSON Web Key Set endpoint. Missing the [jwks_uri] property.");
          }

          return retrieveKeysFromJWKS(jwksURI.toString());
        },
        JSONWebKeyBuilderException::new);
  }

  /**
   * <code>retrieveKeysFromWellKnownConfiguration</code>
   * <p>The retrieve keys from well known configuration method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from well known configuration return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint) {
    return retrieveKeysFromWellKnownConfiguration(endpoint, null);
  }

  /**
   * <code>retrieveKeysFromWellKnownConfiguration</code>
   * <p>The retrieve keys from well known configuration method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @param consumer {@link java.util.function.Consumer} <p>The consumer parameter is <code>Consumer</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from well known configuration return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.function.Consumer
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromWellKnownConfiguration(connection);
  }

  /**
   * <code>retrieveKeysFromJWKS</code>
   * <p>The retrieve keys from jwks method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from jwks return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint) {
    return retrieveKeysFromJWKS(endpoint, null);
  }

  /**
   * <code>retrieveKeysFromJWKS</code>
   * <p>The retrieve keys from jwks method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @param consumer {@link java.util.function.Consumer} <p>The consumer parameter is <code>Consumer</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from jwks return object is <code>List</code> type.</p>
   * @see java.lang.String
   * @see java.util.function.Consumer
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromJWKS(connection);
  }

  /**
   * <code>retrieveKeysFromJWKS</code>
   * <p>The retrieve keys from jwks method.</p>
   * @param httpURLConnection {@link java.net.HttpURLConnection} <p>The http url connection parameter is <code>HttpURLConnection</code> type.</p>
   * @return {@link java.util.List} <p>The retrieve keys from jwks return object is <code>List</code> type.</p>
   * @see java.net.HttpURLConnection
   * @see java.util.List
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(HttpURLConnection httpURLConnection) {
    return get(
        httpURLConnection,
        is -> Mapper.deserialize(is, JSONWebKeySetResponse.class).keys,
        JSONWebKeyBuilderException::new);
  }

  /**
   * <code>JSONWebKeySetException</code>
   * <p>The json web key set exception class.</p>
   * @author Cyan (snow22314@outlook.com)
   * @see java.lang.RuntimeException
   * @since Jdk17
   */
  public static class JSONWebKeySetException extends RuntimeException {
    /**
     * <code>JSONWebKeySetException</code>
     * <p>Instantiates a new json web key set exception.</p>
     * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
     * @see java.lang.String
     */
    public JSONWebKeySetException(String message) {
      super(message);
    }

    /**
     * <code>JSONWebKeySetException</code>
     * <p>Instantiates a new json web key set exception.</p>
     * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
     * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
     * @see java.lang.String
     * @see java.lang.Throwable
     */
    public JSONWebKeySetException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * <code>JSONWebKeySetResponse</code>
   * <p>The json web key set response class.</p>
   * @author Cyan (snow22314@outlook.com)
   * @since Jdk17
   */
// Note, with the introduction of the Java Platform Module System (JPMS), private classes are no longer visible via
  // reflection. To ensure Jackson can de-serialize this class, it must be public.
  public static class JSONWebKeySetResponse {
    /**
     * <code>keys</code>
     * {@link java.util.List} <p>The <code>keys</code> field.</p>
     * @see java.util.List
     */
    public List<JSONWebKey> keys;
  }
}
