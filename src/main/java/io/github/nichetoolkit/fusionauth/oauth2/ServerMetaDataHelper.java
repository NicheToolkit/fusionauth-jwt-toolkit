
package io.github.nichetoolkit.fusionauth.oauth2;

import io.github.nichetoolkit.fusionauth.http.AbstractHttpHelper;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;
import io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData;

import java.net.HttpURLConnection;
import java.util.Objects;

/**
 * <code>ServerMetaDataHelper</code>
 * <p>The server meta data helper class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.http.AbstractHttpHelper
 * @since Jdk17
 */
public class ServerMetaDataHelper extends AbstractHttpHelper {
  /**
   * <code>retrieveFromIssuer</code>
   * <p>The retrieve from issuer method.</p>
   * @param issuer {@link java.lang.String} <p>The issuer parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData} <p>The retrieve from issuer return object is <code>AuthorizationServerMetaData</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData
   */
  public static AuthorizationServerMetaData retrieveFromIssuer(String issuer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveFromWellKnownConfiguration(issuer + "/.well-known/oauth-authorization-server");
  }

  /**
   * <code>retrieveFromWellKnownConfiguration</code>
   * <p>The retrieve from well known configuration method.</p>
   * @param httpURLConnection {@link java.net.HttpURLConnection} <p>The http url connection parameter is <code>HttpURLConnection</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData} <p>The retrieve from well known configuration return object is <code>AuthorizationServerMetaData</code> type.</p>
   * @see java.net.HttpURLConnection
   * @see io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection,
        is -> Mapper.deserialize(is, AuthorizationServerMetaData.class),
        ServerMetaDataException::new);
  }

  /**
   * <code>retrieveFromWellKnownConfiguration</code>
   * <p>The retrieve from well known configuration method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData} <p>The retrieve from well known configuration return object is <code>AuthorizationServerMetaData</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.oauth2.domain.AuthorizationServerMetaData
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(String endpoint) {
    return retrieveFromWellKnownConfiguration(buildURLConnection(endpoint));
  }

  /**
   * <code>ServerMetaDataException</code>
   * <p>The server meta data exception class.</p>
   * @author Cyan (snow22314@outlook.com)
   * @see java.lang.RuntimeException
   * @since Jdk17
   */
  public static class ServerMetaDataException extends RuntimeException {
    /**
     * <code>ServerMetaDataException</code>
     * <p>Instantiates a new server meta data exception.</p>
     * @param message {@link java.lang.String} <p>The message parameter is <code>String</code> type.</p>
     * @param cause   {@link java.lang.Throwable} <p>The cause parameter is <code>Throwable</code> type.</p>
     * @see java.lang.String
     * @see java.lang.Throwable
     */
    public ServerMetaDataException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
