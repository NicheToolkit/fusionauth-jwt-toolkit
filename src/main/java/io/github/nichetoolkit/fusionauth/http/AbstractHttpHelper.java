package io.github.nichetoolkit.fusionauth.http;

import io.github.nichetoolkit.fusionauth.jwks.JSONWebKeySetHelper;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * <code>AbstractHttpHelper</code>
 * <p>The abstract http helper class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public abstract class AbstractHttpHelper {
  /**
   * <code>get</code>
   * <p>The get method.</p>
   * @param <T>           {@link java.lang.Object} <p>The parameter can be of any type.</p>
   * @param urlConnection {@link java.net.HttpURLConnection} <p>The url connection parameter is <code>HttpURLConnection</code> type.</p>
   * @param consumer      {@link java.util.function.Function} <p>The consumer parameter is <code>Function</code> type.</p>
   * @param exception     {@link java.util.function.BiFunction} <p>The exception parameter is <code>BiFunction</code> type.</p>
   * @return T <p>The get return object is <code>T</code> type.</p>
   * @see java.net.HttpURLConnection
   * @see java.util.function.Function
   * @see java.util.function.BiFunction
   */
  protected static <T> T get(HttpURLConnection urlConnection, Function<InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    String endpoint = urlConnection.getURL().toString();

    try {
      urlConnection.setRequestMethod("GET");
      urlConnection.connect();
    } catch (Exception e) {
      throw exception.apply("Failed to connect to [" + endpoint + "].", e);
    }

    int status;
    try {
      status = urlConnection.getResponseCode();
    } catch (Exception e) {
      throw exception.apply("Failed to make a request to [" + endpoint + "].", e);
    }

    if (status < 200 || status > 299) {
      throw exception.apply("Failed to make a request to [" + endpoint + "], a status code of [" + status + "] was returned.", null);
    }

    try (InputStream is = new BufferedInputStream(urlConnection.getInputStream())) {
      return consumer.apply(is);
    } catch (Exception e) {
      throw exception.apply("Failed to parse the response as JSON from [" + endpoint + "].", e);
    }
  }

  /**
   * <code>buildURLConnection</code>
   * <p>The build url connection method.</p>
   * @param endpoint {@link java.lang.String} <p>The endpoint parameter is <code>String</code> type.</p>
   * @return {@link java.net.HttpURLConnection} <p>The build url connection return object is <code>HttpURLConnection</code> type.</p>
   * @see java.lang.String
   * @see java.net.HttpURLConnection
   */
  protected static HttpURLConnection buildURLConnection(String endpoint) {
    try {
      HttpURLConnection urlConnection = (HttpURLConnection) new URL(endpoint).openConnection();
      urlConnection.setDoOutput(true);
      urlConnection.setConnectTimeout(10_000);
      urlConnection.setReadTimeout(10_000);
      urlConnection.addRequestProperty("User-Agent", "fusionauth-jwt (https://github.com/FusionAuth/fusionauth-jwt)");
      return urlConnection;
    } catch (IOException e) {
      throw new JSONWebKeySetHelper.JSONWebKeySetException("Failed to build connection to [" + endpoint + "].", e);
    }
  }
}
