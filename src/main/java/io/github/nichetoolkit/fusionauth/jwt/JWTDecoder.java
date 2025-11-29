
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;
import io.github.nichetoolkit.fusionauth.jwt.domain.Header;
import io.github.nichetoolkit.fusionauth.jwt.domain.JWT;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * <code>JWTDecoder</code>
 * <p>The jwt decoder class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JWTDecoder {
  private int clockSkew = 0;

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedJWT {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @param verifiers  {@link io.github.nichetoolkit.fusionauth.jwt.Verifier} <p>The verifiers parameter is <code>Verifier</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.jwt.Verifier
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public JWT decode(String encodedJWT, Verifier... verifiers) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);

    String[] parts = getParts(encodedJWT);

    Header header = Mapper.deserialize(base64Decode(parts[0]), Header.class);
    Verifier verifier = Arrays.stream(verifiers).filter(v -> v.canVerify(header.algorithm)).findFirst().orElse(null);

    // The 'none' algorithm is only allowed when no verifiers are provided.
    boolean allowNoneAlgorithm = verifiers.length == 0;

    return validate(encodedJWT, parts, header, verifier, allowNoneAlgorithm);
  }

  /**
   * <code>withClockSkew</code>
   * <p>The with clock skew method.</p>
   * @param clockSkew int <p>The clock skew parameter is <code>int</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.JWTDecoder} <p>The with clock skew return object is <code>JWTDecoder</code> type.</p>
   */
  public JWTDecoder withClockSkew(int clockSkew) {
    this.clockSkew = clockSkew;
    return this;
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedJWT {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @param verifiers  {@link java.util.Map} <p>The verifiers parameter is <code>Map</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see java.util.Map
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) {
    return decode(encodedJWT, verifiers, h -> h.getString("kid"));
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedJWT       {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @param verifierFunction {@link java.util.function.Function} <p>The verifier function parameter is <code>Function</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see java.util.function.Function
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public JWT decode(String encodedJWT, Function<String, Verifier> verifierFunction) {
    return decode(encodedJWT, verifierFunction, h -> h.getString("kid"));
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedJWT       {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @param verifierFunction {@link java.util.function.Function} <p>The verifier function parameter is <code>Function</code> type.</p>
   * @param keyFunction      {@link java.util.function.Function} <p>The key function parameter is <code>Function</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see java.util.function.Function
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public JWT decode(String encodedJWT, Function<String, Verifier> verifierFunction, Function<Header, String> keyFunction) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifierFunction);
    Objects.requireNonNull(keyFunction);
    return decodeJWT(encodedJWT, verifierFunction, keyFunction, false);
  }

  private JWT decodeJWT(String encodedJWT, Function<String, Verifier> verifierFunction, Function<Header, String> keyFunction, boolean allowNoneAlgorithm) {
    String[] parts = getParts(encodedJWT);

    Header header = Mapper.deserialize(base64Decode(parts[0]), Header.class);
    String key = keyFunction.apply(header);
    Verifier verifier = verifierFunction.apply(key);

    return validate(encodedJWT, parts, header, verifier, allowNoneAlgorithm);
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedJWT  {@link java.lang.String} <p>The encoded jwt parameter is <code>String</code> type.</p>
   * @param verifiers   {@link java.util.Map} <p>The verifiers parameter is <code>Map</code> type.</p>
   * @param keyFunction {@link java.util.function.Function} <p>The key function parameter is <code>Function</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The decode return object is <code>JWT</code> type.</p>
   * @see java.lang.String
   * @see java.util.Map
   * @see java.util.function.Function
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers, Function<Header, String> keyFunction) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);
    Objects.requireNonNull(keyFunction);
    return decodeJWT(encodedJWT, verifiers::get, keyFunction, verifiers.isEmpty());
  }

  private byte[] base64Decode(String string) {
    try {
      // Equal to calling : .decode(string.getBytes(StandardCharsets.ISO_8859_1))
      // If this is a properly base64 encoded string, decoding using ISO_8859_1 should be fine.
      return Base64.getUrlDecoder().decode(string);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTException("The encoded JWT is not properly Base64 encoded.", e);
    }
  }

  private String[] getParts(String encodedJWT) {
    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return parts;
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  private JWT validate(String encodedJWT, String[] parts, Header header, Verifier verifier, boolean allowNoneAlgorithm) {
    // When parts.length == 2, we have no signature.
    //  - Case 1: If one or more verifiers are provided, we will not decode an un-secured JWT. Throw NoneNotAllowedException
    //  - Case 2: If no verifiers are provided, we will decode an un-secured JWT, the algorithm must be 'none'.
    if (parts.length == 2) {
      if (!allowNoneAlgorithm) {
        throw new NoneNotAllowedException();
      }

      if (header.algorithm != Algorithm.none) {
        throw new MissingSignatureException("Your provided a JWT with the algorithm [" + header.algorithm.getName() + "] but it is missing a signature");
      }
    } else {
      // When parts.length == 3, we have a signature.
      // - Case 1: The algorithm in the header is 'none', we do not expect a signature.
      // - Case 2: No verifier was provided that can verify the algorithm in the header, or no verifier found by the kid in the header
      // - Case 3: The requested verifier cannot verify the signature based upon the algorithm value in the header
      if (header.algorithm == Algorithm.none) {
        throw new InvalidJWTException("You provided a JWT with a signature and an algorithm of none");
      }

      if (verifier == null) {
        throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.algorithm.getName() + "]");
      }

      // When the verifier has been selected based upon the 'kid' or other identifier in the header, we must verify it can verify the algorithm.
      // - When multiple verifiers are provided to .decode w/out a kid, we may have already called 'canVerify', this is ok.
      if (!verifier.canVerify(header.algorithm)) {
        throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.algorithm.getName() + "]");
      }

      verifySignature(verifier, header, parts[2], encodedJWT);
    }

    // Signature is valid or there is no signature to validate for an un-secured JWT, verify time based JWT claims
    JWT jwt = Mapper.deserialize(base64Decode(parts[1]), JWT.class);
    jwt.header = header;
    ZonedDateTime now = now();

    // Verify expiration claim
    ZonedDateTime nowMinusSkew = now.minusSeconds(clockSkew);
    if (jwt.isExpired(nowMinusSkew)) {
      throw new JWTExpiredException();
    }

    // Verify the notBefore claim
    ZonedDateTime nowPlusSkew = now.plusSeconds(clockSkew);
    if (jwt.isUnavailableForProcessing(nowPlusSkew)) {
      throw new JWTUnavailableForProcessingException();
    }

    return jwt;
  }

  /**
   * <code>now</code>
   * <p>The now method.</p>
   * @return {@link java.time.ZonedDateTime} <p>The now return object is <code>ZonedDateTime</code> type.</p>
   * @see java.time.ZonedDateTime
   */
  protected ZonedDateTime now() {
    return ZonedDateTime.now(ZoneOffset.UTC);
  }

  private void verifySignature(Verifier verifier, Header header, String signature, String encodedJWT) {
    // The message comprises the first two segments of the entire JWT, the signature is the last segment.
    int index = encodedJWT.lastIndexOf('.');
    byte[] message = encodedJWT.substring(0, index).getBytes(StandardCharsets.UTF_8);

    byte[] signatureBytes = base64Decode(signature);
    verifier.verify(header.algorithm, message, signatureBytes);
  }
}