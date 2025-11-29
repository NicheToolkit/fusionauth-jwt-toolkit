
package io.github.nichetoolkit.fusionauth.jwt;

import io.github.nichetoolkit.fusionauth.jwt.domain.Header;
import io.github.nichetoolkit.fusionauth.jwt.domain.JWT;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * <code>JWTEncoder</code>
 * <p>The jwt encoder class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class JWTEncoder {
  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param jwt    {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The jwt parameter is <code>JWT</code> type.</p>
   * @param signer {@link io.github.nichetoolkit.fusionauth.jwt.Signer} <p>The signer parameter is <code>Signer</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   * @see io.github.nichetoolkit.fusionauth.jwt.Signer
   * @see java.lang.String
   */
  public String encode(JWT jwt, Signer signer) {
    return encode(jwt, signer, h -> h.set("kid", signer.getKid()));
  }

  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param jwt      {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The jwt parameter is <code>JWT</code> type.</p>
   * @param signer   {@link io.github.nichetoolkit.fusionauth.jwt.Signer} <p>The signer parameter is <code>Signer</code> type.</p>
   * @param supplier {@link java.util.function.Supplier} <p>The supplier parameter is <code>Supplier</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   * @see io.github.nichetoolkit.fusionauth.jwt.Signer
   * @see java.util.function.Supplier
   * @see java.lang.String
   */
  public String encode(JWT jwt, Signer signer, Supplier<Header> supplier) {
    Header header = supplier != null
        ? supplier.get()
        : new Header();
    return encode(jwt, signer, header);
  }

  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param jwt      {@link io.github.nichetoolkit.fusionauth.jwt.domain.JWT} <p>The jwt parameter is <code>JWT</code> type.</p>
   * @param signer   {@link io.github.nichetoolkit.fusionauth.jwt.Signer} <p>The signer parameter is <code>Signer</code> type.</p>
   * @param consumer {@link java.util.function.Consumer} <p>The consumer parameter is <code>Consumer</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.JWT
   * @see io.github.nichetoolkit.fusionauth.jwt.Signer
   * @see java.util.function.Consumer
   * @see java.lang.String
   */
  public String encode(JWT jwt, Signer signer, Consumer<Header> consumer) {
    Header header = new Header();
    if (consumer != null) {
      consumer.accept(header);
    }
    return encode(jwt, signer, header);
  }

  private String encode(JWT jwt, Signer signer, Header header) {
    Objects.requireNonNull(jwt);
    Objects.requireNonNull(signer);

    List<String> parts = new ArrayList<>(3);
    // Set this after we pass the header to the consumer to ensure it isn't tampered with, only the signer can set the algorithm.
    header.algorithm = signer.getAlgorithm();
    parts.add(base64Encode(Mapper.serialize(header)));
    parts.add(base64Encode(Mapper.serialize(jwt)));

    byte[] signature = signer.sign(String.join(".", parts));
    parts.add(base64Encode(signature));

    return String.join(".", parts);
  }

  private String base64Encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
