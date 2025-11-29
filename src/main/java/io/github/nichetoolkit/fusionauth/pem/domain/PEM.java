
package io.github.nichetoolkit.fusionauth.pem.domain;

import io.github.nichetoolkit.fusionauth.domain.Buildable;
import io.github.nichetoolkit.fusionauth.pem.PEMDecoder;
import io.github.nichetoolkit.fusionauth.pem.PEMEncoder;

import java.nio.file.Path;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Objects;

/**
 * <code>PEM</code>
 * <p>The pem class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @see io.github.nichetoolkit.fusionauth.domain.Buildable
 * @since Jdk17
 */
public class PEM implements Buildable<PEM> {
  /**
   * <code>EC_PRIVATE_KEY_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>EC_PRIVATE_KEY_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded EC Private key End Tag
  public static final String EC_PRIVATE_KEY_PREFIX = "-----BEGIN EC PRIVATE KEY-----";

  /**
   * <code>EC_PRIVATE_KEY_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>EC_PRIVATE_KEY_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded EC Private key Start Tag
  public static final String EC_PRIVATE_KEY_SUFFIX = "-----END EC PRIVATE KEY-----";

  /**
   * <code>PKCS_1_PRIVATE_KEY_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_1_PRIVATE_KEY_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded RSA Private Key (PKCS#1) Start Tag
  public static final String PKCS_1_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";

  /**
   * <code>PKCS_1_PRIVATE_KEY_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_1_PRIVATE_KEY_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded RSA Private Key file (PKCS#1) End Tag
  public static final String PKCS_1_PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

  /**
   * <code>PKCS_1_PUBLIC_KEY_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_1_PUBLIC_KEY_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// RSA Public Key file (PKCS#1) Start Tag
  public static final String PKCS_1_PUBLIC_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";

  /**
   * <code>PKCS_1_PUBLIC_KEY_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_1_PUBLIC_KEY_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// RSA Public Key file (PKCS#1) End Tag
  public static final String PKCS_1_PUBLIC_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

  /**
   * <code>PKCS_8_PRIVATE_KEY_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_8_PRIVATE_KEY_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded Private Key (PKCS#8) Start Tag
  public static final String PKCS_8_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

  /**
   * <code>PKCS_8_PRIVATE_KEY_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>PKCS_8_PRIVATE_KEY_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded Private Key (PKCS#8) End Tag
  public static final String PKCS_8_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

  /**
   * <code>X509_CERTIFICATE_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>X509_CERTIFICATE_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded X.509 Certificate Start Tag
  public static final String X509_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";

  /**
   * <code>X509_CERTIFICATE_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>X509_CERTIFICATE_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded X.509 Certificate End Tag
  public static final String X509_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

  /**
   * <code>X509_PUBLIC_KEY_PREFIX</code>
   * {@link java.lang.String} <p>The constant <code>X509_PUBLIC_KEY_PREFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded Public Key (X.509) Start Tag
  public static final String X509_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";

  /**
   * <code>X509_PUBLIC_KEY_SUFFIX</code>
   * {@link java.lang.String} <p>The constant <code>X509_PUBLIC_KEY_SUFFIX</code> field.</p>
   * @see java.lang.String
   */
// PEM Encoded Public Key (X.509) End Tag
  public static final String X509_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

  /**
   * <code>certificate</code>
   * {@link java.security.cert.Certificate} <p>The <code>certificate</code> field.</p>
   * @see java.security.cert.Certificate
   */
  public Certificate certificate;

  /**
   * <code>privateKey</code>
   * {@link java.security.PrivateKey} <p>The <code>privateKey</code> field.</p>
   * @see java.security.PrivateKey
   */
  public PrivateKey privateKey;

  /**
   * <code>publicKey</code>
   * {@link java.security.PublicKey} <p>The <code>publicKey</code> field.</p>
   * @see java.security.PublicKey
   */
  public PublicKey publicKey;

  /**
   * <code>PEM</code>
   * <p>Instantiates a new pem.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param publicKey  {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.security.PublicKey
   */
  public PEM(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * <code>PEM</code>
   * <p>Instantiates a new pem.</p>
   * @param publicKey {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @see java.security.PublicKey
   */
  public PEM(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * <code>PEM</code>
   * <p>Instantiates a new pem.</p>
   * @param certificate {@link java.security.cert.Certificate} <p>The certificate parameter is <code>Certificate</code> type.</p>
   * @see java.security.cert.Certificate
   */
  public PEM(Certificate certificate) {
    this.certificate = certificate;
    this.publicKey = certificate.getPublicKey();
  }

  /**
   * <code>PEM</code>
   * <p>Instantiates a new pem.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @see java.security.PrivateKey
   */
  public PEM(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   * @see java.nio.file.Path
   */
  public static PEM decode(Path path) {
    return new PEMDecoder().decode(path);
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedPEM {@link java.lang.String} <p>The encoded pem parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   * @see java.lang.String
   */
  public static PEM decode(String encodedPEM) {
    return new PEMDecoder().decode(encodedPEM);
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   */
  public static PEM decode(byte[] bytes) {
    return new PEMDecoder().decode(bytes);
  }

  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param key {@link java.security.Key} <p>The key parameter is <code>Key</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see java.security.Key
   * @see java.lang.String
   */
  public static String encode(Key key) {
    return new PEMEncoder().encode(key);
  }

  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param privateKey {@link java.security.PrivateKey} <p>The private key parameter is <code>PrivateKey</code> type.</p>
   * @param publicKey  {@link java.security.PublicKey} <p>The public key parameter is <code>PublicKey</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see java.security.PrivateKey
   * @see java.security.PublicKey
   * @see java.lang.String
   */
  public static String encode(PrivateKey privateKey, PublicKey publicKey) {
    return new PEMEncoder().encode(privateKey, publicKey);
  }

  /**
   * <code>encode</code>
   * <p>The encode method.</p>
   * @param certificate {@link java.security.cert.Certificate} <p>The certificate parameter is <code>Certificate</code> type.</p>
   * @return {@link java.lang.String} <p>The encode return object is <code>String</code> type.</p>
   * @see java.security.cert.Certificate
   * @see java.lang.String
   */
  public static String encode(Certificate certificate) {
    return new PEMEncoder().encode(certificate);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof PEM)) return false;
    PEM pem = (PEM) o;
    return Objects.equals(certificate, pem.certificate) &&
        Objects.equals(privateKey, pem.privateKey) &&
        Objects.equals(publicKey, pem.publicKey);
  }

  /**
   * <code>getCertificate</code>
   * <p>The get certificate getter method.</p>
   * @return {@link java.security.cert.Certificate} <p>The get certificate return object is <code>Certificate</code> type.</p>
   * @see java.security.cert.Certificate
   * @see java.lang.SuppressWarnings
   */
  @SuppressWarnings("unused")
  public Certificate getCertificate() {
    return certificate;
  }

  /**
   * <code>getPrivateKey</code>
   * <p>The get private key getter method.</p>
   * @param <T> {@link java.security.PrivateKey} <p>The generic parameter is <code>PrivateKey</code> type.</p>
   * @return T <p>The get private key return object is <code>T</code> type.</p>
   * @see java.security.PrivateKey
   */
  public <T extends PrivateKey> T getPrivateKey() {
    //noinspection unchecked
    return (T) privateKey;
  }

  /**
   * <code>getPublicKey</code>
   * <p>The get public key getter method.</p>
   * @param <T> {@link java.security.PublicKey} <p>The generic parameter is <code>PublicKey</code> type.</p>
   * @return T <p>The get public key return object is <code>T</code> type.</p>
   * @see java.security.PublicKey
   */
  public <T extends PublicKey> T getPublicKey() {
    //noinspection unchecked
    return (T) publicKey;
  }

  @Override
  public int hashCode() {
    return Objects.hash(certificate, privateKey, publicKey);
  }
}
