
package io.github.nichetoolkit.fusionauth.pem;

import io.github.nichetoolkit.fusionauth.der.DerInputStream;
import io.github.nichetoolkit.fusionauth.der.DerOutputStream;
import io.github.nichetoolkit.fusionauth.der.DerValue;
import io.github.nichetoolkit.fusionauth.der.ObjectIdentifier;
import io.github.nichetoolkit.fusionauth.der.Tag;
import io.github.nichetoolkit.fusionauth.jwt.domain.KeyType;
import io.github.nichetoolkit.fusionauth.pem.domain.PEM;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_SUFFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_SUFFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_1_PUBLIC_KEY_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_1_PUBLIC_KEY_SUFFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_SUFFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.X509_CERTIFICATE_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.X509_CERTIFICATE_SUFFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_PREFIX;
import static io.github.nichetoolkit.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_SUFFIX;

/**
 * <code>PEMDecoder</code>
 * <p>The pem decoder class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class PEMDecoder {
  private static final byte[] EC_ENCRYPTION_OID = new byte[]{(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01};

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param path {@link java.nio.file.Path} <p>The path parameter is <code>Path</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   * @see java.nio.file.Path
   * @see io.github.nichetoolkit.fusionauth.pem.domain.PEM
   */
  public PEM decode(Path path) {
    Objects.requireNonNull(path);

    try {
      return decode(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new PEMDecoderException("Unable to read the file from path [" + path.toAbsolutePath().toString() + "]", e);
    }
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.pem.domain.PEM
   */
  public PEM decode(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return decode(new String(bytes));
  }

  /**
   * <code>decode</code>
   * <p>The decode method.</p>
   * @param encodedKey {@link java.lang.String} <p>The encoded key parameter is <code>String</code> type.</p>
   * @return {@link io.github.nichetoolkit.fusionauth.pem.domain.PEM} <p>The decode return object is <code>PEM</code> type.</p>
   * @see java.lang.String
   * @see io.github.nichetoolkit.fusionauth.pem.domain.PEM
   */
  public PEM decode(String encodedKey) {
    Objects.requireNonNull(encodedKey);

    try {
      if (encodedKey.contains(PKCS_1_PUBLIC_KEY_PREFIX)) {
        return decode_PKCS_1_Public(encodedKey);
      } else if (encodedKey.contains(X509_PUBLIC_KEY_PREFIX)) {
        return decode_X_509(encodedKey);
      } else if (encodedKey.contains(X509_CERTIFICATE_PREFIX)) {
        return new PEM(CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(getKeyBytes(encodedKey, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX))));
      } else if (encodedKey.contains(PKCS_1_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_1_Private(encodedKey);
      } else if (encodedKey.contains(PKCS_8_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_8(encodedKey);
      } else if (encodedKey.contains(EC_PRIVATE_KEY_SUFFIX)) {
        return decode_EC_privateKey(encodedKey);
      } else {
        throw new PEMDecoderException(new InvalidParameterException("Unexpected PEM Format"));
      }
    } catch (CertificateException | InvalidKeyException | InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
      throw new PEMDecoderException(e);
    }
  }

  private PEM decode_EC_privateKey(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, EC_PRIVATE_KEY_PREFIX, EC_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();
    BigInteger version = sequence[0].getBigInteger();

    // Expecting this EC private key to be version 1, it is not encapsulated in a PKCS#8 container
    if (!version.equals(BigInteger.valueOf(1))) {
      throw new PEMDecoderException("Expected version [1] but found version of [" + version + "]");
    }

    // This is an EC private key, encapsulate it in a PKCS#8 format to be compatible with the Java Key Factory
    //
    // EC Private key
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   PrivateKey      OCTET STRING
    //   [0] parameters  Context Specific
    //     curve           OBJECT IDENTIFIER
    //   [1] publicKey   Context Specific
    //                     BIT STRING
    // }
    //

    // Convert it to:
    //
    // DER Encoded PKCS#8  - version 0
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   algorithm       AlgorithmIdentifier,
    //   PrivateKey      OCTET STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length == 2) {
      // This is an EC encoded key w/out the context specific values [0] or [1] - this means we don't
      // have enough information to build a PKCS#8 key.
      throw new PEMDecoderException("Unable to decode the provided PEM, the EC private key does not contain the"
          + " curve identifier necessary to convert to a PKCS#8 format before building a private key");
    }

    ObjectIdentifier curveOID = sequence[2].getOID();
    DerOutputStream pkcs_8 = new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(BigInteger.valueOf(0))) // Always version 0
            .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                .writeValue(new DerValue(Tag.ObjectIdentifier, EC_ENCRYPTION_OID))
                .writeValue(new DerValue(Tag.ObjectIdentifier, curveOID.value))))
            .writeValue(new DerValue(Tag.OctetString, bytes))));

    ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs_8.toByteArray()));

    // Extract the public key from the PEM
    DerValue bitString = new DerInputStream(sequence[3]).readDerValue();
    PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, privateKey);

    // The publicKey may be null if it was not found in the private key
    return new PEM(privateKey, publicKey);
  }

  private PEM decode_PKCS_1_Private(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PRIVATE_KEY_PREFIX, PKCS_1_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // https://tools.ietf.org/html/rfc3447#appendix-A.1
    // ------------------------------------------------------
    // RSAPrivateKey ::= SEQUENCE {
    //   version           Version,
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER,  -- e
    //   privateExponent   INTEGER,  -- d
    //   prime1            INTEGER,  -- p
    //   prime2            INTEGER,  -- q
    //   exponent1         INTEGER,  -- d mod (p-1)
    //   exponent2         INTEGER,  -- d mod (q-1)
    //   coefficient       INTEGER,  -- (inverse of q) mod p
    //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }

    if (sequence.length < 9) {
      throw new PEMDecoderException(
          new InvalidKeyException("Could not build a PKCS#1 private key. Expected at least 9 values in the DER encoded sequence."));
    }

    // Ignoring the version value in the sequence
    BigInteger n = sequence[1].getBigInteger();
    BigInteger e = sequence[2].getBigInteger();
    BigInteger d = sequence[3].getBigInteger();
    BigInteger p = sequence[4].getBigInteger();
    BigInteger q = sequence[5].getBigInteger();
    BigInteger d_mod_p1 = sequence[6].getBigInteger();
    BigInteger d_mod_q1 = sequence[7].getBigInteger();
    BigInteger mod_p = sequence[8].getBigInteger();

    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, d_mod_p1, d_mod_q1, mod_p));
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

    return new PEM(privateKey, publicKey);
  }

  private PEM decode_PKCS_1_Public(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PUBLIC_KEY_PREFIX, PKCS_1_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // ------------------------------------------------------
    // RSAPublicKey ::= SEQUENCE {
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER   -- e
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Integer)) {
      // Expect the following format : [ Integer | Integer ]
      throw new InvalidKeyException("Could not build this PKCS#1 public key. Expecting values in the DER encoded sequence in the following format [ Integer | Integer ]");
    }

    BigInteger modulus = sequence[0].getBigInteger();
    BigInteger publicExponent = sequence[1].getBigInteger();
    return new PEM(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent)));
  }

  private PEM decode_PKCS_8(String encodedKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_8_PRIVATE_KEY_PREFIX, PKCS_8_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#8
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   algorithm       AlgorithmIdentifier,
    //   PrivateKey      OCTET STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length != 3 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Sequence) || !sequence[2].tag.is(Tag.OctetString)) {
      // Expect the following format : [ Integer | Sequence | OctetString ]
      throw new InvalidKeyException("Could not decode the private key. Expecting values in the DER encoded sequence in the following format [ Integer | Sequence | OctetString ]");
    }

    ObjectIdentifier algorithmOID = new DerInputStream(sequence[1].toByteArray()).getOID();
    KeyType type = KeyType.getKeyTypeFromOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Could not decode the private key. Expected an EC or RSA key type but found OID [" + algorithmOID.decode() + "] and was unable to match that to a supported algorithm.");
    }

    PrivateKey privateKey = KeyFactory.getInstance(type.name()).generatePrivate(new PKCS8EncodedKeySpec(bytes));

    // Attempt to extract the public key if available
    if (privateKey instanceof ECPrivateKey) {
      DerValue[] privateKeySequence = new DerInputStream(sequence[2]).getSequence();
      if (privateKeySequence.length == 3 && privateKeySequence[2].tag.rawByte == (byte) 0xA1) {
        DerValue bitString = new DerInputStream(privateKeySequence[2]).readDerValue();
        PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, (ECPrivateKey) privateKey);
        return new PEM(privateKey, publicKey);
      } else {
        // The private key did not contain the public key
        return new PEM(privateKey);
      }
    } else if (privateKey instanceof RSAPrivateCrtKey) {
      BigInteger modulus = ((RSAPrivateCrtKey) privateKey).getModulus();
      BigInteger publicExponent = ((RSAPrivateCrtKey) privateKey).getPublicExponent();
      PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new PEM(privateKey, publicKey);
    }

    return new PEM(privateKey);
  }

  private PEM decode_X_509(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, X509_PUBLIC_KEY_PREFIX, X509_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded Public Key Format SubjectPublicKeyInfo
    // ------------------------------------------------------
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Sequence) || !sequence[1].tag.is(Tag.BitString)) {
      // Expect the following format : [ Sequence | BitString ]
      throw new InvalidKeyException("Could not decode the X.509 public key. Expected values in the DER encoded sequence in the following format [ Sequence | BitString ]");
    }

    DerInputStream der = new DerInputStream(sequence[0].toByteArray());
    ObjectIdentifier algorithmOID = der.getOID();

    KeyType type = KeyType.getKeyTypeFromOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Could not decode the X.509 public key. Expected at 2 values in the DER encoded sequence but found [" + sequence.length + "]");
    }

    return new PEM(KeyFactory.getInstance(type.name()).generatePublic(new X509EncodedKeySpec(bytes)));
  }

  private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s+", "");
    return Base64.getDecoder().decode(base64);
  }

  private PublicKey getPublicKeyFromPrivateEC(DerValue bitString, ECPrivateKey privateKey) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    // Build an X.509 DER encoded byte array from the provided bitString
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    DerValue[] sequence = new DerInputStream(privateKey.getEncoded()).getSequence();
    byte[] encodedPublicKey = new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(Tag.Sequence, sequence[1].toByteArray()))
            .writeValue(new DerValue(Tag.BitString, bitString.toByteArray()))))
        .toByteArray();

    return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
  }
}
