
package io.github.nichetoolkit.fusionauth.jwt.ec;

import io.github.nichetoolkit.fusionauth.der.DerInputStream;
import io.github.nichetoolkit.fusionauth.der.DerOutputStream;
import io.github.nichetoolkit.fusionauth.der.DerValue;
import io.github.nichetoolkit.fusionauth.der.Tag;
import io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * <code>ECDSASignature</code>
 * <p>The ecdsa signature class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class ECDSASignature {
  private final byte[] bytes;

  /**
   * <code>ECDSASignature</code>
   * <p>Instantiates a new ecdsa signature.</p>
   * @param bytes byte <p>The bytes parameter is <code>byte</code> type.</p>
   */
  public ECDSASignature(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * <code>derDecode</code>
   * <p>The der decode method.</p>
   * @param algorithm {@link io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm} <p>The algorithm parameter is <code>Algorithm</code> type.</p>
   * @return byte <p>The der decode return object is <code>byte</code> type.</p>
   * @throws IOException {@link java.io.IOException} <p>The io exception is <code>IOException</code> type.</p>
   * @see io.github.nichetoolkit.fusionauth.jwt.domain.Algorithm
   * @see java.io.IOException
   */
  public byte[] derDecode(Algorithm algorithm) throws IOException {
    // Incoming DER Sequence [ r, s ]
    DerValue[] sequence = new DerInputStream(bytes).getSequence();
    byte[] r = sequence[0].getPositiveBigInteger().toByteArray();
    byte[] s = sequence[1].getPositiveBigInteger().toByteArray();

    // The length of the result is fixed and discrete per algorithm.
    byte[] result;
    switch (algorithm) {
      case ES256:
        result = new byte[64];
        break;
      case ES384:
        result = new byte[96];
        break;
      case ES512:
        result = new byte[132];
        break;
      default:
        throw new IllegalArgumentException("Unable to decode the signature for algorithm [" + algorithm.name() + "]");
    }

    // Because the response is not encoded, the r and s component must take up an equal amount of the resulting array.
    // This allows the consumer of this value to always safely split the value in half based upon an index value since
    // the result is not encoded and does not contain any meta-data about the contents.
    int componentLength = result.length / 2;

    // The extracted byte array of the DER encoded value can be left padded. For this reason, the component lengths
    // may be greater than componentLength which is half of the result. So for example, if r is left padded, the
    // length may be equal to 67 in ES512 even though componentLength is only 66. This is why we must calculate the
    // source position for reading when we copy the r byte array into the result. The same is potentially true for
    // either component. We cannot make an assumption that the source position in r or s will be 0.
    //
    // Similarly, when the r and s components are not padded, but they are shorter than componentLength, we need to
    // pad the value to be right aligned in the result. This is why the destination position may not be 0 or
    // componentLength respectively for
    // r and s.
    //
    // If s is 65 bytes, then the destination position in the 0 initialized resulting array needs to be
    // componentLength + 1 so that we write the final byte of s at the end of the result.
    //
    // For clarity, calculate each input to the arraycopy method first.

    int rSrcPos = r.length > componentLength ? (r.length - componentLength) : 0;
    int rDstPos = Math.max(0, componentLength - r.length);
    int rLength = Math.min(r.length, componentLength);
    System.arraycopy(r, rSrcPos, result, rDstPos, rLength);

    int sSrcPos = s.length > componentLength ? (s.length - componentLength) : 0;
    int sDstPos = s.length < componentLength ? (componentLength + (componentLength - s.length)) : componentLength;
    int sLength = Math.min(s.length, componentLength);
    System.arraycopy(s, sSrcPos, result, sDstPos, sLength);

    return result;
  }

  /**
   * <code>derEncode</code>
   * <p>The der encode method.</p>
   * @return byte <p>The der encode return object is <code>byte</code> type.</p>
   * @throws IOException {@link java.io.IOException} <p>The io exception is <code>IOException</code> type.</p>
   * @see java.io.IOException
   */
  public byte[] derEncode() throws IOException {
    // Split the ECDSA encoded signature into two parts, the r and s components
    byte[] r = Arrays.copyOfRange(bytes, 0, bytes.length / 2);
    byte[] s = Arrays.copyOfRange(bytes, bytes.length / 2, bytes.length);

    return new DerOutputStream()
        // DER Sequence [ r, s ]
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(new BigInteger(1, r)))
            .writeValue(new DerValue(new BigInteger(1, s)))))
        .toByteArray();
  }
}
