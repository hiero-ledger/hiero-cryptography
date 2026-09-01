// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import com.hedera.common.nativesupport.SingletonLoader;

/**
 * A JNI Bridge for the standalone BLS multi-signature API, which lives alongside the hinTS API of
 * {@link HintsLibraryBridge} in the same native library.
 * <p>
 * Signatures follow the same convention as hinTS: public keys are points in G1 of the BLS12-381 curve,
 * signatures are points in G2, and a signature on a message is verified against a public key with the
 * pairing equation {@code e(publicKey, H(message)) == e(g1, signature)}. A signature produced by
 * {@link HintsLibraryBridge#signBls(byte[], byte[])} therefore verifies through this bridge.
 * <p>
 * Public keys and signatures are exchanged as byte arrays in the canonical serialization of the
 * <i>arkworks</i> library, which accepts both the compressed and the uncompressed form on input, and
 * always produces the uncompressed form on output. NOTE: this is not the ZCash/IETF wire format that
 * {@link HintsLibraryBridge#decompressG1ToEip2537(byte[])} consumes; that format writes the
 * coordinates big-endian with the flags in the first byte, whereas arkworks writes them little-endian
 * with the flags in the last byte.
 * <p>
 * WARNING: aggregating public keys by summation is only sound against rogue-key attacks if every
 * public key that enters the aggregate has been checked against a proof of possession of its secret
 * key. This bridge does not perform that check; the caller must.
 */
public class BlsLibraryBridge {
    /**
     * Instance Holder for lazy loading and concurrency handling.
     * The native library is shared with {@link HintsLibraryBridge}, and is extracted and loaded only
     * once no matter which of the two bridges is used first.
     */
    private static final SingletonLoader<BlsLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("hints", new BlsLibraryBridge());

    /** The length of a public key (a G1 point) in the compressed serialization. */
    private static final int COMPRESSED_PUBLIC_KEY_LENGTH_BYTES = 48;

    /** The length of a public key (a G1 point) in the uncompressed serialization. */
    private static final int UNCOMPRESSED_PUBLIC_KEY_LENGTH_BYTES = 96;

    /** The length of a signature (a G2 point) in the compressed serialization. */
    private static final int COMPRESSED_SIGNATURE_LENGTH_BYTES = 96;

    /** The length of a signature (a G2 point) in the uncompressed serialization. */
    private static final int UNCOMPRESSED_SIGNATURE_LENGTH_BYTES = 192;

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        BlsLibraryBridge.class
                .getModule()
                .addOpens(INSTANCE_HOLDER.getNativeLibraryPackageName(), SingletonLoader.class.getModule());
    }

    private BlsLibraryBridge() {
        // private constructor to ensure singleton
    }

    /**
     * Returns the singleton instance of this library adapter.
     *
     * @return the singleton instance of this library adapter.
     */
    public static BlsLibraryBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * Checks that a BLS signature on a message verifies under a public key.
     * <p>
     * The public key must be a serialized G1 point of either {@value #COMPRESSED_PUBLIC_KEY_LENGTH_BYTES}
     * bytes (compressed) or {@value #UNCOMPRESSED_PUBLIC_KEY_LENGTH_BYTES} bytes (uncompressed), and the
     * signature a serialized G2 point of either {@value #COMPRESSED_SIGNATURE_LENGTH_BYTES} bytes
     * (compressed) or {@value #UNCOMPRESSED_SIGNATURE_LENGTH_BYTES} bytes (uncompressed). Both are checked
     * to be on the curve and in the prime order subgroup. An identity public key or an identity signature
     * satisfies the pairing equation for any message, and is rejected rather than accepted.
     *
     * @param signature the signature
     * @param message the signed message
     * @param publicKey the public key of the signer
     * @return true if the signature is valid; false otherwise, or on any malformed input
     */
    public boolean verifySignature(final byte[] signature, final byte[] message, final byte[] publicKey) {
        if (message == null
                || message.length == 0
                || !isValidSignatureLength(signature)
                || !isValidPublicKeyLength(publicKey)) {
            return false;
        }
        return verifySignatureImpl(signature, message, publicKey);
    }

    private native boolean verifySignatureImpl(final byte[] signature, final byte[] message, final byte[] publicKey);

    /**
     * Aggregates the public keys selected by the bitvector into a single public key, which is the sum of
     * the selected G1 points. The aggregate public key verifies the sum of the corresponding signatures on
     * a common message, via {@link #verifySignature(byte[], byte[], byte[])}.
     * <p>
     * The two arrays model a map from party to participation, so they must be of the same length, and the
     * bitvector must select at least one public key. Only the selected entries are read, so an entry the
     * bitvector skips may be null or hold arbitrary bytes, e.g. a placeholder for a party that never
     * published a public key.
     *
     * @param publicKeys the serialized public keys, one per party
     * @param bitvector the flags marking which of those public keys take part, of equal length
     * @return the aggregate public key in the uncompressed serialization
     *         ({@value #UNCOMPRESSED_PUBLIC_KEY_LENGTH_BYTES} bytes), or null on error
     */
    public byte[] aggregatePublicKeys(final byte[][] publicKeys, final boolean[] bitvector) {
        if (publicKeys == null
                || bitvector == null
                || publicKeys.length == 0
                || publicKeys.length != bitvector.length) {
            return null;
        }
        // ensure that every public key the bitvector selects is present and of a sane length
        boolean anySelected = false;
        for (int i = 0; i < publicKeys.length; i++) {
            if (!bitvector[i]) {
                continue;
            }
            if (!isValidPublicKeyLength(publicKeys[i])) {
                return null;
            }
            anySelected = true;
        }
        if (!anySelected) {
            return null;
        }
        return aggregatePublicKeysImpl(publicKeys, bitvector);
    }

    private native byte[] aggregatePublicKeysImpl(final byte[][] publicKeys, final boolean[] bitvector);

    // Returns true if the public key isn't null and has the length of a compressed or an uncompressed G1 point.
    private static boolean isValidPublicKeyLength(final byte[] publicKey) {
        return publicKey != null
                && (publicKey.length == COMPRESSED_PUBLIC_KEY_LENGTH_BYTES
                        || publicKey.length == UNCOMPRESSED_PUBLIC_KEY_LENGTH_BYTES);
    }

    // Returns true if the signature isn't null and has the length of a compressed or an uncompressed G2 point.
    private static boolean isValidSignatureLength(final byte[] signature) {
        return signature != null
                && (signature.length == COMPRESSED_SIGNATURE_LENGTH_BYTES
                        || signature.length == UNCOMPRESSED_SIGNATURE_LENGTH_BYTES);
    }
}
