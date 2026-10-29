// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import com.hedera.common.nativesupport.SingletonLoader;

/**
 * A JNI Bridge for the BLS operations that verify Ethereum signatures in the ciphersuite Ethereum signs with,
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_}.
 */
public final class EthereumBlsBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<EthereumBlsBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("hints", new EthereumBlsBridge());

    private static final int EIP2537_G1_LENGTH_BYTES = 128;
    private static final int EIP2537_G2_LENGTH_BYTES = 256;

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        EthereumBlsBridge.class
                .getModule()
                .addOpens(INSTANCE_HOLDER.getNativeLibraryPackageName(), SingletonLoader.class.getModule());
    }

    private EthereumBlsBridge() {
        // private constructor to ensure singleton
    }

    /**
     * Returns the singleton instance of this library adapter.
     *
     * @return the singleton instance of this library adapter.
     */
    public static EthereumBlsBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * Verifies the aggregate signature of an Ethereum sync committee, given the aggregate public key of the whole
     * committee and the public keys of the members that did not sign.
     * <p>
     * The aggregate public key of the signers is recovered as the committee's aggregate public key minus the public
     * keys of the non-signers, which takes one point addition per non-signer: at most a third of the committee when
     * the 2/3 supermajority signed. The signature is then checked with the {@code FastAggregateVerify} operation of
     * the BLS signature spec, in the ciphersuite Ethereum signs with,
     * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_}: the message is hashed to G2 per RFC 9380, and the pairing
     * equation {@code e(signers, H(message)) == e(g1, signature)} must hold.
     * <p>
     * Points use the EIP-2537 encoding. Every public key, the committee's aggregate included, must be a point on the
     * curve, in the prime-order subgroup and not the identity (the spec's {@code KeyValidate}). So must the signature,
     * and the signers' aggregate public key must not be the identity either.
     * <p>
     * WARNING: this method trusts that the aggregate public key is the sum of the committee members' public keys and
     * that every non-signer is a distinct member of that committee. The caller must authenticate both, e.g. against
     * the SSZ root of the committee; otherwise whoever supplies them chooses the key the signature is checked under.
     *
     * @param aggregatePublicKey the 128-byte EIP-2537 G1 aggregate public key of the whole committee
     * @param nonSignerPublicKeys the 128-byte EIP-2537 G1 public keys of the members that did not sign; empty if
     *     every member signed
     * @param message the signed message; for a sync committee, the 32-byte signing root of the attested header
     * @param signature the 256-byte EIP-2537 G2 aggregate signature
     * @return true if the signature is valid; false otherwise, or on any malformed input
     */
    public boolean verifySyncAggregate(
            final byte[] aggregatePublicKey,
            final byte[][] nonSignerPublicKeys,
            final byte[] message,
            final byte[] signature) {
        if (aggregatePublicKey == null
                || aggregatePublicKey.length != EIP2537_G1_LENGTH_BYTES
                || !allHaveLength(nonSignerPublicKeys, EIP2537_G1_LENGTH_BYTES)
                || message == null
                || signature == null
                || signature.length != EIP2537_G2_LENGTH_BYTES) {
            return false;
        }
        return verifySyncAggregateImpl(aggregatePublicKey, nonSignerPublicKeys, message, signature);
    }

    private native boolean verifySyncAggregateImpl(
            final byte[] aggregatePublicKey,
            final byte[][] nonSignerPublicKeys,
            final byte[] message,
            final byte[] signature);

    /**
     * Checks that every public key is valid in the EIP-2537 encoding: a G1 point on the curve, in the prime-order
     * subgroup and not the identity (the {@code KeyValidate} procedure of the BLS signature spec).
     * This validates the public keys and the aggregate public key of an Ethereum sync committee before
     * {@link #verifySyncAggregate(byte[], byte[][], byte[], byte[])} relies on them.
     *
     * @param publicKeys the 128-byte EIP-2537 G1 public keys; not empty
     * @return true if every public key is valid; false otherwise, or on any malformed input
     */
    public boolean validateG1Eip2537PublicKeys(final byte[][] publicKeys) {
        if (publicKeys == null || publicKeys.length == 0 || !allHaveLength(publicKeys, EIP2537_G1_LENGTH_BYTES)) {
            return false;
        }
        return validateG1Eip2537PublicKeysImpl(publicKeys);
    }

    private native boolean validateG1Eip2537PublicKeysImpl(final byte[][] publicKeys);

    // Returns true if the array isn't null and none of its elements is null or of a length other than the given one.
    private static boolean allHaveLength(final byte[][] arrays, final int length) {
        if (arrays == null) {
            return false;
        }
        for (final byte[] array : arrays) {
            if (array == null || array.length != length) {
                return false;
            }
        }
        return true;
    }
}
