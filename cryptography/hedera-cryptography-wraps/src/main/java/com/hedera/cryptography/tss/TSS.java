// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

import com.hedera.cryptography.hints.HintsLibraryBridge;
import com.hedera.cryptography.wraps.WRAPSLibraryBridge;
import java.util.Arrays;

/**
 * Convenience API for Threshold Signature Scheme (TSS) verification.
 */
public final class TSS {

    private static final int HINTS_VERIFICATION_KEY_LENGTH = 1096;
    private static final int HINTS_SIGNATURE_LENGTH = HintsLibraryBridge.AGGREGATE_SIGNATURE_LENGTH_BYTES;
    private static final int COMPRESSED_WRAPS_PROOF_LENGTH = 11368;

    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();

    private TSS() {}

    /**
     * A convenience method to prepare a `tssSignature` composite array.
     *
     * @param hintsVerificationKey `HintsLibraryBridge.preprocess().verificationKey()`
     * @param hintsSignature `HintsLibraryBridge.aggregateSignatures()`
     * @param abProof `WRAPSLibraryBridge.constructWrapsProof().compressed()`
     * @return the composite `tssSignature` array which is a simple concatenation of the input arrays in their
     *         respective order
     * @throws IllegalArgumentException if any of the arguments are malformed
     */
    public static byte[] composeSignature(
            final byte[] hintsVerificationKey, final byte[] hintsSignature, final byte[] abProof)
            throws IllegalArgumentException {
        if (hintsVerificationKey == null || hintsVerificationKey.length != HINTS_VERIFICATION_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "`hintsVerificationKey` must have a length of " + HINTS_VERIFICATION_KEY_LENGTH);
        }
        if (hintsSignature == null || hintsSignature.length != HINTS_SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("`hintsSignature` must have a length of " + HINTS_SIGNATURE_LENGTH);
        }
        if (abProof == null || abProof.length != COMPRESSED_WRAPS_PROOF_LENGTH) {
            throw new IllegalArgumentException("`abProof` must have a length of " + COMPRESSED_WRAPS_PROOF_LENGTH);
        }

        final byte[] array = Arrays.copyOf(
                hintsVerificationKey, hintsVerificationKey.length + hintsSignature.length + abProof.length);
        System.arraycopy(hintsSignature, 0, array, hintsVerificationKey.length, hintsSignature.length);
        System.arraycopy(abProof, 0, array, hintsVerificationKey.length + hintsSignature.length, abProof.length);
        return array;
    }

    /**
     * A convenience API to verify a `tssSignature` on a `message` with a given `ledgerId`.
     * <p>
     * The `ledgerId` identifies a specific network and is computed by the `WRAPSLibraryBridge.computeNetworkID()`
     * using TSS genesis AddressBook and its genesis hinTS verification key.
     * <p>
     * The `tssSignature` is a composite array which is a simple concatenation of a `hints_verification_key`,
     * `hints_signature`, and an AddressBook proof data. See `TSS.composeSignature()` above for details.
     * <p>
     * The `message` is a message that has been signed via `HintsLibraryBridge.signBls()` prior to calling
     * the `HintsLibraryBridge.aggregateSignatures()` that produced the above `hints_signature`.
     * In Hiero networks, the `message` is likely a "block_root_hash".
     * <p>
     * The `ledgerId` is generally verified via the provided WRAPS compressed proof using a WRAPS verification key
     * currently installed in the library.
     * <p>
     * The `message` is verified against the provided `hints_signature` using the default threshold of strictly greater
     * than 1/2 of the network weight. See the three arguments version of the `HintsLibraryBridge.verifyAggregate()`
     * for details.
     *
     * @param ledgerId ledgerID as computed by `WRAPSLibraryBridge.computeNetworkID()` for genesis AB and hinTS key
     * @param tssSignature hints_verification_key || hints_signature || compressed_wraps_proof
     * @param message a message
     * @return true if both the message and the ledgerId verify successfully with the respective signatures and proofs.
     * @throws IllegalArgumentException if any of the arguments are malformed
     */
    public static boolean verifyTSS(final byte[] ledgerId, final byte[] tssSignature, final byte[] message)
            throws IllegalStateException, IllegalArgumentException {
        // First, check constraints
        if (ledgerId == null || ledgerId.length != 64) {
            throw new IllegalArgumentException("`ledgerId` must be a 64 bytes array, instead got "
                    + (ledgerId == null ? null : (ledgerId.length + "")));
        }
        if (tssSignature == null
                || tssSignature.length
                        != HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH + COMPRESSED_WRAPS_PROOF_LENGTH) {
            throw new IllegalArgumentException("`tssSignature` has a wrong length. Expected "
                    + (HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH + COMPRESSED_WRAPS_PROOF_LENGTH)
                    + " bytes, instead got " + (tssSignature == null ? null : (tssSignature.length + "")));
        }
        if (message == null || message.length == 0) {
            throw new IllegalArgumentException("`message` must be a non-empty array");
        }

        // Then check if the `ledgerId` verifies:
        final byte[] hintsVerificationKey = Arrays.copyOfRange(tssSignature, 0, HINTS_VERIFICATION_KEY_LENGTH);
        final byte[] abProof = Arrays.copyOfRange(
                tssSignature, HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH, tssSignature.length);
        if (!WRAPS.verifyCompressedProof(abProof, ledgerId, hintsVerificationKey)) {
            return false;
        }

        // Finally check if the `message` verifies via hinTS:
        final byte[] hintsSignature = Arrays.copyOfRange(
                tssSignature, HINTS_VERIFICATION_KEY_LENGTH, HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH);
        return HINTS.verifyAggregate(hintsSignature, message, hintsVerificationKey);
    }
}
