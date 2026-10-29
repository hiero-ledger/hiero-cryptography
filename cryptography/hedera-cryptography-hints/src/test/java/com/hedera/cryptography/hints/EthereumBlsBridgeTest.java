// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static com.hedera.cryptography.hints.EthereumBlsConstants.G1_NOT_IN_SUBGROUP;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G1_NOT_ON_CURVE;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G1_ON_ANOTHER_CURVE;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G1_X_ABOVE_MODULUS;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G1_X_EQUAL_TO_MODULUS;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G2_NOT_IN_SUBGROUP;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G2_NOT_ON_CURVE;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G2_ON_ANOTHER_CURVE;
import static com.hedera.cryptography.hints.EthereumBlsConstants.G2_X_ABOVE_MODULUS;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.hints.EthereumSyncCommittee.MainnetSample;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests {@link EthereumBlsBridge} against real mainnet sync aggregates
 * ({@link EthereumSyncCommittee#fullParticipationMainnetSampleData()},
 * {@link EthereumSyncCommittee#sixNonSignersMainnetSampleData()}) and the EIP-2537 failure vectors
 * ({@link EthereumBlsConstants}).
 */
@DisplayName("EthereumBlsBridge")
class EthereumBlsBridgeTest {
    private static final EthereumBlsBridge INSTANCE = EthereumBlsBridge.getInstance();
    // Converts the compressed test vectors to EIP-2537.
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final MainnetSample FULL_PARTICIPATION = EthereumSyncCommittee.fullParticipationMainnetSampleData();
    private static final MainnetSample SIX_NON_SIGNERS = EthereumSyncCommittee.sixNonSignersMainnetSampleData();

    private static final String INVALID_G1_ENCODINGS =
            "com.hedera.cryptography.hints.EthereumBlsBridgeTest#invalidG1Encodings";
    private static final int EIP2537_FP_LENGTH_BYTES = 64;
    private static final int EIP2537_FP_PADDING_LENGTH_BYTES = 16;
    private static final int EIP2537_G1_LENGTH_BYTES = 2 * EIP2537_FP_LENGTH_BYTES;
    private static final int EIP2537_G2_LENGTH_BYTES = 4 * EIP2537_FP_LENGTH_BYTES;
    private static final int FP_LENGTH_BYTES = 48;

    @Nested
    @DisplayName("verifySyncAggregate")
    class VerifySyncAggregate {

        @Test
        @DisplayName("given a mainnet aggregate signed by the whole committee, then it returns true")
        void givenFullParticipation_thenReturnsTrue() {
            assertTrue(verify(FULL_PARTICIPATION, FULL_PARTICIPATION.nonSigners()));
        }

        @Test
        @DisplayName("given a mainnet aggregate and its six non-signers, then it returns true")
        void givenPartialParticipation_thenReturnsTrue() {
            final List<byte[]> nonSigners = SIX_NON_SIGNERS.nonSigners();

            assertEquals(6, nonSigners.size());
            assertTrue(verify(SIX_NON_SIGNERS, nonSigners));
        }

        @Test
        @DisplayName("given the signing root of another aggregate, then it returns false")
        void givenAnotherSigningRoot_thenReturnsFalse() {
            assertFalse(INSTANCE.verifySyncAggregate(
                    eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()),
                    eip2537G1(SIX_NON_SIGNERS.nonSigners()),
                    FULL_PARTICIPATION.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @Test
        @DisplayName("given one non-signer less, then it returns false")
        void givenMissingNonSigner_thenReturnsFalse() {
            final List<byte[]> nonSigners = SIX_NON_SIGNERS.nonSigners();

            assertFalse(verify(SIX_NON_SIGNERS, nonSigners.subList(1, nonSigners.size())));
        }

        @Test
        @DisplayName("given a signer listed as a non-signer, then it returns false")
        void givenSignerAsNonSigner_thenReturnsFalse() {
            final List<byte[]> nonSigners = new ArrayList<>(SIX_NON_SIGNERS.nonSigners());
            nonSigners.add(SIX_NON_SIGNERS.signers().getFirst());

            assertFalse(verify(SIX_NON_SIGNERS, nonSigners));
        }

        @Test
        @DisplayName("given a non-signer listed twice, then it returns false")
        void givenDuplicateNonSigner_thenReturnsFalse() {
            final List<byte[]> nonSigners = new ArrayList<>(SIX_NON_SIGNERS.nonSigners());
            nonSigners.add(nonSigners.getFirst());

            assertFalse(verify(SIX_NON_SIGNERS, nonSigners));
        }

        @Test
        @DisplayName("given non-signers that cancel out the aggregate public key, then it returns false")
        void givenNonSignersCancellingTheAggregate_thenReturnsFalse() {
            final byte[] publicKey = eip2537G1(SIX_NON_SIGNERS.publicKeys().getFirst());

            assertFalse(INSTANCE.verifySyncAggregate(
                    publicKey,
                    new byte[][] {publicKey},
                    SIX_NON_SIGNERS.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource(INVALID_G1_ENCODINGS)
        @DisplayName("given an invalid aggregate public key, then it returns false")
        void givenInvalidAggregatePublicKey_thenReturnsFalse(final UnaryOperator<byte[]> invalidate) {
            assertFalse(INSTANCE.verifySyncAggregate(
                    invalidate.apply(SIX_NON_SIGNERS.aggregatePublicKey()),
                    eip2537G1(SIX_NON_SIGNERS.nonSigners()),
                    SIX_NON_SIGNERS.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource(INVALID_G1_ENCODINGS)
        @DisplayName("given an invalid non-signer public key, then it returns false")
        void givenInvalidNonSigner_thenReturnsFalse(final UnaryOperator<byte[]> invalidate) {
            final List<byte[]> nonSigners = SIX_NON_SIGNERS.nonSigners();
            final byte[][] encoded = eip2537G1(nonSigners);
            encoded[0] = invalidate.apply(nonSigners.getFirst());

            assertFalse(INSTANCE.verifySyncAggregate(
                    eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()),
                    encoded,
                    SIX_NON_SIGNERS.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("invalidG2Encodings")
        @DisplayName("given an invalid signature, then it returns false")
        void givenInvalidSignature_thenReturnsFalse(final UnaryOperator<byte[]> invalidate) {
            assertFalse(INSTANCE.verifySyncAggregate(
                    eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()),
                    eip2537G1(SIX_NON_SIGNERS.nonSigners()),
                    SIX_NON_SIGNERS.signingRoot(),
                    invalidate.apply(SIX_NON_SIGNERS.signature())));
        }

        /** Invalid EIP-2537 encodings of a G2 point, each computed from the compressed form of a valid one. */
        static Stream<Named<UnaryOperator<byte[]>>> invalidG2Encodings() {
            return Stream.of(
                    invalidEncoding("the identity", point -> new byte[EIP2537_G2_LENGTH_BYTES]),
                    invalidEncoding("x above the field modulus", point -> G2_X_ABOVE_MODULUS),
                    invalidEncoding("a point off the curve", point -> G2_NOT_ON_CURVE),
                    invalidEncoding("a point outside the prime-order subgroup", point -> G2_NOT_IN_SUBGROUP),
                    invalidEncoding("a point of prime order on another curve", point -> G2_ON_ANOTHER_CURVE),
                    invalidEncoding("c0 and c1 swapped", point -> withSwappedFp2Coefficients(eip2537G2(point))),
                    invalidEncoding("a non-zero padding byte", point -> withNonZeroPadding(eip2537G2(point))),
                    invalidEncoding("the compressed point in place of x", point -> compressedG2InPlaceOfX(point)));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 48, 96, 127, 129, 256})
        @DisplayName("given an aggregate public key of the wrong length, then it returns false")
        void givenAggregatePublicKeyOfWrongLength_thenReturnsFalse(final int length) {
            assertFalse(INSTANCE.verifySyncAggregate(
                    Arrays.copyOf(eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()), length),
                    eip2537G1(SIX_NON_SIGNERS.nonSigners()),
                    SIX_NON_SIGNERS.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 48, 96, 127, 129, 256})
        @DisplayName("given a non-signer public key of the wrong length, then it returns false")
        void givenNonSignerOfWrongLength_thenReturnsFalse(final int length) {
            final byte[][] nonSigners = eip2537G1(SIX_NON_SIGNERS.nonSigners());
            nonSigners[0] = Arrays.copyOf(nonSigners[0], length);

            assertFalse(INSTANCE.verifySyncAggregate(
                    eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()),
                    nonSigners,
                    SIX_NON_SIGNERS.signingRoot(),
                    eip2537G2(SIX_NON_SIGNERS.signature())));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 96, 192, 255, 257, 512})
        @DisplayName("given a signature of the wrong length, then it returns false")
        void givenSignatureOfWrongLength_thenReturnsFalse(final int length) {
            assertFalse(INSTANCE.verifySyncAggregate(
                    eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey()),
                    eip2537G1(SIX_NON_SIGNERS.nonSigners()),
                    SIX_NON_SIGNERS.signingRoot(),
                    Arrays.copyOf(eip2537G2(SIX_NON_SIGNERS.signature()), length)));
        }

        @Test
        @DisplayName("given a null argument or non-signer, then it returns false")
        void givenNullArgument_thenReturnsFalse() {
            final byte[] aggregatePublicKey = eip2537G1(SIX_NON_SIGNERS.aggregatePublicKey());
            final byte[][] nonSigners = eip2537G1(SIX_NON_SIGNERS.nonSigners());
            final byte[] message = SIX_NON_SIGNERS.signingRoot();
            final byte[] signature = eip2537G2(SIX_NON_SIGNERS.signature());
            final byte[][] nonSignersWithNull = nonSigners.clone();
            nonSignersWithNull[0] = null;

            assertAll(
                    () -> assertFalse(INSTANCE.verifySyncAggregate(null, nonSigners, message, signature)),
                    () -> assertFalse(INSTANCE.verifySyncAggregate(aggregatePublicKey, null, message, signature)),
                    () -> assertFalse(
                            INSTANCE.verifySyncAggregate(aggregatePublicKey, nonSignersWithNull, message, signature)),
                    () -> assertFalse(INSTANCE.verifySyncAggregate(aggregatePublicKey, nonSigners, null, signature)),
                    () -> assertFalse(INSTANCE.verifySyncAggregate(aggregatePublicKey, nonSigners, message, null)));
        }

        private boolean verify(final MainnetSample sample, final List<byte[]> nonSigners) {
            return INSTANCE.verifySyncAggregate(
                    eip2537G1(sample.aggregatePublicKey()),
                    eip2537G1(nonSigners),
                    sample.signingRoot(),
                    eip2537G2(sample.signature()));
        }
    }

    @Nested
    @DisplayName("validateG1Eip2537PublicKeys")
    class ValidateG1Eip2537PublicKeys {

        @Test
        @DisplayName("given the public keys and aggregate public key of a mainnet committee, then it returns true")
        void givenMainnetCommittee_thenReturnsTrue() {
            assertTrue(INSTANCE.validateG1Eip2537PublicKeys(committee()));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource(INVALID_G1_ENCODINGS)
        @DisplayName("given a committee with one invalid public key, then it returns false")
        void givenInvalidPublicKey_thenReturnsFalse(final UnaryOperator<byte[]> invalidate) {
            final byte[][] points = committee();
            points[points.length - 1] =
                    invalidate.apply(SIX_NON_SIGNERS.publicKeys().getLast());

            assertFalse(INSTANCE.validateG1Eip2537PublicKeys(points));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 48, 96, 127, 129, 256})
        @DisplayName("given a committee with one public key of the wrong length, then it returns false")
        void givenPublicKeyOfWrongLength_thenReturnsFalse(final int length) {
            final byte[][] points = committee();
            points[0] = Arrays.copyOf(points[0], length);

            assertFalse(INSTANCE.validateG1Eip2537PublicKeys(points));
        }

        @Test
        @DisplayName("given no points, then it returns false")
        void givenNoPoints_thenReturnsFalse() {
            assertFalse(INSTANCE.validateG1Eip2537PublicKeys(new byte[0][]));
        }

        @Test
        @DisplayName("given a null array or point, then it returns false")
        void givenNullArgument_thenReturnsFalse() {
            final byte[][] pointsWithNull = committee();
            pointsWithNull[0] = null;

            assertAll(
                    () -> assertFalse(INSTANCE.validateG1Eip2537PublicKeys(null)),
                    () -> assertFalse(INSTANCE.validateG1Eip2537PublicKeys(pointsWithNull)));
        }

        // Returns the 512 public keys and the aggregate public key of the mainnet committee, in EIP-2537 encoding.
        private static byte[][] committee() {
            final List<byte[]> points = new ArrayList<>(SIX_NON_SIGNERS.publicKeys());
            points.add(SIX_NON_SIGNERS.aggregatePublicKey());
            return eip2537G1(points);
        }
    }

    /** Invalid EIP-2537 encodings of a G1 point, each computed from the compressed form of a valid one. */
    static Stream<Named<UnaryOperator<byte[]>>> invalidG1Encodings() {
        return Stream.of(
                invalidEncoding("the identity", point -> new byte[EIP2537_G1_LENGTH_BYTES]),
                invalidEncoding("x equal to the field modulus", point -> G1_X_EQUAL_TO_MODULUS),
                invalidEncoding("x above the field modulus", point -> G1_X_ABOVE_MODULUS),
                invalidEncoding("a point off the curve", point -> G1_NOT_ON_CURVE),
                invalidEncoding("a point outside the prime-order subgroup", point -> G1_NOT_IN_SUBGROUP),
                invalidEncoding("a point of prime order on another curve", point -> G1_ON_ANOTHER_CURVE),
                invalidEncoding("a non-zero padding byte", point -> withNonZeroPadding(eip2537G1(point))),
                invalidEncoding("the compressed point in place of x", point -> compressedG1InPlaceOfX(point)));
    }

    private static Named<UnaryOperator<byte[]>> invalidEncoding(
            final String name, final UnaryOperator<byte[]> invalidate) {
        return Named.of(name, invalidate);
    }

    private static byte[] eip2537G1(final byte[] compressed) {
        return requireNonNull(HINTS.decompressG1ToEip2537(compressed));
    }

    private static byte[][] eip2537G1(final List<byte[]> compressed) {
        return compressed.stream().map(EthereumBlsBridgeTest::eip2537G1).toArray(byte[][]::new);
    }

    private static byte[] eip2537G2(final byte[] compressed) {
        return requireNonNull(HINTS.decompressG2ToEip2537(compressed));
    }

    // Swaps c0 and c1 of both coordinates of an EIP-2537 G2 point, i.e. writes them in the ZCash order instead.
    private static byte[] withSwappedFp2Coefficients(final byte[] point) {
        final byte[] swapped = new byte[point.length];
        for (int coordinate = 0; coordinate < point.length; coordinate += 2 * EIP2537_FP_LENGTH_BYTES) {
            System.arraycopy(point, coordinate, swapped, coordinate + EIP2537_FP_LENGTH_BYTES, EIP2537_FP_LENGTH_BYTES);
            System.arraycopy(point, coordinate + EIP2537_FP_LENGTH_BYTES, swapped, coordinate, EIP2537_FP_LENGTH_BYTES);
        }
        return swapped;
    }

    // Sets the last padding byte of the first field element of an EIP-2537 point.
    private static byte[] withNonZeroPadding(final byte[] point) {
        final byte[] padded = point.clone();
        padded[EIP2537_FP_PADDING_LENGTH_BYTES - 1] = 1;
        return padded;
    }

    // Returns an EIP-2537 G1 point whose x holds the 48-byte compressed point, flags included, and whose y is zero.
    // Read as a ZCash serialization without checking the flags, it would decode as the compressed point.
    private static byte[] compressedG1InPlaceOfX(final byte[] compressed) {
        final byte[] point = new byte[EIP2537_G1_LENGTH_BYTES];
        System.arraycopy(compressed, 0, point, EIP2537_FP_PADDING_LENGTH_BYTES, FP_LENGTH_BYTES);
        return point;
    }

    // Returns an EIP-2537 G2 point whose x holds the 96-byte compressed point, flags included, and whose y is zero.
    // The compressed point writes x.c1 first, then x.c0. Read as a ZCash serialization without checking the flags,
    // it would decode as the compressed point.
    private static byte[] compressedG2InPlaceOfX(final byte[] compressed) {
        final byte[] point = new byte[EIP2537_G2_LENGTH_BYTES];
        System.arraycopy(compressed, FP_LENGTH_BYTES, point, EIP2537_FP_PADDING_LENGTH_BYTES, FP_LENGTH_BYTES); // x.c0
        System.arraycopy(
                compressed,
                0,
                point,
                EIP2537_FP_LENGTH_BYTES + EIP2537_FP_PADDING_LENGTH_BYTES,
                FP_LENGTH_BYTES); // x.c1
        return point;
    }
}
