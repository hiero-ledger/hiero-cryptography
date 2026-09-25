// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

public class TSSCompressedWRAPSProof {
    static final byte[] COMPRESSED_WRAPS_PROOF =
            new byte[TSSCompressedWRAPSProof1.PART1.length + TSSCompressedWRAPSProof2.PART2.length];

    // We have to perform this dance because otherwise we get "code too large" from javac:
    static {
        System.arraycopy(
                TSSCompressedWRAPSProof1.PART1, 0, COMPRESSED_WRAPS_PROOF, 0, TSSCompressedWRAPSProof1.PART1.length);
        System.arraycopy(
                TSSCompressedWRAPSProof2.PART2,
                0,
                COMPRESSED_WRAPS_PROOF,
                TSSCompressedWRAPSProof1.PART1.length,
                TSSCompressedWRAPSProof2.PART2.length);
    }
}
