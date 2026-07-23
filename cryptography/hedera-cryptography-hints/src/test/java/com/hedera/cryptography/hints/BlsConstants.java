// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

/**
 * EIP-2537 test vectors for BLS12-381 G1 and G2 point decompression.
 * Source: EIP-2537 spec and add_G2_bls.json asset test vectors.
 */
class BlsConstants {

    // --- G1 generator ---

    /**
     * Beacon-compressed G1 generator (48 bytes).
     * First byte: 0x17 | 0x80 = 0x97 (compression flag; sign bit clear because y < p/2).
     */
    static final byte[] G1_COMPRESSED = fromHex(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac" +
            "586c55e83ff97a1aeffb3af00adb22c6bb");

    /**
     * Expected EIP-2537 G1 output (128 bytes): [16 zeros | x 48 BE | 16 zeros | y 48 BE].
     */
    static final byte[] G1_EIP2537 = fromHex(
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0" +
            "fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6" +
            "bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8" +
            "ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");

    // --- G2 generator ---

    /**
     * Beacon-compressed G2 generator (96 bytes).
     * Bytes  0–47: x.c1 with flags (first byte = 0x13 | 0x80 = 0x93, sign bit clear).
     * Bytes 48–95: x.c0.
     */
    static final byte[] G2_COMPRESSED = fromHex(
            "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f50" +
            "49334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51" +
            "051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");

    /**
     * Expected EIP-2537 G2 output (256 bytes):
     * [16 zeros | x.c0 48 BE | 16 zeros | x.c1 48 BE | 16 zeros | y.c0 48 BE | 16 zeros | y.c1 48 BE].
     */
    static final byte[] G2_EIP2537 = fromHex(
            "00000000000000000000000000000000024aa2b2f08f0a91260805272dc5105" +
            "1c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bd" +
            "b80000000000000000000000000000000013e02b6052719f607dacd3a088274f" +
            "65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b" +
            "7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e35" +
            "1aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828" +
            "01000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b" +
            "99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}