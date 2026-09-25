// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

/**
 * Test vectors for the BLS multi-signature bridge, in the canonical arkworks serialization.
 * <p>
 * They are derived from the same secret keys as the hinTS vectors in {@link HintsConstants}: the secret key of
 * party {@code i} is {@code HintsLibraryBridge.generateSecretKey(HintsConstants.RANDOM_i)}, its public key is
 * {@code g1 * secretKey}, and its signature is over {@link HintsConstants#RANDOM_2} as the message.
 */
class BlsMultisigConstants {

    /**
     * Public key of the party whose secret key is derived from {@link HintsConstants#RANDOM_0} (uncompressed).
     */
    static final byte[] PUBLIC_KEY_0 = fromHex("19fc07c0ebbbb98384bee559407a669233eeb9349154501359941a84ccd2"
            + "2f78851fd232f66c3e9ca783f516514115eb0429143112439dcd030d37b5"
            + "1da7c0aed3b57cee966f6bc28bf27026f2cbea9307682c07cf89515f0334"
            + "9209a611811a");

    /**
     * Public key of the party whose secret key is derived from {@link HintsConstants#RANDOM_1} (uncompressed).
     */
    static final byte[] PUBLIC_KEY_1 = fromHex("05bcac7a9f7de294f4f16d89ca7bba213d0b2914aa973e817e794241997f"
            + "5a7b89043df9122182110384ea97c19820790683ed04f029deda15f8c5ac"
            + "5cc70279f9bef8d54d2b9c319e71ca5805f83631e76eee5be25e55367245"
            + "752593c25cef");

    /**
     * Public key of the party whose secret key is derived from {@link HintsConstants#RANDOM_2} (uncompressed).
     * This is the key that verifies {@link HintsConstants#SIGNATURE}.
     */
    static final byte[] PUBLIC_KEY_2 = fromHex("0f93d9bef723790f77ee684f208e843b5f866d93fa6967eec84566ac4c76"
            + "f54a52c96cb87875eaf97927e7f93e2ea9b9142ae3d39329ffc48fb87aa1"
            + "59a04af9a555d3e5292f0d0e85890ceba81d5fc3edc0b3a5b911ec7b40af"
            + "a66ade592337");

    /**
     * Public key of the party whose secret key is derived from {@link HintsConstants#RANDOM_3} (uncompressed).
     */
    static final byte[] PUBLIC_KEY_3 = fromHex("006035c90ff673c168361c78d8e701d5ca7e908b51c50422aa9ba567fd9f"
            + "0e8724155829dc5158bde62e7d697441e46d08dd3a82c1db5c90114bdf45"
            + "6130d79c5ecbe1bf89a112ff455268b105009e1883a3dc68dfe53e019beb"
            + "9d30ca430c04");

    /**
     * The same public key as {@link #PUBLIC_KEY_2}, in the compressed serialization.
     */
    static final byte[] PUBLIC_KEY_2_COMPRESSED = fromHex(
            "af93d9bef723790f77ee684f208e843b5f866d93fa6967eec84566ac4c76" + "f54a52c96cb87875eaf97927e7f93e2ea9b9");

    /**
     * The same signature as {@link HintsConstants#SIGNATURE}, in the compressed serialization.
     */
    static final byte[] SIGNATURE_2_COMPRESSED = fromHex("b13bec656c68abb414c8942c3862e5a881141946842b071090b8be4ccd7e"
            + "27e4e7b1a431a6c3d9f34845adc1bbbeafbe12d19b6cd3364fc0aefd7d9c"
            + "1bc6b555b74d5e1dc38682d21120ce3f6ac476d171299851aea46af6ccb5"
            + "8d0cb4d1f469");

    /**
     * Sum of {@link #PUBLIC_KEY_0} and {@link #PUBLIC_KEY_2} (uncompressed).
     */
    static final byte[] AGGREGATE_PUBLIC_KEY_0_2 =
            fromHex("182f1563d87b0b5e1acf63fe264c846a9c7e4f208a1fc26662aa02a40df5"
                    + "a92e6bbc4ccb2d29fd7937075bb90bf5c3a3142457befdd5cf47573ac928"
                    + "3daa448aeb57ce3e945696d3869307d8c66e52c454f5ed66613e8bac1737"
                    + "004800b73040");

    /**
     * Sum of the signatures of the parties 0 and 2 on {@link HintsConstants#RANDOM_2} (uncompressed).
     * It verifies under {@link #AGGREGATE_PUBLIC_KEY_0_2}.
     */
    static final byte[] AGGREGATE_SIGNATURE_0_2 = fromHex("0abdadfdc0d5b01bbdfa812912379b2e25bc288873ca8c754dc81ad746a7"
            + "54122db9f8bd685d8cf116e451b4d3aaeca00e72e1b083f129ae82864ac9"
            + "8d6063334010241c5e836eaa2fbaf9e718f17e525f4e4e77c98f8358e751"
            + "e6d62e02a9bc1760a4995b444479af6c559cb9abf26d8b0deb65205bdc6b"
            + "be15a5800109947a942f787b18a8daad35d7dfada583b67e12ebb448ff28"
            + "b6773344c54ce94f65aaa316a290cdf4cef67c08363d0fd91c13c988f626"
            + "3e37084549c0c0554ffb03af");

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
