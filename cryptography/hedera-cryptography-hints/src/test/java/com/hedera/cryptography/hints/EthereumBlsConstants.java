// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import java.util.HexFormat;

/**
 * Invalid EIP-2537 points for the BLS signatures of Ethereum, from the
 * <a href="https://github.com/ethereum/EIPs/blob/master/assets/eip-2537/fail-pairing_check_bls.json">EIP-2537 failure
 * vectors</a> of the pairing precompile.
 */
final class EthereumBlsConstants {

    // --- EIP-2537 fail-pairing_check_bls.json: the invalid point of each single-pair input ---

    /** {@code bls_pairing_e(G1_field_element_equal_to_modulus,G2)}: x is the field modulus. */
    static final byte[] G1_X_EQUAL_TO_MODULUS =
            fromHex("000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7"
                    + "64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
                    + "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
                    + "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");

    /** {@code bls_pairing_e(G1_invalid_field_element,G2)}: x is above the field modulus. */
    static final byte[] G1_X_ABOVE_MODULUS = fromHex("0000000000000000000000000000000031f2e5916b17be2e71b10b4292f558e7"
            + "27dfd7d48af9cbc5087f0ce00dcca27c8b01e83eaace1aefb539f00adb227166"
            + "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
            + "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");

    /** {@code bls_pairing_e(G1_not_on_curve,G2)}. */
    static final byte[] G1_NOT_ON_CURVE = fromHex("00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec9"
            + "7977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"
            + "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
            + "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");

    /** {@code bls_pairing_e(G1_not_in_correct_subgroup,G2)}: on the curve, outside the prime-order subgroup. */
    static final byte[] G1_NOT_IN_SUBGROUP = fromHex("000000000000000000000000000000000123456789abcdef0123456789abcdef"
            + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            + "00000000000000000000000000000000193fb7cedb32b2c3adc06ec11a96bc0d"
            + "661869316f5e4a577a9f7c179593987beb4fb2ee424dbb2f5dd891e228b46c4a");

    /** {@code bls_pairing_e(G1_in_correct_subgroup_invalid_curve,G2)}: of prime order, but on another curve. */
    static final byte[] G1_ON_ANOTHER_CURVE = fromHex("000000000000000000000000000000000a2833e497b38ee3ca5c62828bf4887a"
            + "9f940c9e426c7890a759c20f248c23a7210d2432f4c98a514e524b5184a0ddac"
            + "00000000000000000000000000000000150772d56bf9509469f9ebcd6e475704"
            + "29fd31b0e262b66d512e245c38ec37255529f2271fd70066473e393a8bead0c3");

    /** {@code bls_pairing_e(G1,G2_invalid_field_element)}: x.c0 is above the field modulus. */
    static final byte[] G2_X_ABOVE_MODULUS = fromHex("000000000000000000000000000000001c4bb49d2a0ef12b7123acdd7110bd29"
            + "2b5bc659edc54dc21b81de057194c79b2a5803255959bbef8e7f56c8c1216863"
            + "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
            + "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
            + "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a"
            + "adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
            + "000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99"
            + "cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

    /** {@code bls_pairing_e(G1,G2_not_on_curve)}. */
    static final byte[] G2_NOT_ON_CURVE = fromHex("00000000000000000000000000000000103121a2ceaae586d240843a39896732"
            + "5f8eb5a93e8fea99b62b9f88d8556c80dd726a4b30e84a36eeabaf3592937f27"
            + "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
            + "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
            + "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a"
            + "adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
            + "000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99"
            + "cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

    /** {@code bls_pairing_e(G1,G2_not_in_correct_subgroup)}: on the curve, outside the prime-order subgroup. */
    static final byte[] G2_NOT_IN_SUBGROUP = fromHex("00000000000000000000000000000000197bfd0342bbc8bee2beced2f173e1a8"
            + "7be576379b343e93232d6cef98d84b1d696e5612ff283ce2cfdccb2cfb65fa0c"
            + "00000000000000000000000000000000184e811f55e6f9d84d77d2f79102fd7e"
            + "a7422f4759df5bf7f6331d550245e3f1bcf6a30e3b29110d85e0ca16f9f6ae7a"
            + "000000000000000000000000000000000f10e1eb3c1e53d2ad9cf2d398b2dc22"
            + "c5842fab0a74b174f691a7e914975da3564d835cd7d2982815b8ac57f507348f"
            + "000000000000000000000000000000000767d1c453890f1b9110fda82f5815c2"
            + "7281aba3f026ee868e4176a0654feea41a96575e0c4d58a14dbfbcc05b5010b1");

    /** {@code bls_pairing_e(G1,G2_in_correct_subgroup_invalid_curve)}: of prime order, but on another curve. */
    static final byte[] G2_ON_ANOTHER_CURVE = fromHex("00000000000000000000000000000000152f39ccc20272ce00fb519fc4a3e91f"
            + "50d9eccefbfa51bfbaa77af322907a4372dc493b5226e66b836bc3f454cfbe0e"
            + "00000000000000000000000000000000116ce538b309cdd3587d13fd3fdccc52"
            + "3d2cea1c7be76994ef157dc677520ce22fded623d6408b042d38be76afdba889"
            + "00000000000000000000000000000000192c5538ec7cb7b7b7ee56520d39e2a1"
            + "b8dded91cb5d4c3fcbbde46795e2c7eb61871ba09aa6d521d063a4d99603cda4"
            + "00000000000000000000000000000000094919a748626cc6899e7cdfbc86c87d"
            + "0eda311ad5d78418719b3468c4c7d34223d6d0da1c4d8a99b32d46f835c5ba8f");

    private EthereumBlsConstants() {}

    private static byte[] fromHex(final String hex) {
        return HexFormat.of().parseHex(hex);
    }
}
