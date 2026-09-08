// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hcpq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HcpqTest {
    private static final byte[] LEDGER = {0x00};
    private static final byte[] OTHER_LEDGER = {0x01};
    private static final byte[] BODY = {0x0a, 0x01, 0x01};

    @Test
    void transcriptDerivationsMatchIndependentSha3Vectors() {
        final var hex = HexFormat.of();
        assertArrayEquals(
                hex.parseHex("b06481a311d5d184b1524f565611f20dd7a48c1f5fb1388fe26c963abb9d84f1"),
                Hcpq.transactionDigest(LEDGER, BODY));
        assertArrayEquals(
                hex.parseHex("12e887dd05eccac5b490be89fd73d070109cc7dccbc615d06d466bc5f0b9caac"),
                Hcpq.keyId(new byte[Hcpq.PUBLIC_KEY_LENGTH]));
    }

    @Test
    void signsAndVerifiesWithExactProtocolSizes() throws Exception {
        final var random = new SecureRandom();
        final var pair = Hcpq.generateKeyPair(random);
        final var publicKey = Hcpq.rawPublicKey(pair);
        final var keyId = Hcpq.keyId(publicKey);
        final var signature = Hcpq.signTransaction(LEDGER, BODY, pair.getPrivate(), random);

        assertEquals(Hcpq.PUBLIC_KEY_LENGTH, publicKey.length);
        assertEquals(Hcpq.KEY_ID_LENGTH, keyId.length);
        assertEquals(Hcpq.SIGNATURE_LENGTH, signature.length);
        assertTrue(Hcpq.verifyTransaction(LEDGER, BODY, publicKey, keyId, signature));
    }

    @Test
    void bindsLedgerBodyKeyIdentifierAndSignature() throws Exception {
        final var random = new SecureRandom();
        final var pair = Hcpq.generateKeyPair(random);
        final var publicKey = Hcpq.rawPublicKey(pair);
        final var keyId = Hcpq.keyId(publicKey);
        final var signature = Hcpq.signTransaction(LEDGER, BODY, pair.getPrivate(), random);

        assertFalse(Hcpq.verifyTransaction(OTHER_LEDGER, BODY, publicKey, keyId, signature));
        assertFalse(Hcpq.verifyTransaction(LEDGER, new byte[] {0x0a, 0x01, 0x02}, publicKey, keyId, signature));

        final var wrongId = keyId.clone();
        wrongId[0] ^= 1;
        assertFalse(Hcpq.verifyTransaction(LEDGER, BODY, publicKey, wrongId, signature));

        final var corruptSignature = signature.clone();
        corruptSignature[corruptSignature.length - 1] ^= 1;
        assertFalse(Hcpq.verifyTransaction(LEDGER, BODY, publicKey, keyId, corruptSignature));
    }

    @Test
    void malformedVerificationInputFailsClosed() {
        assertFalse(Hcpq.verifyTransaction(LEDGER, BODY, new byte[1], new byte[32], new byte[2420]));
        assertFalse(Hcpq.verifyTransaction(new byte[0], BODY, new byte[1312], new byte[32], new byte[2420]));
        assertFalse(Hcpq.verifyTransaction(LEDGER, new byte[0], new byte[1312], new byte[32], new byte[2420]));
    }

    @Test
    void signingRejectsEmptyLedgerOrBody() throws Exception {
        final var random = new SecureRandom();
        final var pair = Hcpq.generateKeyPair(random);
        assertThrows(
                IllegalArgumentException.class,
                () -> Hcpq.signTransaction(new byte[0], BODY, pair.getPrivate(), random));
        assertThrows(
                IllegalArgumentException.class,
                () -> Hcpq.signTransaction(LEDGER, new byte[0], pair.getPrivate(), random));
    }
}
