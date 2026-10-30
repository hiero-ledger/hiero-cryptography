// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.Test;

/// Tests interoperability between our Secp256k1ECPrivateKey and Bouncy Castle signer/verifier,
/// and ensures both our Libsecp256k1 and Bouncy Castle verify all the signatures.
public class KeySignatureTest {
    private static final ContextualLibsecp256k1 LIBSECP256K1 = ContextualLibsecp256k1.getInstance();

    private static final Provider BOUNCYCASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BOUNCYCASTLE_PROVIDER);
        }
    }

    private static final byte[] MESSAGE = new byte[] {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32
    };

    @Test
    void signECTest() throws Throwable {
        // This test creates keys using both Bouncy Castle and our Libsecp256k1.
        // It then uses the keys to sign a message using BC and Lib.
        // Finally, it verifies all the signatures using both BC and Lib.

        final PrivateKey bcPrivateKey;
        final PublicKey bcPublicKey;
        {
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
            BigInteger d = new BigInteger(1, Constants.SK);
            org.bouncycastle.jce.spec.ECPrivateKeySpec privateKeySpec =
                    new org.bouncycastle.jce.spec.ECPrivateKeySpec(d, spec);
            KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
            bcPrivateKey = factory.generatePrivate(privateKeySpec);

            org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(d);
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(q, spec);
            bcPublicKey = factory.generatePublic(pubSpec);
        }

        final Secp256k1ECPrivateKey privateKey = new Secp256k1ECPrivateKey(Constants.SK);
        final byte[] publicKeyBytes = new byte[Libsecp256k1.PUBLIC_KEY_BYTES];
        assertEquals(
                1,
                LIBSECP256K1.secp256k1EcPubkeyCreate(
                        MemorySegment.ofArray(publicKeyBytes), MemorySegment.ofArray(Constants.SK)));

        // Ensure the PrivateKey.getEncoded() is the same for our key and BC key:
        Libsecp256k1Test.assertArrayEquals(bcPrivateKey.getEncoded(), privateKey.getEncoded());

        byte[] bcSignerBCKeySignature;
        {
            final Signature ecdsaSign = Signature.getInstance("NONEwithECDSA", BOUNCYCASTLE_PROVIDER);
            ecdsaSign.initSign(bcPrivateKey);
            ecdsaSign.update(MESSAGE);
            bcSignerBCKeySignature = ecdsaSign.sign();
        }

        byte[] bcSignerOurKeySignature;
        {
            final Signature ecdsaSign = Signature.getInstance("NONEwithECDSA", BOUNCYCASTLE_PROVIDER);
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(MESSAGE);
            bcSignerOurKeySignature = ecdsaSign.sign();
        }

        byte[] ourSignerOurKeySignature;
        {
            final byte[] signature = new byte[Libsecp256k1.RECOVERABLE_SIGNATURE_BYTES];
            final MemorySegment signatureSeg = MemorySegment.ofArray(signature);
            LIBSECP256K1.secp256k1EcdsaSignRecoverable(
                    signatureSeg,
                    MemorySegment.ofArray(MESSAGE),
                    MemorySegment.ofArray(Constants.SK),
                    MemorySegment.NULL,
                    MemorySegment.NULL);

            ourSignerOurKeySignature = new byte[Libsecp256k1.SIGNATURE_BYTES];
            final int[] recId = new int[1];
            LIBSECP256K1.secp256k1EcdsaRecoverableSignatureSerializeCompact(
                    MemorySegment.ofArray(ourSignerOurKeySignature), MemorySegment.ofArray(recId), signatureSeg);
        }

        // Note: secp256k1 signatures are non-deterministic. So we cannot compare them with hard-coded
        // values. But we can verify every signature using both BC and our library:

        {
            Signature verify = Signature.getInstance("NONEwithECDSA", BOUNCYCASTLE_PROVIDER);
            verify.initVerify(bcPublicKey);
            verify.update(MESSAGE);
            assertTrue(verify.verify(bcSignerBCKeySignature));

            assertEquals(1, verifyWithLibsecp256k1(rawEcdsaSigFromAsn1Der(bcSignerBCKeySignature), publicKeyBytes));
        }

        {
            Signature verify = Signature.getInstance("NONEwithECDSA", BOUNCYCASTLE_PROVIDER);
            verify.initVerify(bcPublicKey);
            verify.update(MESSAGE);
            assertTrue(verify.verify(bcSignerOurKeySignature));

            assertEquals(1, verifyWithLibsecp256k1(rawEcdsaSigFromAsn1Der(bcSignerOurKeySignature), publicKeyBytes));
        }

        {
            Signature verify = Signature.getInstance("NONEwithECDSA", BOUNCYCASTLE_PROVIDER);
            verify.initVerify(bcPublicKey);
            verify.update(MESSAGE);

            // BC uses DER-encoded signatures, so we prepare it here:
            byte[] derSignature;
            {
                record DerSignature(byte[] rawSignature) implements DerEncoder {
                    @Override
                    public void emit(DerOutputStream os) {
                        byte[] rBytes = Arrays.copyOfRange(rawSignature, 0, 32);
                        byte[] sBytes = Arrays.copyOfRange(rawSignature, 32, 64);

                        BigInteger r = new BigInteger(1, rBytes);
                        BigInteger s = new BigInteger(1, sBytes);

                        DerWriter.putInteger(os, r);
                        DerWriter.putInteger(os, s);
                    }
                }
                derSignature = new DerSignature(ourSignerOurKeySignature).toByteArray();
            }

            assertTrue(verify.verify(derSignature));

            assertEquals(1, verifyWithLibsecp256k1(ourSignerOurKeySignature, publicKeyBytes));
        }
    }

    /// Returns the return value of LIBSECP256K1.secp256k1EcdsaVerify(), which is 1 on success.
    private static int verifyWithLibsecp256k1(byte[] ourSignerOurKeySignature, byte[] publicKeyBytes) {
        byte[] nativeSignature = new byte[Libsecp256k1.SIGNATURE_BYTES];
        {
            final MemorySegment nativeSignatureSeg = MemorySegment.ofArray(nativeSignature);
            final var signatureParseResult = LIBSECP256K1.secp256k1EcdsaSignatureParseCompact(
                    nativeSignatureSeg, MemorySegment.ofArray(ourSignerOurKeySignature));
            if (signatureParseResult != 1) {
                throw new RuntimeException("signature parse error " + signatureParseResult);
            }
            // Normalize the signature to lower-S form. This will return 1 if the signature was normalized, 0 otherwise.
            LIBSECP256K1.secp256k1EcdsaSignatureNormalize(nativeSignatureSeg, nativeSignatureSeg);
        }
        return LIBSECP256K1.secp256k1EcdsaVerify(
                MemorySegment.ofArray(nativeSignature),
                MemorySegment.ofArray(MESSAGE),
                MemorySegment.ofArray(publicKeyBytes));
    }

    /// Parse a BC-native DER-encoded signature into a raw EcDSA signature.
    /// The code is borrowed from Hiero Consensus Node repository.
    private static byte[] rawEcdsaSigFromAsn1Der(final byte[] derSig) {
        final var rLenIndex = 3;
        final var rawBytes = new byte[64];

        final var origRLen = derSig[rLenIndex] & 0xff;
        int finalRLen = origRLen;
        int rStart = rLenIndex + 1;
        while (finalRLen > 32) {
            rStart++;
            finalRLen--;
        }
        System.arraycopy(derSig, rStart, rawBytes, 32 - finalRLen, Math.min(32, origRLen));

        final var sLenPos = rLenIndex + (derSig[rLenIndex] & 0xff) + 2;

        final var origSLen = derSig[sLenPos] & 0xff;
        int finalSLen = origSLen;
        int sStart = sLenPos + 1;
        while (finalSLen > 32) {
            sStart++;
            finalSLen--;
        }
        System.arraycopy(derSig, sStart, rawBytes, 32 + (32 - finalSLen), Math.min(32, origSLen));

        return rawBytes;
    }
}
