// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hcpq;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Objects;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The HCPQ v1 transaction-signature profile.
 *
 * <p>HCPQ does not define a new hardness assumption. It applies strict key identifiers and a ledger-bound,
 * purpose-separated transcript to the FIPS 204 ML-DSA-44 primitive.
 */
public final class Hcpq {
    /** HCPQ wire and transcript version. */
    public static final int VERSION = 1;

    /** HCPQ algorithm identifier for ML-DSA-44. */
    public static final int ML_DSA_44 = 2;

    /** Raw FIPS 204 ML-DSA-44 public-key length. */
    public static final int PUBLIC_KEY_LENGTH = 1_312;

    /** Raw FIPS 204 ML-DSA-44 signature length. */
    public static final int SIGNATURE_LENGTH = 2_420;

    /** HCPQ key identifiers are complete SHA3-256 outputs, never variable prefixes. */
    public static final int KEY_ID_LENGTH = 32;

    private static final byte[] KEY_ID_DOMAIN = "HCPQ-SIG-KEY-ID\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TX_DOMAIN = "HCPQ-SIG-HEDERA-TX\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TX_CONTEXT = "HCPQ-SIG-TX-v1".getBytes(StandardCharsets.US_ASCII);
    private static final Provider PROVIDER = new BouncyCastleProvider();

    private Hcpq() {}

    /** Generates an ML-DSA-44 key pair using caller-supplied cryptographic randomness. */
    public static KeyPair generateKeyPair(final SecureRandom random) throws GeneralSecurityException {
        Objects.requireNonNull(random, "random must not be null");
        final var generator = KeyPairGenerator.getInstance("ML-DSA", PROVIDER);
        generator.initialize(MLDSAParameterSpec.ml_dsa_44, random);
        return generator.generateKeyPair();
    }

    /** Returns the 1,312-byte raw public-key encoding used on the Hedera wire. */
    public static byte[] rawPublicKey(final KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair must not be null");
        if (!(keyPair.getPublic() instanceof MLDSAPublicKey publicKey)) {
            throw new IllegalArgumentException("keyPair must contain an ML-DSA public key");
        }
        final byte[] encoded = publicKey.getPublicData();
        requireLength(encoded, PUBLIC_KEY_LENGTH, "public key");
        return encoded.clone();
    }

    /** Computes the exact 32-byte HCPQ identifier for a raw ML-DSA-44 public key. */
    public static byte[] keyId(final byte[] rawPublicKey) {
        requireLength(rawPublicKey, PUBLIC_KEY_LENGTH, "public key");
        final var digest = sha3();
        digest.update(KEY_ID_DOMAIN);
        digest.update((byte) VERSION);
        digest.update((byte) ML_DSA_44);
        digest.update(uint64(rawPublicKey.length));
        return digest.digest(rawPublicKey);
    }

    /**
     * Signs the HCPQ transaction digest. The caller must supply the exact canonical TransactionBody bytes.
     */
    public static byte[] signTransaction(
            final byte[] ledgerId,
            final byte[] canonicalTransactionBody,
            final PrivateKey privateKey,
            final SecureRandom random)
            throws GeneralSecurityException {
        requireLedgerAndBody(ledgerId, canonicalTransactionBody);
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(random, "random must not be null");

        final var signer = Signature.getInstance("ML-DSA", PROVIDER);
        signer.initSign(privateKey, random);
        signer.setParameter(new ContextParameterSpec(TX_CONTEXT));
        signer.update(transactionDigest(ledgerId, canonicalTransactionBody));
        final byte[] signature = signer.sign();
        requireLength(signature, SIGNATURE_LENGTH, "signature");
        return signature;
    }

    /**
     * Verifies one detached HCPQ signature and fails closed for every malformed input.
     */
    public static boolean verifyTransaction(
            final byte[] ledgerId,
            final byte[] canonicalTransactionBody,
            final byte[] rawPublicKey,
            final byte[] expectedKeyId,
            final byte[] rawSignature) {
        try {
            requireLedgerAndBody(ledgerId, canonicalTransactionBody);
            requireLength(rawPublicKey, PUBLIC_KEY_LENGTH, "public key");
            requireLength(expectedKeyId, KEY_ID_LENGTH, "key id");
            requireLength(rawSignature, SIGNATURE_LENGTH, "signature");
            if (!MessageDigest.isEqual(keyId(rawPublicKey), expectedKeyId)) {
                return false;
            }

            final var spec = new MLDSAPublicKeySpec(MLDSAParameterSpec.ml_dsa_44, rawPublicKey);
            final var publicKey = KeyFactory.getInstance("ML-DSA", PROVIDER).generatePublic(spec);
            final var verifier = Signature.getInstance("ML-DSA", PROVIDER);
            verifier.initVerify(publicKey);
            verifier.setParameter(new ContextParameterSpec(TX_CONTEXT));
            verifier.update(transactionDigest(ledgerId, canonicalTransactionBody));
            return verifier.verify(rawSignature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Computes the fixed-size, ledger-bound digest signed by ML-DSA-44. */
    public static byte[] transactionDigest(final byte[] ledgerId, final byte[] canonicalTransactionBody) {
        requireLedgerAndBody(ledgerId, canonicalTransactionBody);
        final var digest = sha3();
        digest.update(TX_DOMAIN);
        digest.update((byte) VERSION);
        digest.update(uint16(ledgerId.length));
        digest.update(ledgerId);
        digest.update(uint64(canonicalTransactionBody.length));
        return digest.digest(canonicalTransactionBody);
    }

    private static MessageDigest sha3() {
        try {
            return MessageDigest.getInstance("SHA3-256");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA3-256 is required by the Java runtime", e);
        }
    }

    private static void requireLedgerAndBody(final byte[] ledgerId, final byte[] body) {
        Objects.requireNonNull(ledgerId, "ledgerId must not be null");
        Objects.requireNonNull(body, "canonicalTransactionBody must not be null");
        if (ledgerId.length == 0 || ledgerId.length > 0xFFFF) {
            throw new IllegalArgumentException("ledgerId length must be between 1 and 65535 bytes");
        }
        if (body.length == 0) {
            throw new IllegalArgumentException("canonicalTransactionBody must not be empty");
        }
    }

    private static void requireLength(final byte[] value, final int expected, final String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.length != expected) {
            throw new IllegalArgumentException(name + " must be exactly " + expected + " bytes");
        }
    }

    private static byte[] uint16(final int value) {
        return ByteBuffer.allocate(Short.BYTES).putShort((short) value).array();
    }

    private static byte[] uint64(final long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }
}
