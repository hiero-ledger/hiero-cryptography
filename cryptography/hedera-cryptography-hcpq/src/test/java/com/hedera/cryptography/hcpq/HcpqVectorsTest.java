// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hcpq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Checks {@link Hcpq} against the published HCPQ v1 vectors in {@code src/test/resources/hcpq-v1}. Every derived
 * value in the files is recomputed from its inputs, so the files cannot drift from the implementation.
 */
class HcpqVectorsTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final Provider BC = new BouncyCastleProvider();
    private static final byte[] CONTEXT = "HCPQ-SIG-TX-v1".getBytes(StandardCharsets.US_ASCII);

    /** All-zero randomness selects the FIPS 204 deterministic variant, in which rnd is 32 zero bytes. */
    private static final SecureRandom DETERMINISTIC = new SecureRandom() {
        @Override
        public void nextBytes(final byte[] bytes) {
            Arrays.fill(bytes, (byte) 0);
        }
    };

    private static final Map<String, Object> SIGNATURES = load("signature-vectors.json");
    private static final Map<String, Object> CANONICAL_BODIES = load("canonical-transaction-body-vectors.json");

    @Test
    void constantsMatchImplementation() {
        final var constants = map(SIGNATURES, "constants");
        assertEquals((long) Hcpq.VERSION, constants.get("version"));
        assertEquals((long) Hcpq.ML_DSA_44, constants.get("algorithm_id_ml_dsa_44"));
        assertEquals((long) Hcpq.PUBLIC_KEY_LENGTH, constants.get("public_key_length"));
        assertEquals((long) Hcpq.SIGNATURE_LENGTH, constants.get("signature_length"));
        assertEquals((long) Hcpq.KEY_ID_LENGTH, constants.get("key_id_length"));
        assertArrayEquals(CONTEXT, hex(constants, "context"));
    }

    @TestFactory
    Stream<DynamicTest> keyIdentifiers() {
        return tests(SIGNATURES, "key_id")
                .map(v -> DynamicTest.dynamicTest(id(v), () -> {
                    final var publicKey = hex(v, "public_key");
                    assertArrayEquals(hex(v, "key_id"), Hcpq.keyId(publicKey));
                    if (v.containsKey("seed")) {
                        final var privateKey = privateKey(hex(v, "seed"));
                        final var pair = new KeyPair(privateKey.getPublicKey(), privateKey);
                        assertArrayEquals(publicKey, Hcpq.rawPublicKey(pair), "public key derived from seed");
                    }
                }));
    }

    @TestFactory
    Stream<DynamicTest> transactionDigests() {
        return tests(SIGNATURES, "transaction_digest")
                .map(v -> DynamicTest.dynamicTest(
                        id(v),
                        () -> assertArrayEquals(
                                hex(v, "transaction_digest"),
                                Hcpq.transactionDigest(hex(v, "ledger_id"), hex(v, "body")))));
    }

    @TestFactory
    Stream<DynamicTest> signatures() {
        final Map<String, Map<String, Object>> keys =
                tests(SIGNATURES, "key_id").collect(Collectors.toMap(HcpqVectorsTest::id, v -> v));
        return tests(SIGNATURES, "signature")
                .map(v -> DynamicTest.dynamicTest(id(v), () -> {
                    final var key = keys.get(string(v, "key"));
                    assertNotNull(key, "unknown key " + string(v, "key"));
                    final var ledgerId = hex(v, "ledger_id");
                    final var body = hex(v, "body");
                    final var signature = hex(v, "signature");
                    final var publicKey = v.containsKey("public_key") ? hex(v, "public_key") : hex(key, "public_key");
                    final var keyId = v.containsKey("key_id") ? hex(v, "key_id") : hex(key, "key_id");
                    final boolean valid =
                            switch (string(v, "result")) {
                                case "valid" -> true;
                                case "invalid" -> false;
                                default -> throw new IllegalArgumentException("result must be valid or invalid");
                            };

                    assertEquals(valid, Hcpq.verifyTransaction(ledgerId, body, publicKey, keyId, signature));

                    if (valid) {
                        final var digest = Hcpq.transactionDigest(ledgerId, body);
                        assertArrayEquals(hex(v, "transaction_digest"), digest);
                        assertArrayEquals(hex(v, "fips204_message"), fips204Message(CONTEXT, digest));
                        // The production signing path, made deterministic, must reproduce the vector exactly.
                        final var privateKey = privateKey(hex(key, "seed"));
                        assertArrayEquals(signature, Hcpq.signTransaction(ledgerId, body, privateKey, DETERMINISTIC));
                    }
                    if (v.containsKey("signed_as")) {
                        final var provenance = map(v, "signed_as");
                        final var signer = keys.get(string(provenance, "key"));
                        assertNotNull(signer, "unknown signed_as key");
                        assertArrayEquals(
                                signature,
                                sign(
                                        string(provenance, "mode"),
                                        hex(signer, "seed"),
                                        hex(provenance, "context"),
                                        hex(provenance, "message")),
                                "signature must be a genuine signature of signed_as");
                    }
                }));
    }

    @TestFactory
    Stream<DynamicTest> canonicalBodyDigests() {
        return tests(CANONICAL_BODIES, "tests")
                .filter(v -> "accept".equals(v.get("result")))
                .map(v -> DynamicTest.dynamicTest(
                        id(v),
                        () -> assertArrayEquals(
                                hex(v, "transaction_digest"),
                                Hcpq.transactionDigest(hex(v, "ledger_id"), hex(v, "body")))));
    }

    @Test
    void canonicalBodyVectorsAreConsistent() {
        final var ids = new HashSet<String>();
        final var accepted = new HashSet<String>();
        for (final var v : tests(CANONICAL_BODIES, "tests").toList()) {
            assertTrue(ids.add(id(v)), "duplicate id " + id(v));
            hex(v, "body");
            switch (string(v, "result")) {
                case "accept" -> {
                    accepted.add(id(v));
                    map(v, "body_json");
                }
                case "reject" ->
                    assertTrue(Set.of("strict_parse", "canonical_reencode").contains(string(v, "rejected_by")), id(v));
                default -> throw new AssertionError(id(v) + ": result must be accept or reject");
            }
        }
        tests(CANONICAL_BODIES, "tests")
                .filter(v -> v.containsKey("equivalent_to"))
                .forEach(v -> assertTrue(accepted.contains(string(v, "equivalent_to")), id(v)));
    }

    @Test
    void signatureVectorsSignCanonicalBodies() {
        final Set<String> canonical = tests(CANONICAL_BODIES, "tests")
                .filter(v -> "accept".equals(v.get("result")))
                .map(v -> string(v, "body"))
                .collect(Collectors.toSet());
        tests(SIGNATURES, "signature")
                .filter(v -> !"body_binding".equals(v.get("flag")))
                .forEach(v -> assertTrue(canonical.contains(string(v, "body")), id(v) + " signs a canonical body"));
    }

    /** FIPS 204 Algorithm 2: M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M. */
    private static byte[] fips204Message(final byte[] context, final byte[] message) {
        final var out = new byte[2 + context.length + message.length];
        out[1] = (byte) context.length;
        System.arraycopy(context, 0, out, 2, context.length);
        System.arraycopy(message, 0, out, 2 + context.length, message.length);
        return out;
    }

    private static MLDSAPrivateKey privateKey(final byte[] seed) throws GeneralSecurityException {
        return (MLDSAPrivateKey) KeyFactory.getInstance("ML-DSA-44", BC)
                .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.ml_dsa_44, seed));
    }

    private static byte[] sign(final String mode, final byte[] seed, final byte[] context, final byte[] message)
            throws GeneralSecurityException {
        final PrivateKey privateKey;
        final Signature signer;
        switch (mode) {
            case "ml_dsa" -> {
                privateKey = privateKey(seed);
                signer = Signature.getInstance("ML-DSA-44", BC);
            }
            case "hash_ml_dsa_sha512" -> {
                privateKey = KeyFactory.getInstance("HASH-ML-DSA", BC)
                        .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.ml_dsa_44_with_sha512, seed));
                signer = Signature.getInstance("ML-DSA-44-WITH-SHA512", BC);
            }
            default -> throw new IllegalArgumentException("unknown signed_as mode " + mode);
        }
        signer.initSign(privateKey, DETERMINISTIC);
        signer.setParameter(new ContextParameterSpec(context));
        signer.update(message);
        return signer.sign();
    }

    private static Map<String, Object> load(final String name) {
        try (var in = HcpqVectorsTest.class.getResourceAsStream("/hcpq-v1/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing vector file " + name);
            }
            return cast(Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Stream<Map<String, Object>> tests(final Map<String, Object> file, final String section) {
        final List<Object> entries = cast(file.get(section));
        return entries.stream().map(HcpqVectorsTest::cast);
    }

    private static String id(final Map<String, Object> vector) {
        return string(vector, "id");
    }

    private static Map<String, Object> map(final Map<String, Object> vector, final String field) {
        return cast(require(vector, field));
    }

    private static String string(final Map<String, Object> vector, final String field) {
        return (String) require(vector, field);
    }

    private static byte[] hex(final Map<String, Object> vector, final String field) {
        return HEX.parseHex(string(vector, field));
    }

    private static Object require(final Map<String, Object> vector, final String field) {
        final var value = vector.get(field);
        if (value == null) {
            throw new IllegalArgumentException("vector " + vector.get("id") + " is missing " + field);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static <T> T cast(final Object value) {
        return (T) value;
    }
}
