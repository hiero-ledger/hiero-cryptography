// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import com.hedera.cryptography.security.der.model.OID;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/// A java.security.PrivateKey implementation for a secp256k1 EC private key.
///
/// Our Libsecp256k1-aware code would only ever use the getSecretKey() directly.
/// However, this current PrivateKey implementation can be fed to a Bouncy Castle signer,
/// and it will be able to produce a valid EcDSA secp256k1 signature using this key as well.
///
/// Any other functionality isn't directly supported, but can be implemented if needed.
///
/// NOTE: This record doesn't make a defensive copy of the secretKey bytes. Applications
/// are responsible for not modifying the array, or if they do, then the key changes accordingly.
///
/// @param secretKey 32 bytes secret key
public record Secp256k1ECPrivateKey(byte[] secretKey) implements ECPrivateKey, DerEncoder {
    /// Secp256k1 G.
    public static final ECPoint SECP256K1_G = new ECPoint(
            new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424"));

    /// Secp256k1 N.
    public static final BigInteger SECP256K1_CURVE_N =
            new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337");

    /// Secp256k1 H.
    public static final int SECP256K1_H = 1;

    /// Secp256k1 Fp field.
    public static final ECField SECP256K1_FIELD = new ECFieldFp(
            new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663"));

    /// Secp256k1 curve.
    public static final EllipticCurve SECP256K1_CURVE =
            new EllipticCurve(SECP256K1_FIELD, BigInteger.ZERO, new BigInteger("7"));

    /// Secp256k1 EC parameters.
    public static final ECParameterSpec SECP256K1_PARAMS =
            new ECParameterSpec(SECP256K1_CURVE, SECP256K1_G, SECP256K1_CURVE_N, SECP256K1_H);

    private static final OID SECP256K1_CURVE_OID = new OID("1.3.132.0.10");
    private static final OID EC_PUBLIC_KEY_OID = new OID("1.2.840.10045.2.1");

    public Secp256k1ECPrivateKey {
        if (secretKey == null || secretKey.length != Libsecp256k1.SECRET_KEY_BYTES) {
            throw new IllegalArgumentException("Expected a secret key of length " + Libsecp256k1.SECRET_KEY_BYTES
                    + " , but got " + (secretKey == null ? "null" : ("" + secretKey.length)));
        }
    }

    @Override
    public ECParameterSpec getParams() {
        return SECP256K1_PARAMS;
    }

    @Override
    public BigInteger getS() {
        return new BigInteger(1, secretKey);
    }

    @Override
    public String getAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getEncoded() {
        return /* DerEncoder. */ toByteArray();
    }

    /// SEC1 EC-PrivateKey ("the older") format.
    private record DerSec1PrivateKey(Secp256k1ECPrivateKey key) implements DerEncoder {
        @Override
        public void emit(DerOutputStream os) {
            DerWriter.putInteger(os, (byte) 1);
            DerWriter.put(os, DerWriter.TAG_OCTET_STRING, key.secretKey());
            SECP256K1_CURVE_OID.encode(os, DerWriter.createTag(DerWriter.TAG_TBS_CERTIFICATE, false, (byte) 0));
        }
    }

    private record DerAlgorithm() implements DerEncoder {
        @Override
        public void emit(DerOutputStream os) {
            EC_PUBLIC_KEY_OID.encode(os);
            SECP256K1_CURVE_OID.encode(os);
        }
    }

    /// Emit a PKCS#8 PrivateKeyInfo for this key. The PrivateKey.getEncoded() is a useful
    /// shortcut to get this value.
    @Override
    public void emit(DerOutputStream os) {
        DerWriter.putInteger(os, (byte) 0);
        new DerAlgorithm().encode(os);
        DerEncoder.wrap(DerWriter.TAG_OCTET_STRING, new DerSec1PrivateKey(this)).encode(os);
    }
}
