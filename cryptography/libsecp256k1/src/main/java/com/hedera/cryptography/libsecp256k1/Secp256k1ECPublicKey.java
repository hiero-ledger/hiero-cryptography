// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/// A java.security.PublicKey implementation for a secp256k1 EC public key.
///
/// The key accepts a canonical key representation which can be obtained by calling
/// secp256k1EcPubkeySerialize on the result from a call to secp256k1EcPubkeyCreate,
/// and ignoring the prefix byte 0x04.
/// Using the internal key representation as obtained from secp256k1EcPubkeyCreate directly
/// would result in a "wrong" key which is likely to produce a "point not on curve"
/// exception or otherwise fail to verify a signature.
///
/// This implementation supports usages where a key created by our Libsecp256k1 bindings
/// needs to be used with other Java signature verifiers, such as Bouncy Castle,
/// or where it's convenient to use the generic Java PublicKey/ECPublicKey interfaces.
/// This way an application can support different keys, e.g. secp256k1, Ed25519, etc.
///
/// Libsecp256k1-aware applications would likely use the `publicKey()` getter only,
/// while generic signature verifiers would use standard ECPublicKey getters.
///
/// NOTE: only a limited set of operations is supported, such as getW(), getParams(),
/// and getEncoded(). Other operations throw exceptions currently, but can be implemented
/// if needed in the future.
///
/// NOTE: This record doesn't make a defensive copy of the publicKey bytes. Applications
/// are responsible for not modifying the array, or if they do, then the key changes accordingly.
///
/// @param publicKey 64 bytes with a canonical (portable) public key, where
///                  [0..31] describe the x coordinate, and [32..63] - the y.
///                  IMPORTANT: use secp256k1EcPubkeySerialize to obtain it.
public record Secp256k1ECPublicKey(byte[] publicKey) implements ECPublicKey, DerEncoder {
    public Secp256k1ECPublicKey {
        if (publicKey == null || publicKey.length != Libsecp256k1.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("Expected a public key of length " + Libsecp256k1.PUBLIC_KEY_BYTES
                    + " , but got " + (publicKey == null ? "null" : ("" + publicKey.length)));
        }
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(
                new BigInteger(1, Arrays.copyOfRange(publicKey, 0, 32)),
                new BigInteger(1, Arrays.copyOfRange(publicKey, 32, 64)));
    }

    @Override
    public ECParameterSpec getParams() {
        return Secp256k1ECPrivateKey.SECP256K1_PARAMS;
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

    @Override
    public void emit(DerOutputStream os) {
        // SubjectPublicKeyInfo = {AlgorithmIdentifier, bit_string}
        Secp256k1ECPrivateKey.SECP256K1_ALGORITHM_IDENTIFIER.encode(os);

        final byte[] bits = new byte[1 + publicKey.length];
        // Prefix 4 means a full, uncompressed public key with both x and y coordinates of the w point:
        bits[0] = (byte) 0x04;
        System.arraycopy(publicKey, 0, bits, 1, publicKey.length);
        DerWriter.putBitString(os, bits);
    }
}
