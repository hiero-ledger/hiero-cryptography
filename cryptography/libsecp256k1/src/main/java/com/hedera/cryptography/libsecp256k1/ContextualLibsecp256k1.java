// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import java.lang.foreign.MemorySegment;
import java.security.SecureRandom;

/// A Libsecp256k1 that creates and maintains a secp256k1 context,
/// simplifying the API usage for applications.
public class ContextualLibsecp256k1 {
    /// Singleton support
    private static final class InstanceHolder {
        private static final Libsecp256k1 LIBSECP256K1 = Libsecp256k1.getInstance();
        private static final ContextualLibsecp256k1 INSTANCE = new ContextualLibsecp256k1();
    }

    /// Return a singleton instance of the Libsecp256k1 object.
    public static ContextualLibsecp256k1 getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /// A magic number copied from Besu implementation.
    public static final int FLAGS_FOR_CONTEXT_CREATE = 769;

    /// Context object for libsecp256k1. We never free() it because we never unload the library.
    private final MemorySegment context;

    /// Create ContextualLibsecp256k1.
    /// The implementation replicates the behavior of the Besu library for maximum compatibility.
    private ContextualLibsecp256k1() {
        try {
            this.context = InstanceHolder.LIBSECP256K1.secp256k1ContextCreateNoChecks(FLAGS_FOR_CONTEXT_CREATE);

            if (Boolean.parseBoolean(System.getProperty("secp256k1.randomize", "true"))) {
                byte[] seed = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(seed);
                if (InstanceHolder.LIBSECP256K1.secp256k1ContextRandomizeNoChecks(context, MemorySegment.ofArray(seed))
                        != 1) {
                    throw new RuntimeException("Failed to call secp256k1_context_randomize");
                }
            }
        } catch (Throwable ex) {
            throw new Libsecp256k1Exception(ex);
        }
    }

    // Below are methods w/o the context argument that delegate to InstanceHolder.LIBSECP256K1
    // passing the `ContextualLibsecp256k1.context` as the first arg.

    /// Create a pubkey from a seckey.
    /// @param pubkey 64 bytes segment that receives a public key
    /// @param seckey 32 bytes long secret key
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeyCreate(MemorySegment pubkey, MemorySegment seckey) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeyCreate(context, pubkey, seckey);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeyCreateNoChecks(MemorySegment pubkey, MemorySegment seckey) throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeyCreate(context, pubkey, seckey);
    }

    /// Parse variable size public key from input into the pubkey.
    /// @param pubkey 64 bytes segment that receives a public key
    /// @param input serialized public key
    /// @param inputlen the length of the input
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeyParse(MemorySegment pubkey, MemorySegment input, long inputlen) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeyParse(context, pubkey, input, inputlen);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeyParseNoChecks(MemorySegment pubkey, MemorySegment input, long inputlen)
            throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeyParseNoChecks(context, pubkey, input, inputlen);
    }

    /// Serialize public key to output.
    /// @param output 65 or 33 bytes array that receives the serialized key
    /// @param outputlenPtr initially points to a size_t with output length, receives the actual length written
    /// @param pubkey 64 bytes segment that contains a public key
    /// @param flags flags for serialization - SECP256K1_EC_COMPRESSED or SECP256K1_EC_UNCOMPRESSED
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeySerialize(
            MemorySegment output, MemorySegment outputlenPtr, MemorySegment pubkey, int flags) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeySerialize(context, output, outputlenPtr, pubkey, flags);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeySerializeNoChecks(
            MemorySegment output, MemorySegment outputlenPtr, MemorySegment pubkey, int flags) throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcPubkeySerializeNoChecks(
                context, output, outputlenPtr, pubkey, flags);
    }

    /// Parse signature.
    /// @param signature 64 bytes segment that receives a signature
    /// @param input64 64 bytes segment that contains serialized signature to parse
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaSignatureParseCompact(MemorySegment signature, MemorySegment input64) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignatureParseCompact(context, signature, input64);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignatureParseCompactNoChecks(MemorySegment signature, MemorySegment input64)
            throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignatureParseCompactNoChecks(context, signature, input64);
    }

    /// Normalize signature.
    /// @param sigout a 64 bytes segment that receives a normalized signature
    /// @param sigin a 64 bytes segment with an input signature, normalized or not
    /// @return 1 if sigin was not normalized, 0 if it was already normalized
    public int secp256k1EcdsaSignatureNormalize(MemorySegment sigout, MemorySegment sigin) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignatureNormalize(context, sigout, sigin);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignatureNormalizetNoChecks(MemorySegment sigout, MemorySegment sigin) throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignatureNormalizetNoChecks(context, sigout, sigin);
    }

    /// Verify signature.
    /// @param sig a 64 bytes segment with a signature
    /// @param msghash32 a 32 bytes message
    /// @param pubkey a 64 bytes segment with a public key
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaVerify(MemorySegment sig, MemorySegment msghash32, MemorySegment pubkey) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaVerify(context, sig, msghash32, pubkey);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaVerifyNoChecks(MemorySegment sig, MemorySegment msghash32, MemorySegment pubkey)
            throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaVerifyNoChecks(context, sig, msghash32, pubkey);
    }

    /// Recover pubkey from sig.
    /// @param pubkey a 64 bytes segment that receives a public key
    /// @param sig a 65 bytes segment with a recoverable signature
    /// @param msghash32 a 32 bytes message
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecover(MemorySegment pubkey, MemorySegment sig, MemorySegment msghash32) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecover(context, pubkey, sig, msghash32);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverNoChecks(MemorySegment pubkey, MemorySegment sig, MemorySegment msghash32)
            throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecoverNoChecks(context, pubkey, sig, msghash32);
    }

    /// Parse a compact signature.
    /// @param sig a 65 bytes segment that receives a recoverable signature
    /// @param input64 a 64 bytes compact signature
    /// @param recid recovery id - 0, 1, 2, or 3
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecoverableSignatureParseCompact(MemorySegment sig, MemorySegment input64, int recid) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecoverableSignatureParseCompact(context, sig, input64, recid);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverableSignatureParseCompactNoChecks(
            MemorySegment sig, MemorySegment input64, int recid) throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecoverableSignatureParseCompactNoChecks(
                context, sig, input64, recid);
    }

    /// Create a recoverable signature.
    /// @param sig a 65 bytes segment that receives a recoverable signature
    /// @param msghash32 a 32 bytes message
    /// @param seckey 32 bytes long secret key
    /// @param noncefp a pointer to a function to generate nonce, can be NULL
    /// @param ndata arbitrary data for the nonce generator, can be NULL
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaSignRecoverable(
            MemorySegment sig,
            MemorySegment msghash32,
            MemorySegment seckey,
            MemorySegment noncefp,
            MemorySegment ndata) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignRecoverable(
                context, sig, msghash32, seckey, noncefp, ndata);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignRecoverableNoChecks(
            MemorySegment sig,
            MemorySegment msghash32,
            MemorySegment seckey,
            MemorySegment noncefp,
            MemorySegment ndata)
            throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaSignRecoverableNoChecks(
                context, sig, msghash32, seckey, noncefp, ndata);
    }

    /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
    /// @param output64 a 64 bytes segment that receives the signature
    /// @param recid a pointer to integer that receives recovery id - 0, 1, 2, or 3
    /// @param sig a 65 bytes segment with a recoverable signature
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecoverableSignatureSerializeCompact(
            MemorySegment output64, MemorySegment recid, MemorySegment sig) {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecoverableSignatureSerializeCompact(
                context, output64, recid, sig);
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverableSignatureSerializeCompactNoChecks(
            MemorySegment output64, MemorySegment recid, MemorySegment sig) throws Throwable {
        return InstanceHolder.LIBSECP256K1.secp256k1EcdsaRecoverableSignatureSerializeCompactNoChecks(
                context, output64, recid, sig);
    }
}
