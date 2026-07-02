// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import com.hedera.common.nativesupport.ForeignLibrary;
import com.hedera.common.nativesupport.NativeLibrary;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Map;

/// Libsecp256k1 native library Java FFM bindings.
/// https://github.com/bitcoin-core/secp256k1 .
public final class Libsecp256k1 {
    // Implementation note: the native secp256k1 library defines structs for keys, such as:
    //    typedef struct secp256k1_pubkey {
    //        unsigned char data[64];
    //    } secp256k1_pubkey;
    // for opaqueness and syntax benefits in C code.
    // However, all APIs accept pointers to such structs and never return/take them by value.
    // Further, unsigned char has an alignment of 1 byte with no padding,
    // so a pointer to the struct is the same as a pointer to its first field, which is the char array.
    // So, to simplify our API, we don't model these structs in our code.
    // We accept MemorySegments that point directly to user byte arrays,
    // and as far as C is concerned, this is perfectly fine.

    /// Singleton support
    private static final class InstanceHolder {
        private static final Libsecp256k1 INSTANCE = new Libsecp256k1();
    }

    /// Return a singleton instance of the Libsecp256k1 object.
    public static Libsecp256k1 getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /// Public key length.
    public static final int PUBLIC_KEY_BYTES = 64;
    /// Secret key length.
    public static final int SECRET_KEY_BYTES = 32;
    /// Signature length.
    public static final int SIGNATURE_BYTES = 64;
    /// Recoverable signature length.
    public static final int RECOVERABLE_SIGNATURE_BYTES = 65;

    /// Flag for uncompressed serialization (65 bytes).
    public static final int SECP256K1_EC_UNCOMPRESSED = 2;

    /// Flag for compressed serialization (33 bytes).
    public static final int SECP256K1_EC_COMPRESSED = 258;

    /// Native size_t for Java FFM.
    private static final MemoryLayout C_SIZE_T =
            Linker.nativeLinker().canonicalLayouts().get("size_t");

    static {
        // !!! NOTE !!!: we assume we run on a 64-bit system, and size_t is 64 bits, aka long.
        // To support 32-bit systems, we'd need a conditional at runtime to cast the value to either int or long.
        // This would have a performance penalty, and would complicate the code unnecessarily.
        if (C_SIZE_T.byteSize() != Long.BYTES) {
            throw new IllegalStateException(
                    "Only 64-bit systems are supported. size_t is not a long. Instead its size is "
                            + C_SIZE_T.byteSize());
        }
    }

    // Handles for native functions
    private final MethodHandle secp256k1ContextCreate;
    private final MethodHandle secp256k1ContextRandomize;
    private final MethodHandle secp256k1EcPubkeyCreate;
    private final MethodHandle secp256k1EcPubkeyParse;
    private final MethodHandle secp256k1EcPubkeySerialize;
    private final MethodHandle secp256k1EcdsaSignatureParseCompact;
    private final MethodHandle secp256k1EcdsaSignatureNormalize;
    private final MethodHandle secp256k1EcdsaVerify;
    private final MethodHandle secp256k1EcdsaRecover;
    private final MethodHandle secp256k1EcdsaRecoverableSignatureParseCompact;
    private final MethodHandle secp256k1EcdsaSignRecoverable;
    private final MethodHandle secp256k1EcdsaRecoverableSignatureSerializeCompact;

    @SuppressWarnings("restricted") // lookup() and downcallHandle() are restricted
    private Libsecp256k1() {
        // libsecp256k1 always has the "lib" prefix on all platforms, so we pass Map.of() for prefixes:
        final ForeignLibrary library =
                ForeignLibrary.withName("libsecp256k1", Map.of(), NativeLibrary.DEFAULT_LIB_EXTENSIONS);

        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        Libsecp256k1.class.getModule().addOpens(library.packageNameOfResource(), ForeignLibrary.class.getModule());

        // Use the global Arena because we intend to load the library once and never unload it again:
        final SymbolLookup lookup = library.lookup(Libsecp256k1.class, Arena.global());
        final Linker linker = Linker.nativeLinker();

        this.secp256k1ContextCreate = lookup.find("secp256k1_context_create")
                .map(symbol ->
                        linker.downcallHandle(symbol, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_context_create' not found"));

        this.secp256k1ContextRandomize = lookup.find("secp256k1_context_randomize")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_context_randomize' not found"));

        this.secp256k1EcPubkeyCreate = lookup.find("secp256k1_ec_pubkey_create")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ec_pubkey_create' not found"));

        this.secp256k1EcPubkeyParse = lookup.find("secp256k1_ec_pubkey_parse")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                C_SIZE_T),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ec_pubkey_parse' not found"));

        this.secp256k1EcPubkeySerialize = lookup.find("secp256k1_ec_pubkey_serialize")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ec_pubkey_serialize' not found"));

        this.secp256k1EcdsaSignatureParseCompact = lookup.find("secp256k1_ecdsa_signature_parse_compact")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() ->
                        new IllegalStateException("Function 'secp256k1_ecdsa_signature_parse_compact' not found"));

        this.secp256k1EcdsaSignatureNormalize = lookup.find("secp256k1_ecdsa_signature_normalize")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(
                        () -> new IllegalStateException("Function 'secp256k1_ecdsa_signature_normalize' not found"));

        this.secp256k1EcdsaVerify = lookup.find("secp256k1_ecdsa_verify")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ecdsa_verify' not found"));

        this.secp256k1EcdsaRecover = lookup.find("secp256k1_ecdsa_recover")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ecdsa_recover' not found"));

        this.secp256k1EcdsaRecoverableSignatureParseCompact = lookup.find(
                        "secp256k1_ecdsa_recoverable_signature_parse_compact")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException(
                        "Function 'secp256k1_ecdsa_recoverable_signature_parse_compact' not found"));

        this.secp256k1EcdsaSignRecoverable = lookup.find("secp256k1_ecdsa_sign_recoverable")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'secp256k1_ecdsa_sign_recoverable' not found"));

        this.secp256k1EcdsaRecoverableSignatureSerializeCompact = lookup.find(
                        "secp256k1_ecdsa_recoverable_signature_serialize_compact")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException(
                        "Function 'secp256k1_ecdsa_recoverable_signature_serialize_compact' not found"));
    }

    /// Create a secp256k1 context, which usually should be done just once as the operation is very heavy.
    /// A non-NoChecks version only as applications will use the ContextualLibsecp256k1 class.
    /// @param flags flags bitmask
    /// @return a context MemorySegment
    public MemorySegment secp256k1ContextCreateNoChecks(int flags) throws Throwable {
        return (MemorySegment) secp256k1ContextCreate.invokeExact(flags);
    }

    /// Randomizes a context.
    /// A non-NoChecks version only as applications will use the ContextualLibsecp256k1 class.
    /// @param context secp256k1 context
    /// @param seed32 random 32 bytes
    /// @return 1 on success, 0 on error
    public int secp256k1ContextRandomizeNoChecks(MemorySegment context, MemorySegment seed32) throws Throwable {
        return (int) secp256k1ContextRandomize.invokeExact(context, seed32);
    }

    /// Create a pubkey from a seckey.
    /// @param context secp256k1 context
    /// @param pubkey 64 bytes segment that receives a public key
    /// @param seckey 32 bytes long secret key
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeyCreate(MemorySegment context, MemorySegment pubkey, MemorySegment seckey) {
        try {
            if (pubkey.byteSize() != PUBLIC_KEY_BYTES) {
                return 0;
            }
            if (seckey.byteSize() != SECRET_KEY_BYTES) {
                return 0;
            }
            return secp256k1EcPubkeyCreateNoChecks(context, pubkey, seckey);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeyCreateNoChecks(MemorySegment context, MemorySegment pubkey, MemorySegment seckey)
            throws Throwable {
        return (int) secp256k1EcPubkeyCreate.invokeExact(context, pubkey, seckey);
    }

    /// Parse variable size public key from input into the pubkey.
    /// @param context secp256k1 context
    /// @param pubkey 64 bytes segment that receives a public key
    /// @param input serialized public key
    /// @param inputlen the length of the input
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeyParse(MemorySegment context, MemorySegment pubkey, MemorySegment input, long inputlen) {
        try {
            if (pubkey.byteSize() != PUBLIC_KEY_BYTES) {
                return 0;
            }
            if (input.byteSize() != inputlen) {
                return 0;
            }
            return secp256k1EcPubkeyParseNoChecks(context, pubkey, input, inputlen);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeyParseNoChecks(
            MemorySegment context, MemorySegment pubkey, MemorySegment input, long inputlen) throws Throwable {
        return (int) secp256k1EcPubkeyParse.invokeExact(context, pubkey, input, inputlen);
    }

    /// Serialize public key to output.
    /// @param context secp256k1 context
    /// @param output 65 or 33 bytes array that receives the serialized key
    /// @param outputlenPtr initially points to a size_t with output length, receives the actual length written
    /// @param pubkey 64 bytes segment that contains a public key
    /// @param flags flags for serialization - SECP256K1_EC_COMPRESSED or SECP256K1_EC_UNCOMPRESSED
    /// @return 1 on success, 0 on error
    public int secp256k1EcPubkeySerialize(
            MemorySegment context, MemorySegment output, MemorySegment outputlenPtr, MemorySegment pubkey, int flags) {
        try {
            if (pubkey.byteSize() != PUBLIC_KEY_BYTES) {
                return 0;
            }
            final long initialOutputLength = outputlenPtr.get((ValueLayout.OfLong) C_SIZE_T, 0);
            if (output.byteSize() != initialOutputLength) {
                return 0;
            }
            return secp256k1EcPubkeySerializeNoChecks(context, output, outputlenPtr, pubkey, flags);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcPubkeySerializeNoChecks(
            MemorySegment context, MemorySegment output, MemorySegment outputlenPtr, MemorySegment pubkey, int flags)
            throws Throwable {
        return (int) secp256k1EcPubkeySerialize.invokeExact(context, output, outputlenPtr, pubkey, flags);
    }

    /// Parse signature.
    /// @param context secp256k1 context
    /// @param signature 64 bytes segment that receives a signature
    /// @param input64 64 bytes segment that contains serialized signature to parse
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaSignatureParseCompact(
            MemorySegment context, MemorySegment signature, MemorySegment input64) {
        try {
            if (signature.byteSize() != SIGNATURE_BYTES) {
                return 0;
            }
            if (input64.byteSize() != 64) {
                return 0;
            }
            return secp256k1EcdsaSignatureParseCompactNoChecks(context, signature, input64);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignatureParseCompactNoChecks(
            MemorySegment context, MemorySegment signature, MemorySegment input64) throws Throwable {
        return (int) secp256k1EcdsaSignatureParseCompact.invokeExact(context, signature, input64);
    }

    /// Normalize signature.
    /// @param context secp256k1 context
    /// @param sigout a 64 bytes segment that receives a normalized signature
    /// @param sigin a 64 bytes segment with an input signature, normalized or not
    /// @return 1 if sigin was not normalized, 0 if it was already normalized
    public int secp256k1EcdsaSignatureNormalize(MemorySegment context, MemorySegment sigout, MemorySegment sigin) {
        try {
            if (sigout.byteSize() != SIGNATURE_BYTES) {
                return 0;
            }
            if (sigin.byteSize() != SIGNATURE_BYTES) {
                return 0;
            }
            return secp256k1EcdsaSignatureNormalizetNoChecks(context, sigout, sigin);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignatureNormalizetNoChecks(
            MemorySegment context, MemorySegment sigout, MemorySegment sigin) throws Throwable {
        return (int) secp256k1EcdsaSignatureNormalize.invokeExact(context, sigout, sigin);
    }

    /// Verify signature.
    /// @param context secp256k1 context
    /// @param sig a 64 bytes segment with a signature
    /// @param msghash32 a 32 bytes message
    /// @param pubkey a 64 bytes segment with a public key
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaVerify(
            MemorySegment context, MemorySegment sig, MemorySegment msghash32, MemorySegment pubkey) {
        try {
            if (sig.byteSize() != SIGNATURE_BYTES) {
                return 0;
            }
            if (msghash32.byteSize() != 32) {
                return 0;
            }
            if (pubkey.byteSize() != PUBLIC_KEY_BYTES) {
                return 0;
            }
            return secp256k1EcdsaVerifyNoChecks(context, sig, msghash32, pubkey);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaVerifyNoChecks(
            MemorySegment context, MemorySegment sig, MemorySegment msghash32, MemorySegment pubkey) throws Throwable {
        return (int) secp256k1EcdsaVerify.invokeExact(context, sig, msghash32, pubkey);
    }

    /// Recover pubkey from sig.
    /// @param context secp256k1 context
    /// @param pubkey a 64 bytes segment that receives a public key
    /// @param sig a 65 bytes segment with a recoverable signature
    /// @param msghash32 a 32 bytes message
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecover(
            MemorySegment context, MemorySegment pubkey, MemorySegment sig, MemorySegment msghash32) {
        try {
            if (pubkey.byteSize() != PUBLIC_KEY_BYTES) {
                return 0;
            }
            if (sig.byteSize() != RECOVERABLE_SIGNATURE_BYTES) {
                return 0;
            }
            if (msghash32.byteSize() != 32) {
                return 0;
            }
            return secp256k1EcdsaRecoverNoChecks(context, pubkey, sig, msghash32);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverNoChecks(
            MemorySegment context, MemorySegment pubkey, MemorySegment sig, MemorySegment msghash32) throws Throwable {
        return (int) secp256k1EcdsaRecover.invokeExact(context, pubkey, sig, msghash32);
    }

    /// Parse a compact signature.
    /// @param context secp256k1 context
    /// @param sig a 65 bytes segment that receives a recoverable signature
    /// @param input64 a 64 bytes compact signature
    /// @param recid recovery id - 0, 1, 2, or 3
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecoverableSignatureParseCompact(
            MemorySegment context, MemorySegment sig, MemorySegment input64, int recid) {
        try {
            if (sig.byteSize() != RECOVERABLE_SIGNATURE_BYTES) {
                return 0;
            }
            if (input64.byteSize() != 64) {
                return 0;
            }
            return secp256k1EcdsaRecoverableSignatureParseCompactNoChecks(context, sig, input64, recid);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverableSignatureParseCompactNoChecks(
            MemorySegment context, MemorySegment sig, MemorySegment input64, int recid) throws Throwable {
        return (int) secp256k1EcdsaRecoverableSignatureParseCompact.invokeExact(context, sig, input64, recid);
    }

    /// Create a recoverable signature.
    /// @param context secp256k1 context
    /// @param sig a 65 bytes segment that receives a recoverable signature
    /// @param msghash32 a 32 bytes message
    /// @param seckey 32 bytes long secret key
    /// @param noncefp a pointer to a function to generate nonce, can be NULL
    /// @param ndata arbitrary data for the nonce generator, can be NULL
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaSignRecoverable(
            MemorySegment context,
            MemorySegment sig,
            MemorySegment msghash32,
            MemorySegment seckey,
            MemorySegment noncefp,
            MemorySegment ndata) {
        try {
            if (sig.byteSize() != RECOVERABLE_SIGNATURE_BYTES) {
                return 0;
            }
            if (msghash32.byteSize() != 32) {
                return 0;
            }
            if (seckey.byteSize() != SECRET_KEY_BYTES) {
                return 0;
            }
            return secp256k1EcdsaSignRecoverableNoChecks(context, sig, msghash32, seckey, noncefp, ndata);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaSignRecoverableNoChecks(
            MemorySegment context,
            MemorySegment sig,
            MemorySegment msghash32,
            MemorySegment seckey,
            MemorySegment noncefp,
            MemorySegment ndata)
            throws Throwable {
        return (int) secp256k1EcdsaSignRecoverable.invokeExact(context, sig, msghash32, seckey, noncefp, ndata);
    }

    /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
    /// @param context secp256k1 context
    /// @param output64 a 64 bytes segment that receives the signature
    /// @param recid a pointer to integer that receives recovery id - 0, 1, 2, or 3
    /// @param sig a 65 bytes segment with a recoverable signature
    /// @return 1 on success, 0 on error
    public int secp256k1EcdsaRecoverableSignatureSerializeCompact(
            MemorySegment context, MemorySegment output64, MemorySegment recid, MemorySegment sig) {
        try {
            if (output64.byteSize() != 64) {
                return 0;
            }
            if (recid.byteSize() != Integer.BYTES) {
                return 0;
            }
            if (sig.byteSize() != RECOVERABLE_SIGNATURE_BYTES) {
                return 0;
            }
            return secp256k1EcdsaRecoverableSignatureSerializeCompactNoChecks(context, output64, recid, sig);
        } catch (Throwable t) {
            throw new Libsecp256k1Exception(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int secp256k1EcdsaRecoverableSignatureSerializeCompactNoChecks(
            MemorySegment context, MemorySegment output64, MemorySegment recid, MemorySegment sig) throws Throwable {
        return (int) secp256k1EcdsaRecoverableSignatureSerializeCompact.invokeExact(context, output64, recid, sig);
    }
}
