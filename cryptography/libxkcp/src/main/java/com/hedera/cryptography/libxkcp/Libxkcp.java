// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libxkcp;

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

/// libXKCP native library Java FFM bindings.
/// https://github.com/XKCP/XKCP .
public final class Libxkcp {

    /// Singleton support
    private static final class InstanceHolder {
        private static final Libxkcp INSTANCE = new Libxkcp();
    }

    /// Return a singleton instance of the Libxkcp object.
    public static Libxkcp getInstance() {
        return InstanceHolder.INSTANCE;
    }

    // HashReturn codes
    public static final int KECCAK_SUCCESS = 0;
    public static final int KECCAK_FAIL = 1;
    public static final int KECCAK_BAD_HASHLEN = 2;

    // Useful, commonly-used constants for HashInitialize
    public static final int SHA3_256_RATE = 1088;
    public static final int SHA3_256_CAPACITY = 512;
    public static final int SHA3_256_HASHBITLEN = 256;

    /// The original value as submitted by Keccak team to the NIST competition
    /// and used by Ethereum keccak256 - 0x01.
    /// Note that the modern finalized NIST FIPS 202 SHA3_256 standard uses 0x06 instead.
    public static final byte SHA3_256_DELIMITED_SUFFIX_ORIGINAL = 0x01;

    /// The length of a SHA3_256 hash value in bytes, as produced by the `keccakHashFinal()`.
    public static final int SHA3_256_HASHVAL_LENGTH_BYTES = SHA3_256_HASHBITLEN / 8;

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

    private final MethodHandle hieroSizeofKeccakHashInstance;
    private final MethodHandle keccakHashInitialize;
    private final MethodHandle keccakHashUpdate;
    private final MethodHandle keccakHashFinal;

    /// A size (in bytes) of the native Keccak_HashInstance structure that APIs use as a context.
    /// In Java, one can allocate a byte[] of this size, or a (possibly off-heap) MemorySegment
    /// to work with the hashing APIs.
    /// As of 2026-07-29, on Mac aarch64 the size is 224 bytes, but it varies from platform to platform
    /// and may change in the future. So applications should read this field at runtime rather than
    /// hard-code the value in their code.
    public final int sizeOfKeccakHashInstance;

    @SuppressWarnings("restricted") // lookup() and downcallHandle() are restricted
    private Libxkcp() {
        // It always has the "lib" prefix on all platforms, so we pass Map.of() for prefixes:
        final ForeignLibrary library =
                ForeignLibrary.withName("libXKCP", Map.of(), NativeLibrary.DEFAULT_LIB_EXTENSIONS);

        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        Libxkcp.class.getModule().addOpens(library.packageNameOfResource(), ForeignLibrary.class.getModule());

        // Use the global Arena because we intend to load the library once and never unload it again:
        final SymbolLookup lookup = library.lookup(Libxkcp.class, Arena.global());
        final Linker linker = Linker.nativeLinker();

        this.hieroSizeofKeccakHashInstance = ForeignLibrary.find(
                lookup, linker, "Hiero_sizeof_Keccak_HashInstance", FunctionDescriptor.of(C_SIZE_T));
        this.sizeOfKeccakHashInstance = Math.toIntExact(hieroSizeofKeccakHashInstance());

        this.keccakHashInitialize = ForeignLibrary.find(
                lookup,
                linker,
                "Keccak_HashInitialize",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE));
        this.keccakHashUpdate = ForeignLibrary.find(
                lookup,
                linker,
                "Keccak_HashUpdate",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, C_SIZE_T));
        this.keccakHashFinal = ForeignLibrary.find(
                lookup,
                linker,
                "Keccak_HashFinal",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /// Return the size of the native `Keccak_HashInstance` struct.
    public long hieroSizeofKeccakHashInstance() {
        try {
            return hieroSizeofKeccakHashInstanceNoChecks();
        } catch (Throwable t) {
            throw new LibxkcpException(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public long hieroSizeofKeccakHashInstanceNoChecks() throws Throwable {
        return (long) hieroSizeofKeccakHashInstance.invokeExact();
    }

    /// Initialize the Keccak[r, c] sponge function instance used in sequential hashing mode.
    public int keccakHashInitialize(
            MemorySegment hashInstance, int rate, int capacity, int hashbitlen, byte delimitedSuffix) {
        if (hashInstance.byteSize() != sizeOfKeccakHashInstance) {
            throw new IllegalArgumentException("hashInstance must be " + sizeOfKeccakHashInstance
                    + " bytes long, instead got " + hashInstance.byteSize());
        }
        if (rate <= 0 || capacity <= 0 || hashbitlen <= 0) {
            throw new IllegalArgumentException("rate, capacity, and hashbitlen must all be positive, instead got: "
                    + rate + ", " + capacity + ", " + hashbitlen);
        }

        try {
            return keccakHashInitializeNoChecks(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
        } catch (Throwable t) {
            throw new LibxkcpException(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int keccakHashInitializeNoChecks(
            MemorySegment hashInstance, int rate, int capacity, int hashbitlen, byte delimitedSuffix) throws Throwable {
        return (int) keccakHashInitialize.invokeExact(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
    }

    /// Give input data to be absorbed.
    public int keccakHashUpdate(MemorySegment hashInstance, MemorySegment data, long databitlen) {
        if (hashInstance.byteSize() != sizeOfKeccakHashInstance) {
            throw new IllegalArgumentException("hashInstance must be " + sizeOfKeccakHashInstance
                    + " bytes long, instead got " + hashInstance.byteSize());
        }
        if (databitlen < 0) {
            throw new IllegalArgumentException("databitlen must be non-negative, instead got: " + databitlen);
        }
        if (databitlen == 0) {
            // There's no data to hash, so there's no need to call into native. It's a no-op:
            return KECCAK_SUCCESS;
        }
        // Allow for a large buffer in case an application reuses a larger one:
        if (data.byteSize() < Math.ceilDiv(databitlen, 8)) {
            throw new IllegalArgumentException("data must be at least " + Math.ceilDiv(databitlen, 8)
                    + " bytes long for databitlen = " + databitlen + ", but instead got " + data.byteSize());
        }

        try {
            return keccakHashUpdateNoChecks(hashInstance, data, databitlen);
        } catch (Throwable t) {
            throw new LibxkcpException(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int keccakHashUpdateNoChecks(MemorySegment hashInstance, MemorySegment data, long databitlen)
            throws Throwable {
        return (int) keccakHashUpdate.invokeExact(hashInstance, data, databitlen);
    }

    /// Get output bits if the length was specified when calling `keccakHashInitialize()`.
    public int keccakHashFinal(MemorySegment hashInstance, MemorySegment hashval) {
        if (hashInstance.byteSize() != sizeOfKeccakHashInstance) {
            throw new IllegalArgumentException("hashInstance must be " + sizeOfKeccakHashInstance
                    + " bytes long, instead got " + hashInstance.byteSize());
        }

        // NOTE: we cannot really validate the size of the `hashval` because we don't know
        // the size of the hash value initialized previously via `keccakHashInitialize`.
        // We'd have to read it from the `hashInstance`, but the latter struct is opaque
        // (at Java level) and is difficult to model (at Java level) because it's platform-
        // -dependent.

        try {
            return keccakHashFinalNoChecks(hashInstance, hashval);
        } catch (Throwable t) {
            throw new LibxkcpException(t);
        }
    }

    /// A fast, unsafe version of the method that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int keccakHashFinalNoChecks(MemorySegment hashInstance, MemorySegment hashval) throws Throwable {
        return (int) keccakHashFinal.invokeExact(hashInstance, hashval);
    }
}
