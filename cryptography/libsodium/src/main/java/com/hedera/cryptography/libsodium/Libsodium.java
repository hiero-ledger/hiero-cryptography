// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsodium;

import com.hedera.common.nativesupport.ForeignLibrary;
import com.hedera.common.nativesupport.NativeLibrary;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Map;

/// Libsodium native library Java FFM bindings.
/// https://github.com/jedisct1/libsodium .
public final class Libsodium {

    /// Singleton support
    private static final class InstanceHolder {
        private static final Libsodium INSTANCE = new Libsodium();
    }

    /// Return a singleton instance of the Libsodium object.
    public static Libsodium getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /// Public Key length.
    public static final int ED25519_PUBLICKEYBYTES = 32;

    /// Secret Key length.
    public static final int ED25519_SECRETKEYBYTES = 64;

    /// Signature length.
    public static final int ED25519_BYTES = 64;

    // Handles for native functions
    private final MethodHandle cryptoSignKeypair;
    private final MethodHandle cryptoSignDetached;
    private final MethodHandle cryptoSignVerifyDetached;

    @SuppressWarnings("restricted") // lookup() and downcallHandle() are restricted
    private Libsodium() {
        // Libsodium always has the "lib" prefix on all platforms, so we pass Map.of() for prefixes:
        final ForeignLibrary library =
                ForeignLibrary.withName("libsodium", Map.of(), NativeLibrary.DEFAULT_LIB_EXTENSIONS);

        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        Libsodium.class.getModule().addOpens(library.packageNameOfResource(), ForeignLibrary.class.getModule());

        // Use the global Arena because we intend to load the library once and never unload it again:
        final SymbolLookup lookup = library.lookup(Libsodium.class, Arena.global());
        final Linker linker = Linker.nativeLinker();

        this.cryptoSignKeypair = lookup.find("crypto_sign_keypair")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'crypto_sign_keypair' not found"));

        this.cryptoSignDetached = lookup.find("crypto_sign_detached")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'crypto_sign_detached' not found"));

        this.cryptoSignVerifyDetached = lookup.find("crypto_sign_verify_detached")
                .map(symbol -> linker.downcallHandle(
                        symbol,
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG,
                                ValueLayout.ADDRESS),
                        Linker.Option.critical(true)))
                .orElseThrow(() -> new IllegalStateException("Function 'crypto_sign_verify_detached' not found"));
    }

    /// Libsodium crypto_sign_keypair API to generate a key pair.
    /// @param pk receives public key, must be 32 bytes long.
    /// @param sk receives secret key, must be 64 bytes long.
    /// @return 0 at all times (per the current libsodium implementation as of June 2026)
    public int cryptoSignKeypair(final MemorySegment pk, final MemorySegment sk) {
        if (pk.byteSize() != ED25519_PUBLICKEYBYTES) {
            throw new IllegalArgumentException(
                    "pk must be " + ED25519_PUBLICKEYBYTES + " bytes long, got: " + pk.byteSize());
        }
        if (sk.byteSize() != ED25519_SECRETKEYBYTES) {
            throw new IllegalArgumentException(
                    "sk must be " + ED25519_SECRETKEYBYTES + " bytes long, got: " + sk.byteSize());
        }

        try {
            return cryptoSignKeypairNoChecks(pk, sk);
        } catch (Throwable t) {
            throw new LibsodiumException(t);
        }
    }

    /// A fast, unsafe version of cryptoSignKeypair that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int cryptoSignKeypairNoChecks(final MemorySegment pk, final MemorySegment sk) throws Throwable {
        return (int) cryptoSignKeypair.invokeExact(pk, sk);
    }

    /// Libsodium crypto_sign_detached API to sign a message.
    /// @param sig receives a 64 byte signature
    /// @param siglenP optionally receives a long with the size of the signature, may be null/NULL
    /// @param m message to sign, must be >= 1 bytes long
    /// @param mlen the length of the message
    /// @param sk secret key
    /// @return 0 on success, 1..5 if arguments are invalid, or a non-zero failure code from libsodium
    public int cryptoSignDetached(
            final MemorySegment sig, MemorySegment siglenP, final MemorySegment m, final long mlen, MemorySegment sk) {
        if (sk.byteSize() != ED25519_SECRETKEYBYTES) {
            return 1;
        }
        if (mlen < 1) {
            return 2;
        }
        if (m.byteSize() < mlen) {
            return 3;
        }
        if (siglenP == null) {
            // For convenience:
            siglenP = MemorySegment.NULL;
        } else if (siglenP != MemorySegment.NULL && siglenP.byteSize() < Long.BYTES) {
            return 4;
        }
        if (sig.byteSize() < ED25519_BYTES) {
            return 5;
        }

        try {
            return cryptoSignDetachedNoChecks(sig, siglenP, m, mlen, sk);
        } catch (Throwable t) {
            throw new LibsodiumException(t);
        }
    }

    /// A fast, unsafe version of cryptoSignDetached that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int cryptoSignDetachedNoChecks(
            final MemorySegment sig,
            MemorySegment siglenP,
            final MemorySegment m,
            final long mlen,
            final MemorySegment sk)
            throws Throwable {
        return (int) cryptoSignDetached.invokeExact(sig, siglenP, m, mlen, sk);
    }

    /// Libsodium crypto_sign_verify_detached API to sign a message.
    /// @param sig a 64 byte signature
    /// @param m a message, must be >= 1 bytes long
    /// @param mlen the length of the message
    /// @param pk public key
    /// @return 0 on success, 1..4 if arguments are invalid, or a non-zero failure code from libsodium
    public int cryptoSignVerifyDetached(
            final MemorySegment sig, final MemorySegment m, final long mlen, final MemorySegment pk) {
        if (pk.byteSize() != ED25519_PUBLICKEYBYTES) {
            return 1;
        }
        if (mlen < 1) {
            return 2;
        }
        if (m.byteSize() < mlen) {
            return 3;
        }
        if (sig.byteSize() < ED25519_BYTES) {
            return 4;
        }

        try {
            return cryptoSignVerifyDetachedNoChecks(sig, m, mlen, pk);
        } catch (Throwable t) {
            throw new LibsodiumException(t);
        }
    }

    /// A fast, unsafe version of cryptoSignVerifyDetached that doesn't validate arguments.
    /// May crash in native code, but is faster if the caller knows what it's doing.
    public int cryptoSignVerifyDetachedNoChecks(
            final MemorySegment sig, final MemorySegment m, final long mlen, final MemorySegment pk) throws Throwable {
        return (int) cryptoSignVerifyDetached.invokeExact(sig, m, mlen, pk);
    }
}
