// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

/// An exception thrown when a call to a native function fails in regular,
/// not-NoChecks versions of methods.
///
/// It's an unchecked wrapper for a checked Throwable because regular client code
/// isn't supposed to encounter this exception. This is because we build and package
/// our own native library, so it's available and known to work. Also,
/// regular not-NoChecks methods validate input arguments for sanity, and when invalid,
/// the IllegalArgumentException is thrown which the client code can process.
/// Other than that, the client code should either never experience a native Throwable,
/// or it uses the NoChecks versions of methods, and then it knows what it's doing.
public class Libsecp256k1Exception extends RuntimeException {
    /// Wraps the Throwable cause.
    public Libsecp256k1Exception(Throwable cause) {
        super(cause);
    }
}
