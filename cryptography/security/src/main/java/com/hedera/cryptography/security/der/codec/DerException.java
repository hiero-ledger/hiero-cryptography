// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.codec;

/// An exception thrown when an error occurs during DER values encoding.
public class DerException extends RuntimeException {
    public DerException(String message) {
        super(message);
    }

    public DerException(Throwable cause) {
        super(cause);
    }
}
