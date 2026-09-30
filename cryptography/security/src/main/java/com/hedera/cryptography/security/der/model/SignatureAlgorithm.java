// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;

/// A signature algorithm identifier.
/// Currently, we only support the SHA384withRSA algorithm.
public record SignatureAlgorithm(String signatureAlgorithm) implements DerEncoder {
    private static final String SHA_384_WITH_RSA = "SHA384withRSA";
    private static final String OID_SHA_384_WITH_RSA = "1.2.840.113549.1.1.12";

    public SignatureAlgorithm {
        if (!SHA_384_WITH_RSA.equalsIgnoreCase(signatureAlgorithm)) {
            throw new IllegalArgumentException(
                    "Only " + SHA_384_WITH_RSA + " signature algorithm is supported, got: " + signatureAlgorithm);
        }
    }

    @Override
    public void emit(DerOutputStream os) {
        new OID(OID_SHA_384_WITH_RSA).encode(os);
        // SHA384withRSA needs a NULL parameter:
        DerWriter.putNull(os);
    }
}
