// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;

/// A signature algorithm identifier.
public record SignatureAlgorithm(String signatureAlgorithm, OID oid, boolean needsNullParam) implements DerEncoder {
    /// A helper constructor that assigns correct values based on the canonical algorithm name.
    public SignatureAlgorithm(String signatureAlgorithm) {
        final OID oid;
        final boolean needsNullParam;

        if ("SHA384withRSA".equalsIgnoreCase(signatureAlgorithm)) {
            oid = new OID("1.2.840.113549.1.1.12");
            needsNullParam = true;
        } else if ("SHA384withECDSA".equalsIgnoreCase(signatureAlgorithm)) {
            oid = new OID("1.2.840.10045.4.3.3");
            needsNullParam = false;
        } else if ("Ed25519".equalsIgnoreCase(signatureAlgorithm) || "EdDSA".equalsIgnoreCase(signatureAlgorithm)) {
            // Bouncy Castle uses Ed25519, while JDK refers to this as EdDSA.
            oid = new OID("1.3.101.112");
            needsNullParam = false;
        } else {
            throw new IllegalArgumentException("Unknown signature algorithm: " + signatureAlgorithm);
        }

        this(signatureAlgorithm, oid, needsNullParam);
    }

    @Override
    public void emit(DerOutputStream os) {
        oid.encode(os);
        if (needsNullParam) {
            DerWriter.putNull(os);
        }
    }
}
