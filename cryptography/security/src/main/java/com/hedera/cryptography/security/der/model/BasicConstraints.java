// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;

/// A BasicConstraints certificate extension.
public record BasicConstraints(boolean cA, BigInteger pathLenConstraint) implements DerEncoder {
    /// A DER OID for BasicConstraints.
    public static final OID OID = new OID("2.5.29.19");

    /// A factory method for a certificate Extension object that wraps this BasicConstraints.
    public Extension newExtension(boolean critical) {
        return new Extension(OID, critical, this);
    }

    @Override
    public void emit(DerOutputStream os) {
        // Per DER encoding, a FALSE boolean can be omitted
        if (cA) {
            DerWriter.putBoolean(os, true);

            // Only encode this if cA is true
            if (pathLenConstraint != null) {
                DerWriter.putInteger(os, pathLenConstraint);
            }
        }
    }
}
