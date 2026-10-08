// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;

/// A certificate extension wrapper as per the DER encoding standard.
/// Concrete extension classes, such as the BasicConstraints, implement a factory-method
/// `Extension newExtension(boolean critical)` that creates instances of this wrapper.
public record Extension(OID oid, boolean critical, DerEncoder extensionObject) implements DerEncoder {
    @Override
    public void emit(DerOutputStream os) {
        oid.encode(os);
        if (critical) {
            DerWriter.putBoolean(os, true);
        }
        DerEncoder.wrap(DerWriter.TAG_OCTET_STRING, extensionObject).encode(os);
    }
}
