// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;

/// Attribute-Value-Assertion. We only support string values for now.
public record AVA(OID oid, DerString value) implements DerEncoder {
    @Override
    public void emit(DerOutputStream os) {
        oid.encode(os);
        value.encode(os);
    }
}
