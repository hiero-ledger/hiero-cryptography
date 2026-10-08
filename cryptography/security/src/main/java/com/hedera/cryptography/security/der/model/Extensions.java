// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import java.util.List;

/// A list of x509 certificate extensions.
public record Extensions(List<Extension> extensions) implements DerEncoder {
    @Override
    public void emit(DerOutputStream os) {
        extensions.forEach(e -> e.encode(os));
    }
}
