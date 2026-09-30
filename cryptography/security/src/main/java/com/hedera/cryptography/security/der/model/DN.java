// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import java.util.List;

/// Distinguished name, which is an ordered list of RDN objects.
public record DN(List<RDN> rdnList) implements DerEncoder {

    // FUTURE WORK: we may want to implement a parser for human-readable one-liner DN names, like:
    //     "CN=example.com, O=My Company, L=Singapore, C=SG"
    // in the future, if needed.

    @Override
    public void emit(DerOutputStream os) {
        rdnList.forEach(rdn -> rdn.encode(os));
    }
}
