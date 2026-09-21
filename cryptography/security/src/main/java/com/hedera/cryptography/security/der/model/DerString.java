// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.nio.charset.StandardCharsets;

/// DER string. UTF-8 by default.
public record DerString(String str, byte tag) implements DerEncoder {

    public DerString(String str) {
        this(str, DerWriter.TAG_UTF_8_STRING);
    }

    /// This type does NOT use an outer TAG_SEQUENCE, so we override the encode() method.
    @Override
    public void encode(DerOutputStream os) {
        emit(os);
    }

    @Override
    public void emit(DerOutputStream os) {
        DerWriter.put(
                os,
                tag,
                str.getBytes(
                        tag == DerWriter.TAG_PRINTABLE_STRING ? StandardCharsets.US_ASCII : StandardCharsets.UTF_8));
    }
}
