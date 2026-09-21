// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.util.Comparator;
import java.util.List;

/// A Relative Distinguished Name, that is a set of AVAs which get sorted in lexicographical
/// order of their DER-encoded representations when encoding the RDN content.
public record RDN(List<AVA> avaList) implements DerEncoder {
    @Override
    public void encode(DerOutputStream os) {
        encode(os, DerWriter.TAG_SET);
    }

    @Override
    public void emit(DerOutputStream os) {
        // Must be a sequential stream because we write to `os`:
        avaList.stream()
                .map(de -> {
                    DerOutputStream tmp = new DerOutputStream();
                    de.encode(tmp);
                    return tmp.toByteArray();
                })
                .sorted(ByteArrayLexOrder.INSTANCE)
                .forEach(os::writeBytes);
    }

    private static class ByteArrayLexOrder implements Comparator<byte[]> {
        private static final ByteArrayLexOrder INSTANCE = new ByteArrayLexOrder();

        public final int compare(byte[] bytes1, byte[] bytes2) {
            int diff;
            for (int i = 0; i < bytes1.length && i < bytes2.length; i++) {
                diff = (bytes1[i] & 0xFF) - (bytes2[i] & 0xFF);
                if (diff != 0) {
                    return diff;
                }
            }
            return bytes1.length - bytes2.length;
        }
    }
}
