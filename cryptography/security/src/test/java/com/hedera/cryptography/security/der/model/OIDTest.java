// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

public class OIDTest {
    @Test
    void test() throws Exception {
        final String str = "1.2.840.113549.1.1.12";

        DerOutputStream baos = new DerOutputStream();
        new OID(str).encode(baos);
        final byte[] array = baos.toByteArray();

        // tag 6 == OID, len 9 bytes, and then the encoded OID value:
        TestUtils.assertArrayEquals(
                new byte[] {0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0C},
                array);

        // Try the same using Bouncy Castle:
        final ASN1ObjectIdentifier bcOID = new ASN1ObjectIdentifier(str);
        final byte[] bcArray = bcOID.getEncoded();

        // Ensure we emit the same encoded bytes as BC:
        TestUtils.assertArrayEquals(bcArray, array);
    }
}
