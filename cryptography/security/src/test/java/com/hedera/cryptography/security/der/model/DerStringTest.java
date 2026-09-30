// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class DerStringTest {
    @ParameterizedTest
    @ValueSource(strings = {"example.com", "My Company", "Singapore", "SG"})
    void test(String str) throws Exception {
        DerOutputStream os = new DerOutputStream();
        new DerString(str).encode(os);

        final DERUTF8String bcString = new DERUTF8String(str);

        TestUtils.assertArrayEquals(bcString.getEncoded(), os.toByteArray());
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "My Company", "Singapore", "SG"})
    void testPrintableString(String str) throws Exception {
        DerOutputStream os = new DerOutputStream();
        new DerString(str, DerWriter.TAG_PRINTABLE_STRING).encode(os);

        final DERPrintableString bcString = new DERPrintableString(str);

        TestUtils.assertArrayEquals(bcString.getEncoded(), os.toByteArray());
    }
}
