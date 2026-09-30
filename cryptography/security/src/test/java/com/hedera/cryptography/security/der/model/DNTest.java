// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

public class DNTest {
    @Test
    void test() throws Exception {
        final DN dn = new DN(List.of(
                new RDN(List.of(new AVA(new OID("2.5.4.3"), new DerString("example.com")))),
                new RDN(List.of(new AVA(new OID("2.5.4.10"), new DerString("My Company")))),
                new RDN(List.of(new AVA(new OID("2.5.4.7"), new DerString("Singapore")))),
                new RDN(List.of(new AVA(new OID("2.5.4.6"), new DerString("SG", DerWriter.TAG_PRINTABLE_STRING))))));

        DerOutputStream os = new DerOutputStream();
        dn.encode(os);
        final byte[] array = os.toByteArray();

        // The encoded representation is rather long and complex. So we simply compare it
        // with what Bouncy Castle produces for the same name:

        X500Name x500Name = new X500Name("CN=example.com, O=My Company, L=Singapore, C=SG");
        final byte[] bcArray = x500Name.getEncoded();

        TestUtils.assertArrayEquals(bcArray, array);
    }
}
