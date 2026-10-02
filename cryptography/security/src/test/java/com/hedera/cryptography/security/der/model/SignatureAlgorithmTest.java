// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.junit.jupiter.api.Test;

public class SignatureAlgorithmTest {
    @Test
    void test() throws Exception {
        final String str = "SHA384withRSA";

        DerOutputStream os = new DerOutputStream();
        new SignatureAlgorithm(str).encode(os);
        final byte[] array = os.toByteArray();

        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        AlgorithmIdentifier ai = finder.find(str);
        final byte[] bcArray = ai.getEncoded();

        TestUtils.assertArrayEquals(bcArray, array);
    }

    @Test
    void testKnownUnknown() throws Exception {
        // These shouldn't throw exceptions:
        new SignatureAlgorithm("SHA384withRSA");
        new SignatureAlgorithm("SHA384withECDSA");
        new SignatureAlgorithm("Ed25519");

        // But these are not supported:
        assertThrows(IllegalArgumentException.class, () -> new SignatureAlgorithm("someRandomName"));
    }
}
