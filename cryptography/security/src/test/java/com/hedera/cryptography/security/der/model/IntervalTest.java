// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.junit.jupiter.api.Test;

public class IntervalTest {
    @Test
    void test() throws Exception {
        Instant from = Instant.parse("2007-12-03T10:15:30.00Z");
        Instant to = Instant.parse("2107-02-25T05:45:11.00Z");

        Interval interval = new Interval(from, to);

        DerOutputStream os = new DerOutputStream();
        interval.encode(os);
        final byte[] array = os.toByteArray();

        // TAG_SEQUENCE 0x30 (48), 32 bytes length. Each item:
        //    from: TAG_UTC_TIME 0x17 (23), 13 bytes length, the encoding
        //    to: TAG_GENERALIZED_TIME 0x18 (24), 15 bytes length, the encoding
        TestUtils.assertArrayEquals(
                new byte[] {
                    48, 32, 23, 13, 48, 55, 49, 50, 48, 51, 49, 48, 49, 53, 51, 48, 90, 24, 15, 50, 49, 48, 55, 48, 50,
                    50, 53, 48, 53, 52, 53, 49, 49, 90
                },
                array);

        // Compare our output with Bouncy Castle:
        Validity validity = new Validity(new Time(Date.from(from)), new Time(Date.from(to)));
        final byte[] bcArray = validity.getEncoded();

        TestUtils.assertArrayEquals(bcArray, array);
    }
}
