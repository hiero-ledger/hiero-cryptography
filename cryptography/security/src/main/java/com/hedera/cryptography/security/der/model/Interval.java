// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.time.Instant;

/// A dates interval, e.g. to describe a certificate validity interval.
public record Interval(Instant from, Instant to) implements DerEncoder {
    /// Jan 01 00:00 2050 GMT .
    private static final Instant YR_2050 = Instant.ofEpochMilli(2524608000000L);

    @Override
    public void emit(DerOutputStream os) {
        if (from.isBefore(YR_2050)) {
            DerWriter.putInstant(os, DerWriter.TAG_UTC_TIME, from);
        } else {
            DerWriter.putInstant(os, DerWriter.TAG_GENERALIZED_TIME, from);
        }

        if (to.isBefore(YR_2050)) {
            DerWriter.putInstant(os, DerWriter.TAG_UTC_TIME, to);
        } else {
            DerWriter.putInstant(os, DerWriter.TAG_GENERALIZED_TIME, to);
        }
    }
}
