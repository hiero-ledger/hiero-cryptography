// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.codec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/// Utility class to write DER-encoded values.
public class DerWriter {
    public static final byte TAG_INTEGER = 0x02;
    public static final byte TAG_BIT_STRING = 0x03;
    public static final byte TAG_NULL = 0x05;
    public static final byte TAG_OBJECT_ID = 0x06;
    public static final byte TAG_UTF_8_STRING = 0x0C;
    public static final byte TAG_PRINTABLE_STRING = 0x13;
    public static final byte TAG_UTC_TIME = 0x17;
    public static final byte TAG_GENERALIZED_TIME = 0x18;
    public static final byte TAG_SEQUENCE = 0x30;
    public static final byte TAG_SET = 0x31;
    public static final byte TAG_TBS_CERTIFICATE = (byte) 0xa0;

    /// Write a (sometimes) length-prefixed varint number.
    public static void putLength(DerOutputStream os, int len) {
        if (len < 128) {
            os.write((byte) len);

        } else if (len < (1 << 8)) {
            os.write((byte) 0x081);
            os.write((byte) len);

        } else if (len < (1 << 16)) {
            os.write((byte) 0x082);
            os.write((byte) (len >> 8));
            os.write((byte) len);

        } else if (len < (1 << 24)) {
            os.write((byte) 0x083);
            os.write((byte) (len >> 16));
            os.write((byte) (len >> 8));
            os.write((byte) len);

        } else {
            os.write((byte) 0x084);
            os.write((byte) (len >> 24));
            os.write((byte) (len >> 16));
            os.write((byte) (len >> 8));
            os.write((byte) len);
        }
    }

    /// Write a BigInteger.
    public static void putInteger(DerOutputStream os, BigInteger i) {
        os.write(TAG_INTEGER);
        byte[] buf = i.toByteArray();
        putLength(os, buf.length);
        os.write(buf, 0, buf.length);
    }

    /// Write a single byte TAG_INTEGER.
    public static void putInteger(DerOutputStream os, byte i) {
        os.write(TAG_INTEGER);
        putLength(os, 1);
        os.write(i & 0xFF);
    }

    /// Write a byte array.
    public static void put(DerOutputStream os, final byte tag, byte[] buf) {
        put(os, tag, buf, 0, buf.length);
    }

    /// Write a byte array slice.
    public static void put(DerOutputStream os, final byte tag, byte[] buf, int offset, int length) {
        os.write(tag);
        putLength(os, length);
        os.write(buf, offset, length);
    }

    /// Write a DER NULL value.
    public static void putNull(DerOutputStream os) {
        os.write(TAG_NULL);
        putLength(os, 0);
    }

    /// Write an instant.
    public static void putInstant(DerOutputStream os, byte tag, Instant instant) {
        String pattern =
                switch (tag) {
                    case TAG_UTC_TIME -> "yyMMddHHmmss'Z'";
                    case TAG_GENERALIZED_TIME -> "yyyyMMddHHmmss'Z'";
                    default -> throw new IllegalArgumentException("Unsupported time tag: " + tag);
                };

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern).withZone(ZoneOffset.UTC);

        final byte[] bytes = formatter.format(instant).getBytes(StandardCharsets.ISO_8859_1);

        put(os, tag, bytes);
    }

    /// Write a DER bit string.
    public static void putBitString(DerOutputStream os, byte[] bits) {
        os.write(TAG_BIT_STRING);
        putLength(os, bits.length + 1);
        // The final octet has no padding because we use entire bytes, so put zero:
        os.write(0);
        os.writeBytes(bits);
    }
}
