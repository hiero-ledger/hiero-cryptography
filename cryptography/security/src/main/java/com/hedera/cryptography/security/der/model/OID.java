// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerException;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;

/// An Object Identifier as used in DER-encoded data.
public record OID(String oid) implements DerEncoder {
    private static final int MAXIMUM_OID_SIZE = 4096;

    /// This type does NOT use an outer TAG_SEQUENCE, so we override the encode() method.
    @Override
    public void encode(DerOutputStream os) {
        emit(os);
    }

    // The emit() code below is very loosely based on the JDK implementation in sun.security,
    // but it's simplified greatly and may be a little less efficient.
    // However, the pack7Oid() below that encodes varint values is a brand-new
    // implementation altogether.

    @Override
    public void emit(DerOutputStream os) {
        int ch = '.';
        int start = 0;
        int end;

        int pos = 0;
        byte[] tmp = new byte[oid.length()];
        int first = 0;
        int count = 0;
        String comp;
        do {
            end = oid.indexOf(ch, start);
            if (end == -1) {
                comp = oid.substring(start);
            } else {
                comp = oid.substring(start, end);
            }

            BigInteger bignum = new BigInteger(comp);
            if (count == 0) {
                checkFirstComponent(bignum.intValueExact());
                first = bignum.intValue();
            } else {
                if (count == 1) {
                    checkSecondComponent(first, bignum);
                    bignum = bignum.add(BigInteger.valueOf(40L * first));
                } else {
                    checkOtherComponent(count, bignum);
                }
                pos += pack7Oid(bignum, tmp, pos);
            }

            start = end + 1;
            count++;

            checkOidSize(pos);
        } while (end != -1);

        checkCount(count);

        DerWriter.put(os, DerWriter.TAG_OBJECT_ID, tmp, 0, pos);
    }

    // Masks and shifts, in BigEndian {MSB mask, MSB shift left, LSB mask, LSB shift right}.
    // We only need %7 combinations, and then the pattern repeats.
    private static final int[][] MASK = {
        // Septet 0
        {0b00000000, 0, 0b01111111, 0},
        // Septet 1 , etc.
        {0b00111111, 1, 0b10000000, 7},
        {0b00011111, 2, 0b11000000, 6},
        {0b00001111, 3, 0b11100000, 5},
        {0b00000111, 4, 0b11110000, 4},
        {0b00000011, 5, 0b11111000, 3},
        {0b00000001, 6, 0b11111100, 2},
        {0b00000000, 7, 0b11111110, 1},
    };

    // BigEndian VarInt encoding (unlike the Protobuf varint that uses LittleEndian.)
    private static int pack7Oid(BigInteger input, byte[] out, int offset) {
        final int origOffset = offset;

        // This is a BigEndian array already:
        byte[] b = input.toByteArray();
        if (b.length > Integer.MAX_VALUE / 8) {
            throw new DerException("BigInteger is too large: " + input);
        }

        boolean skipLeadingZeros = true;
        // sp is a septet pointer.
        // 0 corresponds to 7 LSB of b[b.length - 1].
        // 1 corresponds to the 1 MSB of b[b.length - 1] and 6 LSB of b[b.length - 2].
        // And so forth.
        for (int sp = (b.length * 8) / 7; sp >= 0; sp--) {
            int[] mask = MASK[sp % 7];
            int lsbIndex = b.length - (sp * 7) / 8 - 1;

            int value = (b[lsbIndex] & mask[2]) >>> mask[3];

            int msbIndex = lsbIndex - 1;
            if (msbIndex >= 0) {
                value |= (b[msbIndex] & mask[0]) << mask[1];
            }

            if (skipLeadingZeros) {
                if (value == 0) {
                    continue;
                } else {
                    skipLeadingZeros = false;
                }
            }

            if (sp > 0) {
                value |= 0x80;
            }

            out[offset++] = (byte) (value & 0xFF);
        }

        return offset - origOffset;
    }

    private static void checkFirstComponent(int first) {
        if (first < 0 || first > 2) {
            throw new DerException("First oid component is invalid: " + first);
        }
    }

    private static void checkSecondComponent(int first, BigInteger second) {
        if (second.signum() == -1 || first != 2 && second.compareTo(BigInteger.valueOf(39)) > 0) {
            throw new DerException("Second oid component is invalid: " + second + " for first: " + first);
        }
    }

    private static void checkOtherComponent(int i, BigInteger num) {
        if (num.signum() == -1) {
            throw new DerException("oid component " + (i + 1) + " must be non-negative, got " + num);
        }
    }

    private static void checkOidSize(int oidLength) {
        if (oidLength < 0) {
            throw new DerException("Encoded length was negative: " + oidLength);
        }

        if (oidLength > MAXIMUM_OID_SIZE) {
            throw new DerException("Encoded length " + oidLength + " exceeds " + MAXIMUM_OID_SIZE);
        }
    }

    private static void checkCount(int count) {
        if (count < 2) {
            throw new DerException("Must be at least two oid components");
        }
    }
}
