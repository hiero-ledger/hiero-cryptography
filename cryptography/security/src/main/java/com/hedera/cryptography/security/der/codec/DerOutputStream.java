// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.codec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/// An output stream to support DER encoding.
///
/// It's based on the ByteArrayOutputStream to avoid reinventing the wheel,
/// as well as avoid IOException coming from the basic OutputStream.
///
/// The main purpose of this class is to facilitate length measuring for inner
/// DER objects and avoid allocating a lot of garbage OutputStream and byte[]
/// objects in the Java heap along the way.
///
/// This class is not thread-safe as it maintains a mutable state.
public class DerOutputStream extends ByteArrayOutputStream {

    /// It's unlikely to encounter a nested objects depth greater than 16.
    /// But it will grow dynamically if needed.
    private static final int INITIAL_LENGTHS_STACK_SIZE = 16;

    // Many DER-encoded objects box their content inside a TAG_SEQUENCE or a similar other tag.
    // This requires knowing the size of the emitted data upfront.
    // Most existing DER encoders (e.g. JDK's sun.security) implement this via:
    //    encode(os) {
    //       OutputStream tmp = new;
    //       emitDataTo(tmp);
    //       byte[] arr = tmp.toByteArray();
    //       put(os, tag);
    //       put(os, arr.length);
    //       put(os, arr);
    //    }
    // This creates multiple new OutputStream and byte[] objects which is inefficient for GC.
    //
    // We implement a length measuring mode that allows the code to measure its output size before
    // actually emitting the data. Note that this does require two passes over the data, so
    // this is slightly more CPU-intensive. However, this avoids creating very many temporary
    // OutputStream and byte[] objects, thus reducing the RAM usage and Java GC load.

    /// A stack of lengths being measured to support nested calls for sub-objects.
    private int[] lengths;

    /// The current index in the lengths array, or -1 if we're actually writing the data.
    private int lengthsIndex = -1;

    /// Returns true if the output stream is measuring the length currently
    /// rather than actually writing the data.
    public boolean isMeasuringLength() {
        return lengthsIndex > -1;
    }

    /// Start measuring length and return the current index of measuring. The top level index is zero.
    /// This machinery supports nested measuring where a complex object consisting of multiple inner
    /// objects can recursively measure its size and produce a total size in the end.
    /// While in the length measuring mode, this output stream doesn't write bytes to the underlying
    /// ByteArrayOutputStream, but instead just increments the lengths counter accordingly.
    public int startMeasuringLength() {
        lengthsIndex++;
        if (lengths == null) {
            lengths = new int[INITIAL_LENGTHS_STACK_SIZE];
        } else if (lengths.length <= lengthsIndex) {
            lengths = Arrays.copyOf(lengths, lengths.length * 2);
        }
        // Reset the length explicitly to support measuring sibling objects in a row:
        lengths[lengthsIndex] = 0;
        return lengthsIndex;
    }

    /// A helper method that just adds to the length currently being measured.
    /// It's useful to avoid extra unnecessary calls to DerEncoder.emit() when the previous
    /// call has already computed the required length. See DerEncoder.encode() for more details.
    public void addLength(int length) {
        lengths[lengthsIndex] += length;
    }

    /// Finish measuring the length at the given index and return the measured length.
    public int finishMeasuringLength(int index) {
        if (index != lengthsIndex) {
            // Either startMeasuringLength() hasn't been called, or a call to finishMeasuringLength() has been
            // missed/skipped.
            throw new IllegalStateException(
                    "Finishing length measuring " + index + " while " + lengthsIndex + " is running");
        }
        return lengths[lengthsIndex--];
    }

    // Below go the overridden write*() methods that either delegate to the underlying
    // ByteArrayOutputStream to perform actual writing, or only increment the lengths
    // counters when in the length measuring mode.

    @Override
    public void write(int b) {
        if (isMeasuringLength()) {
            lengths[lengthsIndex]++;
        } else {
            super.write(b);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) {
        if (isMeasuringLength()) {
            lengths[lengthsIndex] += len;
        } else {
            super.write(b, off, len);
        }
    }

    @Override
    public void writeBytes(byte[] b) {
        if (isMeasuringLength()) {
            lengths[lengthsIndex] += b.length;
        } else {
            super.writeBytes(b);
        }
    }

    @Override
    public void write(byte[] b) throws IOException {
        if (isMeasuringLength()) {
            lengths[lengthsIndex] += b.length;
        } else {
            super.write(b);
        }
    }
}
