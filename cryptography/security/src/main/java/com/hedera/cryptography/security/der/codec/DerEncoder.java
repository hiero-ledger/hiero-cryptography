// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.codec;

/// A DER encoder to encode complex DER objects.
/// Complex objects are often boxed inside TAG_SEQUENCE or a similar tag.
/// The encode() method would encode the entire object, together with the outer boxing if needed.
/// The emit() method would only encode the body that needs to be boxed to obtain the complete
/// encoding. This is useful for determining the length of the inner body.
public interface DerEncoder {
    /// Encode the model boxed inside a TAG_SEQUENCE.
    /// A model can override this method to either replace the TAG_SEQUENCE with a different
    /// boxing tag, or skip the boxing altogether and delegate to emit() directly.
    default void encode(DerOutputStream os) {
        encode(os, DerWriter.TAG_SEQUENCE);
    }

    /// Encode the model boxed inside a custom tag.
    default void encode(DerOutputStream os, byte tag) {
        int index = os.startMeasuringLength();
        emit(os);
        int length = os.finishMeasuringLength(index);

        os.write(tag);
        DerWriter.putLength(os, length);
        if (os.isMeasuringLength()) {
            // Avoid calling emit() again:
            os.addLength(length);
        } else {
            emit(os);
        }
    }

    /// Emit the model content alone w/o the outer TAG_SEQUENCE.
    void emit(DerOutputStream os);
}
