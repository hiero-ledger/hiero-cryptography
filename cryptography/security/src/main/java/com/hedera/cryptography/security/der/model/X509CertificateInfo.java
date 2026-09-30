// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;
import java.security.PublicKey;

/// Raw information about a v3 certificate. This is the certificate data that will eventually
/// need to be signed.
/// Per modern TLS standards, the minimum supported certificate version is v3.
public record X509CertificateInfo(
        // Subject
        DN distinguishedName,
        PublicKey publicKey,

        // Issuer/CA
        DN caDistinguishedName,

        // Certificate and signing details
        BigInteger serialNumber,
        Interval validityInterval,
        SignatureAlgorithm signatureAlgorithm)
        implements DerEncoder {

    /// Certificate version v3. Values are zero-based, so v3 is 2.
    private static final byte VERSION_3 = 2;

    /// A helper model to wrap the version into a TAG_TBS_CERTIFICATE per DER spec.
    private record Version(byte version) implements DerEncoder {
        @Override
        public void encode(DerOutputStream os) {
            encode(os, DerWriter.TAG_TBS_CERTIFICATE);
        }

        @Override
        public void emit(DerOutputStream os) {
            DerWriter.putInteger(os, version);
        }
    }

    /// A helper constant to avoid creating dummy Version objects on each emit() call.
    private static final Version VERSION_3_MODEL = new Version(VERSION_3);

    @Override
    public void emit(DerOutputStream os) {
        VERSION_3_MODEL.encode(os);
        DerWriter.putInteger(os, serialNumber);
        signatureAlgorithm.encode(os);
        caDistinguishedName.encode(os);
        validityInterval.encode(os);
        distinguishedName.encode(os);
        os.writeBytes(publicKey().getEncoded());
        // Skip issuerUniqueId as not supported.
        // Skip subjectUniqueId as not supported.
        // Skip extensions as not supported.
    }
}
