// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;
import java.security.PublicKey;

/// Raw information about a certificate. This is the certificate data that will eventually
/// need to be signed.
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

    @Override
    public void emit(DerOutputStream os) {
        // Skip the version because we only support V1 (== 0).
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
