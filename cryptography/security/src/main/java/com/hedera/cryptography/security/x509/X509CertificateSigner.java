// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.x509;

import com.hedera.cryptography.security.der.codec.DerEncoder;
import com.hedera.cryptography.security.der.codec.DerException;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import com.hedera.cryptography.security.der.model.SignatureAlgorithm;
import com.hedera.cryptography.security.der.model.X509CertificateInfo;
import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/// A certificate signer.
public final class X509CertificateSigner {
    private X509CertificateSigner() {}

    /// A helper model for a signed certificate to produce a proper DER encoding inside a TAG_SEQUENCE.
    private record SignedX509Certificate(byte[] rawCert, SignatureAlgorithm signatureAlgorithm, byte[] signature)
            implements DerEncoder {
        @Override
        public void emit(DerOutputStream os) {
            os.writeBytes(rawCert);
            signatureAlgorithm.encode(os);
            DerWriter.putBitString(os, signature);
        }
    }

    /// Sign a given X509CertificateInfo with a given PrivateKey and return an X509Certificate instance.
    public static X509Certificate sign(X509CertificateInfo info, PrivateKey privateKey) {
        // First, encode the raw cert and sign it:
        final DerOutputStream os = new DerOutputStream();
        info.encode(os);
        final byte[] rawCert = os.toByteArray();
        final byte[] signature;
        try {
            final Signature signer =
                    Signature.getInstance(info.signatureAlgorithm().signatureAlgorithm());
            signer.initSign(privateKey);
            signer.update(rawCert, 0, rawCert.length);
            signature = signer.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DerException(e);
        }

        // Then encode the entire signed certificate:
        os.reset();
        new SignedX509Certificate(rawCert, info.signatureAlgorithm(), signature).encode(os);

        // Finally, simply use JDK to parse the encoded cert:
        final ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (CertificateException e) {
            throw new DerException(e);
        }
    }
}
