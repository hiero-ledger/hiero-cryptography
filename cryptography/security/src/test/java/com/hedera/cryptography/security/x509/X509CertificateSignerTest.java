// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.hedera.cryptography.security.der.codec.DerWriter;
import com.hedera.cryptography.security.der.model.AVA;
import com.hedera.cryptography.security.der.model.DN;
import com.hedera.cryptography.security.der.model.DerString;
import com.hedera.cryptography.security.der.model.Interval;
import com.hedera.cryptography.security.der.model.OID;
import com.hedera.cryptography.security.der.model.RDN;
import com.hedera.cryptography.security.der.model.SignatureAlgorithm;
import com.hedera.cryptography.security.der.model.X509CertificateInfo;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;

public class X509CertificateSignerTest {
    private static final String PRNG_TYPE = "SHA1PRNG";
    private static final String PRNG_PROVIDER = "SUN";
    private static final String KEY_TYPE = "RSA";
    private static final int KEY_SIZE_BITS = 3072;
    private static final int SERIAL_NUMBER = 5;
    private static final String ALGORITHM = "SHA384withRSA";

    @Test
    void test() throws Throwable {
        final DN subject = new DN(List.of(
                new RDN(List.of(new AVA(new OID("2.5.4.3"), new DerString("example.com")))),
                new RDN(List.of(new AVA(new OID("2.5.4.10"), new DerString("My Company")))),
                new RDN(List.of(new AVA(new OID("2.5.4.7"), new DerString("Singapore")))),
                new RDN(List.of(new AVA(new OID("2.5.4.6"), new DerString("SG", DerWriter.TAG_PRINTABLE_STRING))))));

        final DN issuer = new DN(List.of(
                new RDN(List.of(new AVA(new OID("2.5.4.3"), new DerString("signer.com")))),
                new RDN(List.of(new AVA(new OID("2.5.4.10"), new DerString("The Signer")))),
                new RDN(List.of(new AVA(new OID("2.5.4.7"), new DerString("Singapore")))),
                new RDN(List.of(new AVA(new OID("2.5.4.6"), new DerString("SG", DerWriter.TAG_PRINTABLE_STRING))))));

        Instant from = Instant.parse("2007-12-03T10:15:30.00Z");
        Instant to = Instant.parse("2107-02-25T05:45:11.00Z");

        final SecureRandom secureRandom = SecureRandom.getInstance(PRNG_TYPE, PRNG_PROVIDER);
        final KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(KEY_TYPE);
        rsaKeyGen.initialize(KEY_SIZE_BITS, secureRandom);
        final KeyPair subjectKeyPair = rsaKeyGen.generateKeyPair();

        // For this test we will use this same key pair for the cert (the public key),
        // and for signing (the private key).

        final X509CertificateInfo info = new X509CertificateInfo(
                subject,
                subjectKeyPair.getPublic(),
                issuer,
                BigInteger.valueOf(SERIAL_NUMBER),
                new Interval(from, to),
                new SignatureAlgorithm(ALGORITHM));

        final X509Certificate cert = X509CertificateSigner.sign(info, subjectKeyPair.getPrivate());

        // Check the certificate:

        cert.checkValidity(new Date(from.plusSeconds(48 * 60 * 60).toEpochMilli()));
        assertThrows(
                CertificateNotYetValidException.class,
                () -> cert.checkValidity(
                        new Date(from.minusSeconds(48 * 60 * 60).toEpochMilli())));
        cert.checkValidity(new Date(to.minusSeconds(48 * 60 * 60).toEpochMilli()));
        assertThrows(
                CertificateExpiredException.class,
                () -> cert.checkValidity(new Date(to.plusSeconds(48 * 60 * 60).toEpochMilli())));

        assertEquals(
                "C=SG, L=Singapore, O=The Signer, CN=signer.com",
                cert.getIssuerX500Principal().toString());
        assertEquals(
                "C=SG, L=Singapore, O=My Company, CN=example.com",
                cert.getSubjectX500Principal().toString());

        assertEquals(subjectKeyPair.getPublic(), cert.getPublicKey());

        assertEquals(SERIAL_NUMBER, cert.getSerialNumber().intValueExact());

        assertEquals(ALGORITHM, cert.getSigAlgName());

        // Finally, verify the signature (remember we use the same subjectKeyPair for the subject and the signer):
        cert.verify(subjectKeyPair.getPublic());
    }
}
