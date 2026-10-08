// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.x509;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.security.der.codec.DerWriter;
import com.hedera.cryptography.security.der.model.AVA;
import com.hedera.cryptography.security.der.model.BasicConstraints;
import com.hedera.cryptography.security.der.model.DN;
import com.hedera.cryptography.security.der.model.DerString;
import com.hedera.cryptography.security.der.model.Extensions;
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

    private static final DN SUBJECT = new DN(List.of(
            new RDN(List.of(new AVA(new OID("2.5.4.3"), new DerString("example.com")))),
            new RDN(List.of(new AVA(new OID("2.5.4.10"), new DerString("My Company")))),
            new RDN(List.of(new AVA(new OID("2.5.4.7"), new DerString("Singapore")))),
            new RDN(List.of(new AVA(new OID("2.5.4.6"), new DerString("SG", DerWriter.TAG_PRINTABLE_STRING))))));

    private static final DN ISSUER = new DN(List.of(
            new RDN(List.of(new AVA(new OID("2.5.4.3"), new DerString("signer.com")))),
            new RDN(List.of(new AVA(new OID("2.5.4.10"), new DerString("The Signer")))),
            new RDN(List.of(new AVA(new OID("2.5.4.7"), new DerString("Singapore")))),
            new RDN(List.of(new AVA(new OID("2.5.4.6"), new DerString("SG", DerWriter.TAG_PRINTABLE_STRING))))));

    private static final Instant FROM = Instant.parse("2007-12-03T10:15:30.00Z");
    private static final Instant TO = Instant.parse("2107-02-25T05:45:11.00Z");

    @Test
    void test() throws Throwable {
        final SecureRandom secureRandom = SecureRandom.getInstance(PRNG_TYPE, PRNG_PROVIDER);
        final KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(KEY_TYPE);
        rsaKeyGen.initialize(KEY_SIZE_BITS, secureRandom);
        final KeyPair subjectKeyPair = rsaKeyGen.generateKeyPair();

        // For this test we will use this same key pair for the cert (the public key),
        // and for signing (the private key).

        final X509CertificateInfo info = new X509CertificateInfo(
                SUBJECT,
                subjectKeyPair.getPublic(),
                ISSUER,
                BigInteger.valueOf(SERIAL_NUMBER),
                new Interval(FROM, TO),
                new SignatureAlgorithm(ALGORITHM),
                null);

        final X509Certificate cert = X509CertificateSigner.sign(info, subjectKeyPair.getPrivate());

        // Check the certificate:
        validate(cert, subjectKeyPair);
    }

    @Test
    void testBasicConstraintsExtension() throws Throwable {
        final SecureRandom secureRandom = SecureRandom.getInstance(PRNG_TYPE, PRNG_PROVIDER);
        final KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(KEY_TYPE);
        rsaKeyGen.initialize(KEY_SIZE_BITS, secureRandom);
        final KeyPair subjectKeyPair = rsaKeyGen.generateKeyPair();

        // For this test we will use this same key pair for the cert (the public key),
        // and for signing (the private key).

        final X509CertificateInfo info = new X509CertificateInfo(
                SUBJECT,
                subjectKeyPair.getPublic(),
                ISSUER,
                BigInteger.valueOf(SERIAL_NUMBER),
                new Interval(FROM, TO),
                new SignatureAlgorithm(ALGORITHM),
                new Extensions(List.of(new BasicConstraints(true, null).newExtension(true))));

        final X509Certificate cert = X509CertificateSigner.sign(info, subjectKeyPair.getPrivate());

        // First, check the certificate for all the basics, same as the regular test:
        validate(cert, subjectKeyPair);

        // Then, check the extension:
        assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
        assertEquals(1, cert.getCriticalExtensionOIDs().size());
        assertTrue(cert.getCriticalExtensionOIDs().contains(BasicConstraints.OID.oid()));
        assertArrayEquals(new byte[] {4, 5, 48, 3, 1, 1, -1}, cert.getExtensionValue(BasicConstraints.OID.oid()));
    }

    private void validate(final X509Certificate cert, KeyPair subjectKeyPair) throws Throwable {
        cert.checkValidity(new Date(FROM.plusSeconds(48 * 60 * 60).toEpochMilli()));
        assertThrows(
                CertificateNotYetValidException.class,
                () -> cert.checkValidity(
                        new Date(FROM.minusSeconds(48 * 60 * 60).toEpochMilli())));
        cert.checkValidity(new Date(TO.minusSeconds(48 * 60 * 60).toEpochMilli()));
        assertThrows(
                CertificateExpiredException.class,
                () -> cert.checkValidity(new Date(TO.plusSeconds(48 * 60 * 60).toEpochMilli())));

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
