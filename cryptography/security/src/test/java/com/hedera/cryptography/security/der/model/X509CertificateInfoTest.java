// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security.der.model;

import com.hedera.cryptography.security.TestUtils;
import com.hedera.cryptography.security.der.codec.DerOutputStream;
import com.hedera.cryptography.security.der.codec.DerWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.junit.jupiter.api.Test;

public class X509CertificateInfoTest {
    private static final String PRNG_TYPE = "SHA1PRNG";
    private static final String PRNG_PROVIDER = "SUN";
    private static final String KEY_TYPE = "RSA";
    private static final int KEY_SIZE_BITS = 3072;
    private static final int SERIAL_NUMBER = 5;
    private static final String ALGORITHM = "SHA384withRSA";

    @Test
    void test() throws Exception {
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

        DerOutputStream os = new DerOutputStream();
        final X509CertificateInfo cert = new X509CertificateInfo(
                subject,
                subjectKeyPair.getPublic(),
                issuer,
                BigInteger.valueOf(SERIAL_NUMBER),
                new Interval(from, to),
                new SignatureAlgorithm(ALGORITHM));
        cert.encode(os);
        byte[] array = os.toByteArray();

        // Now test if we produce the same data as BouncyCastle:

        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();

        X500Name bcSubject = new X500Name("CN=example.com, O=My Company, L=Singapore, C=SG");
        X500Name bcIssuer = new X500Name("CN=signer.com, O=The Signer, L=Singapore, C=SG");

        TBSCertificate tbsCertificate = new TBSCertificate(
                // Specify 2 which is the certificate v3. This is what we support.
                new ASN1Integer(2),
                new ASN1Integer(SERIAL_NUMBER),
                finder.find(ALGORITHM),
                bcIssuer,
                new Validity(new Time(Date.from(from)), new Time(Date.from(to))),
                bcSubject,
                SubjectPublicKeyInfo.getInstance(subjectKeyPair.getPublic().getEncoded()),
                null,
                null,
                null);

        byte[] bcArray = tbsCertificate.getEncoded();

        TestUtils.assertArrayEquals(bcArray, array);
    }
}
