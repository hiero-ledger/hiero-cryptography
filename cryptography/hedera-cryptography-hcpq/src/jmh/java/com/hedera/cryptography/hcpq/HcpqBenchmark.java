// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hcpq;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

/** Primitive microbenchmarks; these do not measure Hedera network throughput. */
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 2, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
public class HcpqBenchmark {
    private static final byte[] LEDGER_ID = {0x00};
    private static final byte[] CANONICAL_BODY = new byte[256];

    private SecureRandom random;
    private KeyPair keyPair;
    private byte[] publicKey;
    private byte[] keyId;
    private byte[] signature;

    @Setup
    public void setup() throws Exception {
        random = new SecureRandom();
        keyPair = Hcpq.generateKeyPair(random);
        publicKey = Hcpq.rawPublicKey(keyPair);
        keyId = Hcpq.keyId(publicKey);
        signature = Hcpq.signTransaction(LEDGER_ID, CANONICAL_BODY, keyPair.getPrivate(), random);
    }

    @Benchmark
    public void sign(final Blackhole blackhole) throws Exception {
        blackhole.consume(Hcpq.signTransaction(LEDGER_ID, CANONICAL_BODY, keyPair.getPrivate(), random));
    }

    @Benchmark
    public void verify(final Blackhole blackhole) {
        blackhole.consume(Hcpq.verifyTransaction(LEDGER_ID, CANONICAL_BODY, publicKey, keyId, signature));
    }
}
