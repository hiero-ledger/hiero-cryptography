// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;

/**
 * A sync committee of Ethereum. Public keys use the compressed encoding of the beacon chain.
 *
 * @param aggregatePublicKey the aggregate public key of the committee, as the beacon state records it
 * @param publicKeys the public keys of the members, in committee order
 */
record EthereumSyncCommittee(byte[] aggregatePublicKey, List<byte[]> publicKeys) {

    private static final String MAINNET_SAMPLE_RESOURCE = "mainnet-sync-committee-period-1895.properties";
    private static final int COMMITTEE_SIZE = 512;
    private static final String HEX_PREFIX = "0x";

    /**
     * The aggregate signature of the members that signed, on a signing root. The signature uses the compressed
     * encoding of the beacon chain.
     *
     * @param signingRoot the signed message
     * @param syncCommitteeBits the participation bitvector: bit {@code i % 8} of byte {@code i / 8} is set if and
     *     only if member {@code i} signed
     * @param signature the aggregate signature
     */
    record SyncAggregate(byte[] signingRoot, byte[] syncCommitteeBits, byte[] signature) {}

    /**
     * A real sync committee of Ethereum mainnet and one of its sync aggregates.
     *
     * @param committee the sync committee
     * @param aggregate the sync aggregate
     */
    record MainnetSample(EthereumSyncCommittee committee, SyncAggregate aggregate) {

        /** {@return the aggregate public key of the committee} */
        byte[] aggregatePublicKey() {
            return committee.aggregatePublicKey();
        }

        /** {@return the public keys of the members, in committee order} */
        List<byte[]> publicKeys() {
            return committee.publicKeys();
        }

        /** {@return the public keys of the members that signed the aggregate, in committee order} */
        List<byte[]> signers() {
            return committee.signers(aggregate);
        }

        /** {@return the public keys of the members that did not sign the aggregate, in committee order} */
        List<byte[]> nonSigners() {
            return committee.nonSigners(aggregate);
        }

        /** {@return the message the aggregate signs} */
        byte[] signingRoot() {
            return aggregate.signingRoot();
        }

        /** {@return the aggregate signature} */
        byte[] signature() {
            return aggregate.signature();
        }
    }

    /**
     * Loads a real sync committee of Ethereum mainnet and its sync aggregate of the block at slot 15526240, signed by
     * every member, from {@value #MAINNET_SAMPLE_RESOURCE}, whose comments say where the data comes from.
     *
     * @return the committee and the aggregate
     */
    static MainnetSample fullParticipationMainnetSampleData() {
        return mainnetSample("full");
    }

    /**
     * Loads a real sync committee of Ethereum mainnet and its sync aggregate of the block at slot 15526248, signed by
     * all members but six, from {@value #MAINNET_SAMPLE_RESOURCE}, whose comments say where the data comes from.
     *
     * @return the committee and the aggregate
     */
    static MainnetSample sixNonSignersMainnetSampleData() {
        return mainnetSample("partial");
    }

    private static MainnetSample mainnetSample(final String aggregateName) {
        final Properties properties = new Properties();
        try (InputStream in = EthereumSyncCommittee.class.getResourceAsStream(MAINNET_SAMPLE_RESOURCE)) {
            properties.load(requireNonNull(in, MAINNET_SAMPLE_RESOURCE));
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
        final List<byte[]> publicKeys = new ArrayList<>(COMMITTEE_SIZE);
        for (int i = 0; i < COMMITTEE_SIZE; i++) {
            publicKeys.add(hexValue(properties, "committee.publicKey." + i));
        }
        return new MainnetSample(
                new EthereumSyncCommittee(
                        hexValue(properties, "committee.aggregatePublicKey"), List.copyOf(publicKeys)),
                syncAggregate(properties, aggregateName));
    }

    // Returns the bytes of a "0x"-prefixed hex property.
    private static byte[] hexValue(final Properties properties, final String key) {
        final String value = requireNonNull(properties.getProperty(key), key);
        if (!value.startsWith(HEX_PREFIX)) {
            throw new IllegalArgumentException(key + " is not 0x-prefixed hex");
        }
        return HexFormat.of().parseHex(value, HEX_PREFIX.length(), value.length());
    }

    private static SyncAggregate syncAggregate(final Properties properties, final String name) {
        return new SyncAggregate(
                hexValue(properties, name + ".signingRoot"),
                hexValue(properties, name + ".syncCommitteeBits"),
                hexValue(properties, name + ".signature"));
    }

    /**
     * Returns the public keys of the members that signed an aggregate, in committee order.
     *
     * @param aggregate the sync aggregate
     * @return the signers' public keys
     */
    List<byte[]> signers(final SyncAggregate aggregate) {
        return members(aggregate, true);
    }

    /**
     * Returns the public keys of the members that did not sign an aggregate, in committee order.
     *
     * @param aggregate the sync aggregate
     * @return the non-signers' public keys
     */
    List<byte[]> nonSigners(final SyncAggregate aggregate) {
        return members(aggregate, false);
    }

    private List<byte[]> members(final SyncAggregate aggregate, final boolean signed) {
        final List<byte[]> members = new ArrayList<>();
        for (int i = 0; i < publicKeys.size(); i++) {
            final boolean signer = (aggregate.syncCommitteeBits()[i / Byte.SIZE] >> (i % Byte.SIZE) & 1) == 1;
            if (signer == signed) {
                members.add(publicKeys.get(i));
            }
        }
        return members;
    }
}
