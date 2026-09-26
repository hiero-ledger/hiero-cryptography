# Hedera HCPQ transaction signatures

This experimental module implements the cryptographic portion of HCPQ v1, a
ledger-bound Hedera transaction profile for FIPS 204 ML-DSA-44.

HCPQ does **not** define a new signature primitive or hardness assumption. It
uses ML-DSA-44 with exact encodings, a complete 32-byte public-key identifier,
and a Hedera-specific signing transcript.

## Protocol contract

- Public key: raw ML-DSA-44 encoding, exactly 1,312 bytes.
- Signature: raw ML-DSA-44 encoding, exactly 2,420 bytes.
- Key identifier: the complete 32-byte SHA3-256 result; truncation is invalid.
- Transaction body: the exact canonical `TransactionBody` protobuf bytes.
- Ledger identifier: non-empty trusted network configuration, not caller data.
- ML-DSA context: `HCPQ-SIG-TX-v1`.

The key identifier is:

```text
SHA3-256(
    "HCPQ-SIG-KEY-ID\0" ||
    version:u8 ||
    algorithm:u8 ||
    public_key_length:u64be ||
    public_key
)
```

The message supplied to ML-DSA-44 is:

```text
SHA3-256(
    "HCPQ-SIG-HEDERA-TX\0" ||
    version:u8 ||
    ledger_id_length:u16be ||
    ledger_id ||
    transaction_body_length:u64be ||
    canonical_transaction_body
)
```

## Implementation notes

The module constructs a private Bouncy Castle provider instance and does not
modify the JVM-wide provider registry. Signing requires a caller-supplied
`SecureRandom`; verification rejects malformed lengths, key identifiers,
public-key encodings, signatures, empty ledger identifiers, and empty bodies.

The consensus-node integration is responsible for canonical protobuf
validation, obtaining the configured ledger identifier, activation gating,
resource limits, matching the public key from entity state, fees, and
throttling.

## Security and deployment status

This is draft reference code, not a production activation recommendation. It
has local unit and integration tests but has not received independent
cryptographic, side-channel, JVM-provider, or consensus-network review.

Before protecting real assets, the complete integration requires published
cross-provider vectors, dependency and provenance review, hardware and wallet
analysis, adversarial tests, representative multi-node capacity testing, and
an approved HIP with network-configured fees and throttles. Primitive
verification throughput does not prove a 10,000-transactions-per-second
network result.
