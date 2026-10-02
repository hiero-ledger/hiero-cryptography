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

Signing is pure ML-DSA-44 (FIPS 204 `ML-DSA.Sign` and `ML-DSA.Verify`) over the
32-byte digest above with the context string; HashML-DSA is not used. The
module pins the `ML-DSA-44` algorithm, so ML-DSA-65, ML-DSA-87, and HashML-DSA
keys are rejected.

## Test vectors

Language-neutral vectors for SDK, wallet, and node implementers are in
[`src/test/resources/hcpq-v1`](src/test/resources/hcpq-v1):

- `signature-vectors.json`: key identifiers for seeded ML-DSA-44 keys,
  transaction digests (including multi-byte length prefixes), and signature
  tests. Valid signatures use the FIPS 204 deterministic variant so they are
  reproducible. Invalid tests cover cross-ledger replay, modified bodies, wrong
  or empty contexts, HashML-DSA, signing the raw body instead of the digest,
  wrong keys, mismatched or truncated key identifiers, and malformed lengths.
  Every invalid signature that came from a signing operation records how it was
  produced in `signed_as`.
- `canonical-transaction-body-vectors.json`: canonical `TransactionBody`
  encodings with their proto3 JSON form, and alternate encodings that a node
  must reject (explicit defaults, field-order changes including .proto
  declaration order, non-minimal varints and lengths, duplicate fields,
  unpacked repeated scalars, unknown fields, truncation, trailing bytes, and
  invalid UTF-8).

`HcpqVectorsTest` recomputes every derived value in both files from its inputs,
including every signature. The canonical-body verdicts were generated with the
PBJ 0.15.10 `TransactionBody` codec using the node's strict-parse and
re-encode rule. Each rejected alternate encoding parses to the same body as
its canonical counterpart, and Google's reference protobuf encoder (`protoc`)
reproduces every accepted body byte for byte.

`tools/crosscheck_openssl.py` checks the signature vectors independently of
this module, using Python's `hashlib` and the OpenSSL 3.5+ command line:

```sh
python3 tools/crosscheck_openssl.py src/test/resources/hcpq-v1/signature-vectors.json
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

Before protecting real assets, the complete integration requires the vectors
above to be run by independent SDK implementations, dependency and provenance review, hardware and wallet
analysis, adversarial tests, representative multi-node capacity testing, and
an approved HIP with network-configured fees and throttles. Primitive
verification throughput does not prove a 10,000-transactions-per-second
network result.
