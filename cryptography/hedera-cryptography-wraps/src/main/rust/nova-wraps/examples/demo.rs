//! End-to-end demonstration of the [`wraps`] library: a genesis committee rotating
//! itself, then nine further rotations, each authorised by a weighted Schnorr
//! multisignature and folded into one Nova proof.
//!
//! Values cross a bincode serialization/deserialization boundary before use, with
//! byte sizes printed for successful return values and function arguments. Shared
//! parameters and keys are round-tripped once; key generation and signing show one
//! representative member per book/phase. Only sizes, never key or seed bytes, are
//! printed. Proof/key payload sizes are separate from their demo transport envelopes.
//!
//! Needs powers-of-tau files. Put `ppot_pruned_XX.ptau` under `params/`, or point
//! `WRAPS_PTAU_DIR` at a directory holding them:
//!
//! ```bash
//! WRAPS_PTAU_DIR=../Nova/params cargo run --release --example demo
//! ```
use serde::{de::DeserializeOwned, Serialize};
use wraps::{
  decode, encode, AddressBook, Base, BitVector, RotationMessage, RoundMessage,
  SchnorrMultiSignature, SchnorrSecretKey, SigningProtocolMessage, SigningProtocolObject,
  SigningProtocolPhase, E2, ENTROPY_SIZE, MAX_AB_SIZE, WRAPS,
};

fn main() {
  use std::time::Instant;

  println!("=========================================================");
  println!("WRAPS: address-book rotation attested by a weighted");
  println!("Schnorr multisignature, folded with Nova");
  println!("=========================================================");

  let num_steps = 10;
  println!("Sizes below use bincode legacy; return sizes measure the successful payload.");
  let dir = round_trip("setup_public_params input: ptau_dir", ptau_dir());
  println!("Producing public parameters from {}...", dir.display());
  // Generate public parameters once, then borrow them to derive each party's key.
  let start = Instant::now();
  let pp = WRAPS::setup_public_params(&dir).expect("powers-of-tau setup");
  println!("WRAPS::setup_public_params, took {:?}", start.elapsed());
  let pp = round_trip(
    "setup_public_params return: PublicParams (reused by setup/proving/verification)",
    pp,
  );
  let start = Instant::now();
  let wraps_pk = WRAPS::setup_prover(&pp).expect("prover key setup");
  println!("WRAPS::setup_prover, took {:?}", start.elapsed());
  let wraps_pk = round_trip("setup_prover return / construct input: ProverKey", wraps_pk);
  let start = Instant::now();
  let wraps_vk = WRAPS::setup_verifier(&pp).expect("verifier key setup");
  println!("WRAPS::setup_verifier, took {:?}", start.elapsed());
  let wraps_vk = round_trip(
    "setup_verifier return / construct and key-encoding input: VerifierKey",
    wraps_vk,
  );
  let (primary, secondary) = pp.num_constraints();
  println!("Number of constraints per step (primary circuit): {primary}");
  println!("Number of constraints per step (secondary circuit): {secondary}");

  let vk_bytes = WRAPS::get_compressed_verification_key_bytes(&wraps_vk).unwrap();
  println!(
    "Verification key payload: {} bytes (deflated)",
    vk_bytes.len()
  );
  let vk_bytes = round_trip(
    "get_compressed_verification_key_bytes return: Vec<u8>",
    vk_bytes,
  );

  let (genesis_ab, genesis_keys) = random_address_book();
  println!(
    "Generating a genesis address book of {} members (padded to {MAX_AB_SIZE})...",
    genesis_ab.len()
  );
  let ab_genesis_hash = round_trip(
    "compute_addressbook_hash return: AddressBookHash",
    WRAPS::compute_addressbook_hash(&genesis_ab).unwrap(),
  );

  // A seat can be held open with the sentinel key: the point at infinity, which
  // contributes nothing to a joint key. It is exempt from the proof-of-knowledge check
  // precisely because there is no secret to prove — and that costs nothing, because the
  // circuit and `subset_weight` both treat such a seat as carrying no weight, so there
  // is nothing to claim with it either.
  let sentinel = round_trip(
    "sentinel_keygen return: SchnorrAttestedPubKey",
    WRAPS::sentinel_keygen(),
  );
  let held_open: AddressBook<E2> = genesis_ab
    .iter()
    .enumerate()
    .map(|(i, entry)| {
      if i < 4 {
        (Base::from(i as u64), sentinel.clone(), 0)
      } else {
        entry.clone()
      }
    })
    .collect();
  let held_open = round_trip(
    "compute_addressbook_hash input: sentinel AddressBook",
    held_open,
  );
  round_trip(
    "compute_addressbook_hash return: sentinel AddressBookHash",
    WRAPS::compute_addressbook_hash(&held_open).expect("sentinel seats are valid"),
  );
  println!("A book with 4 seats held open by the sentinel key validates");

  let mut prev = (genesis_ab, genesis_keys);
  let mut running_proof: Option<Vec<u8>> = None;

  for i in 0..num_steps {
    println!(
      "--------------------------------------- rotation {} of {num_steps}",
      i + 1
    );
    // The genesis step rotates the book onto itself; later steps propose a fresh one.
    let next = if i == 0 {
      prev.clone()
    } else {
      random_address_book()
    };
    let hints_vk = round_trip(
      "compute_hints_vk_hash / compute_rotation_message input: hints_vk Vec<u8>",
      vec![i as u8; 1480],
    );
    let hints_vk_hash = round_trip(
      "compute_hints_vk_hash return: HintsVKHash",
      WRAPS::compute_hints_vk_hash(&hints_vk),
    );

    // next.0 is the decoded AddressBook produced by random_address_book (or genesis).
    let message = round_trip(
      "compute_rotation_message return: serialized RotationMessage",
      WRAPS::compute_rotation_message(&next.0, &hints_vk).unwrap(),
    );
    let decoded_message: RotationMessage<E2> = round_trip(
      "RotationMessage",
      decode(&message).expect("decode rotation message"),
    );
    assert_eq!(decoded_message[1], hints_vk_hash);
    assert_eq!(
      encode(&decoded_message).expect("encode rotation message"),
      message
    );
    let bitvector = round_trip(
      "signing_protocol input: BitVector",
      sufficient_bitvector(prev.0.len()),
    );
    let start = Instant::now();
    let multisignature = threshold_sign(&message, &prev.0, &prev.1, &bitvector, true);
    println!(
      "  threshold_sign over {} of {} seats, took {:?}",
      bitvector.iter().filter(|b| **b).count(),
      prev.0.len(),
      start.elapsed()
    );
    let (signing_book, signed_message, signature) = round_trip(
      "verify_signature inputs: (AddressBook, rotation message bytes, SchnorrMultiSignature)",
      (prev.0.clone(), message.clone(), multisignature.clone()),
    );
    assert!(round_trip(
      "verify_signature return: bool",
      WRAPS::verify_signature(&signing_book, &signed_message, &signature).unwrap(),
    ));

    // The large shared pp/pk/vk inputs were decoded once above and are reused here.
    let (genesis_hash, prev_ab, next_ab, prev_proof, proof_hints_vk, proof_signature) = round_trip(
      "construct_wraps_proof inputs (excluding shared pp/pk/vk)",
      (
        ab_genesis_hash,
        prev.0.clone(),
        next.0.clone(),
        running_proof.clone(),
        hints_vk.clone(),
        multisignature,
      ),
    );

    let start = Instant::now();
    let (uncompressed, compressed) = WRAPS::construct_wraps_proof(
      &pp,
      &wraps_pk,
      &wraps_vk,
      &genesis_hash,
      &prev_ab,
      &next_ab,
      prev_proof,
      &proof_hints_vk,
      &proof_signature,
    )
    .expect("the rotation is authorised");
    println!("  construct_wraps_proof, took {:?}", start.elapsed());
    println!(
      "  proof payloads: running {} bytes (bincode), compressed {} bytes (bincode)",
      uncompressed.len(),
      compressed.len()
    );
    let (uncompressed, compressed) = round_trip(
      "construct_wraps_proof return: (running Vec<u8>, compressed Vec<u8>)",
      (uncompressed, compressed),
    );

    let (verifier_key, proof, genesis_hash, verifier_hints_vk) = round_trip(
      "verify_compressed_wraps_proof inputs: (vk bytes, proof bytes, genesis hash, hints vk)",
      (
        vk_bytes.clone(),
        compressed,
        ab_genesis_hash,
        hints_vk.clone(),
      ),
    );

    let start = Instant::now();
    let verified = WRAPS::verify_compressed_wraps_proof(
      &verifier_key,
      &proof,
      &genesis_hash,
      &verifier_hints_vk,
    )
    .unwrap();
    println!(
      "  verify_compressed_wraps_proof: {verified:?}, took {:?}",
      start.elapsed()
    );
    assert!(round_trip(
      "verify_compressed_wraps_proof return: bool",
      verified
    ));

    // The same chain, checked from the running proof instead. Cheaper, but it needs the
    // folding parameters and megabytes of proof, so it is for a party that already has
    // both rather than for a remote verifier.
    let (uncompressed, genesis_hash, verifier_hints_vk) = round_trip(
      "verify_uncompressed_wraps_proof inputs (excluding shared pp)",
      (uncompressed, ab_genesis_hash, hints_vk.clone()),
    );
    let start = Instant::now();
    let verified =
      WRAPS::verify_uncompressed_wraps_proof(&pp, &uncompressed, &genesis_hash, &verifier_hints_vk)
        .unwrap();
    println!(
      "  verify_uncompressed_wraps_proof: {verified:?}, took {:?}",
      start.elapsed()
    );
    assert!(round_trip(
      "verify_uncompressed_wraps_proof return: bool",
      verified
    ));

    // A committee below the threshold cannot rotate, however honest its shares are.
    let short = threshold_sign(
      &message,
      &prev.0,
      &prev.1,
      &insufficient_bitvector(prev.0.len()),
      false,
    );
    let rejected = WRAPS::construct_wraps_proof(
      &pp,
      &wraps_pk,
      &wraps_vk,
      &ab_genesis_hash,
      &prev.0,
      &next.0,
      running_proof.clone(),
      &hints_vk,
      &short,
    );
    assert!(rejected.is_err(), "a minority must not be able to rotate");
    println!("  a one-third committee was rejected, as it should be");

    prev = next;
    running_proof = Some(uncompressed);
  }

  println!("=========================================================");
  println!("Rotated {num_steps} address books; every proof verified");
  println!("=========================================================");
}

// =========================================================================
// Serialization using the library's shared codec.
// =========================================================================

/// Checks a complete round trip and returns the decoded value for subsequent calls.
/// Byte equality avoids requiring PartialEq/Debug on Nova's parameters and keys.
fn round_trip<T: Serialize + DeserializeOwned>(label: &str, value: T) -> T {
  let bytes = encode(&value).expect("serialize demo value");
  drop(value);
  let decoded: T = decode(&bytes).expect("deserialize demo value");
  let encoded_again = encode(&decoded).expect("reserialize demo value");
  assert!(
    bytes == encoded_again,
    "{label}: round trip changed the encoding"
  );
  println!("  {label}: {} bytes; round trip OK", bytes.len());
  decoded
}

// =========================================================================
// Simulation helpers for this demo.
// =========================================================================

/// Generates a fresh address book and keeps its members' secret keys.
///
/// The size varies between a quarter of [`MAX_AB_SIZE`] and the whole of it, so callers
/// exercise the padding path rather than always landing on the one size that needs none.
///
/// Weights are drawn from a narrow band around 500 so that a subset's share of the total
/// weight tracks its share of the seats, which is what makes the bitvectors below
/// predictably above or below the threshold.
fn random_address_book() -> (AddressBook<E2>, Vec<SchnorrSecretKey<E2>>) {
  use rand::Rng;
  let mut rng = rand::thread_rng();
  let size = rng.gen_range(MAX_AB_SIZE / 4..=MAX_AB_SIZE);

  let mut keys = Vec::with_capacity(size);
  let ab = (0..size)
    .map(|i| {
      let seed = rng.gen();
      let seed = if i == 0 {
        round_trip("keygen input: seed", seed)
      } else {
        seed
      };
      let generated = WRAPS::keygen(seed);
      let (sk, attested) = if i == 0 {
        round_trip(
          "keygen return: (SchnorrSecretKey, SchnorrAttestedPubKey)",
          generated,
        )
      } else {
        generated
      };
      let (sk, attested) = if i == 0 {
        let sk = round_trip("  SchnorrSecretKey", sk);
        let (pk, pok) = attested;
        let pk = round_trip("  SchnorrPublicKey", pk);
        let pok = round_trip("  SchnorrPoK", pok);
        (sk, (pk, pok))
      } else {
        (sk, attested)
      };
      keys.push(sk);
      let entry = (
        Base::from(i as u64),
        attested,
        rng.gen_range(475u64..=525u64),
      );
      if i == 0 {
        round_trip("AddressBookEntry", entry)
      } else {
        entry
      }
    })
    .collect();

  (
    round_trip("hashing / signing / proving input: AddressBook", ab),
    round_trip("signing keys: Vec<SchnorrSecretKey>", keys),
  )
}

/// A subset that always clears the threshold: about two thirds of the seats.
///
/// Padding seats are left out, which is what padding means — a seat that does not exist
/// did not sign.
fn sufficient_bitvector(size: usize) -> BitVector {
  BitVector::from(core::array::from_fn(|i| {
    i < size && (i % 2 == 0 || i % 3 == 0)
  }))
}

/// A subset that never clears it: about a third of the seats.
fn insufficient_bitvector(size: usize) -> BitVector {
  BitVector::from(core::array::from_fn(|i| i < size && i % 3 == 0))
}

/// Runs all three rounds plus aggregation over the members the bitvector names.
fn threshold_sign(
  message: &[u8],
  address_book: &AddressBook<E2>,
  keys: &[SchnorrSecretKey<E2>],
  bitvector: &BitVector,
  report_serialization: bool,
) -> SchnorrMultiSignature<E2> {
  use rand::Rng;
  let mut rng = rand::thread_rng();

  let signing_keys = keys
    .iter()
    .zip(bitvector.iter())
    .filter_map(|(sk, &signed)| signed.then_some(sk))
    .collect::<Vec<_>>();
  // One seed per signer, drawn once and reused across this instance's three rounds —
  // and never across instances, since `threshold_sign` draws afresh on every call.
  let seeds = (0..signing_keys.len())
    .map(|_| rng.gen::<[u8; ENTROPY_SIZE]>())
    .collect::<Vec<_>>();

  let run = |phase,
             i: Option<usize>,
             sk: Option<&SchnorrSecretKey<E2>>,
             r1: &[SigningProtocolMessage],
             r2: &[SigningProtocolMessage],
             r3: &[SigningProtocolMessage]| {
    // One representative signer per phase keeps the size report readable. The
    // remaining signers' messages cross the boundary together in each broadcast.
    let report = report_serialization && i.is_none_or(|i| i == 0);
    let inputs = (
      phase,
      i.map(|i| seeds[i]),
      message.to_vec(),
      sk.copied(),
      address_book.clone(),
      *bitvector,
      r1.to_vec(),
      r2.to_vec(),
      r3.to_vec(),
    );
    let (phase, entropy, message, sk, book, bits, r1, r2, r3) = if report {
      round_trip(&format!("signing_protocol {phase:?} inputs (phase, entropy, message, key, book, bits, r1, r2, r3)"), inputs)
    } else {
      inputs
    };
    let output = WRAPS::signing_protocol(
      phase,
      entropy,
      &message,
      sk.as_ref(),
      &book,
      bits,
      &r1,
      &r2,
      &r3,
    )
    .expect("honest signers follow the protocol");
    if report {
      round_trip(
        &format!("signing_protocol {phase:?} return: SigningProtocolObject"),
        output,
      )
    } else {
      output
    }
  };

  // Round 1: everyone is bound to a nonce before any nonce is revealed. WRAPS
  // returns encoded bytes that subsequent rounds accept directly; decoding below
  // is only for payload inspection and size reports.
  let round1 = (0..signing_keys.len())
    .map(
      |i| match run(SigningProtocolPhase::R1, Some(i), None, &[], &[], &[]) {
        SigningProtocolObject::ProtocolMessage(m) => m,
        _ => unreachable!("R1 returns a round-1 message"),
      },
    )
    .collect::<Vec<_>>();
  let round1 = if report_serialization {
    let wire: RoundMessage<E2> = decode(&round1[0]).expect("decode round-1 message");
    let wire = round_trip("RoundMessage<E2>::Round1", wire);
    let RoundMessage::Round1(payload) = wire else {
      unreachable!("the R1 broadcast contains round-1 messages");
    };
    round_trip("MultisigRound1", payload);
    round_trip("R1 broadcast: Vec<SigningProtocolMessage>", round1)
  } else {
    round1
  };

  // Round 2: the openings.
  let round2 = (0..signing_keys.len())
    .map(
      |i| match run(SigningProtocolPhase::R2, Some(i), None, &round1, &[], &[]) {
        SigningProtocolObject::ProtocolMessage(m) => m,
        _ => unreachable!("R2 returns a round-2 message"),
      },
    )
    .collect::<Vec<_>>();
  let round2 = if report_serialization {
    let wire: RoundMessage<E2> = decode(&round2[0]).expect("decode round-2 message");
    let wire = round_trip("RoundMessage<E2>::Round2", wire);
    let RoundMessage::Round2(payload) = wire else {
      unreachable!("the R2 broadcast contains round-2 messages");
    };
    round_trip("MultisigRound2", payload);
    round_trip("R2 broadcast: Vec<SigningProtocolMessage>", round2)
  } else {
    round2
  };

  // Round 3: partial signatures over the shared challenge.
  let round3 = (0..signing_keys.len())
    .map(|i| {
      match run(
        SigningProtocolPhase::R3,
        Some(i),
        Some(signing_keys[i]),
        &round1,
        &round2,
        &[],
      ) {
        SigningProtocolObject::ProtocolMessage(m) => m,
        _ => unreachable!("R3 returns a round-3 message"),
      }
    })
    .collect::<Vec<_>>();
  let round3 = if report_serialization {
    let wire: RoundMessage<E2> = decode(&round3[0]).expect("decode round-3 message");
    let wire = round_trip("RoundMessage<E2>::Round3", wire);
    let RoundMessage::Round3(payload) = wire else {
      unreachable!("the R3 broadcast contains round-3 messages");
    };
    let payload = round_trip("MultisigRound3", payload);
    round_trip("Signature", payload.partial_signature);
    round_trip("R3 broadcast: Vec<SigningProtocolMessage>", round3)
  } else {
    round3
  };

  match run(
    SigningProtocolPhase::Aggregate,
    None,
    None,
    &round1,
    &round2,
    &round3,
  ) {
    SigningProtocolObject::ProtocolOutput(sig) => {
      if report_serialization {
        round_trip("SchnorrMultiSignature: (BitVector, Signature)", sig)
      } else {
        sig
      }
    }
    _ => unreachable!("Aggregate returns the multisignature"),
  }
}

/// The directory holding pruned powers-of-tau files, overridable for testing.
///
/// HyperKZG on the primary curve needs a universal setup, so there is no transparent
/// fallback here. Drop `ppot_pruned_XX.ptau` files into `./params` — or point
/// `WRAPS_PTAU_DIR` at a directory holding them. See the "Powers of tau" section of
/// the README.
fn ptau_dir() -> std::path::PathBuf {
  std::env::var("WRAPS_PTAU_DIR")
    .unwrap_or_else(|_| "params".to_string())
    .into()
}
