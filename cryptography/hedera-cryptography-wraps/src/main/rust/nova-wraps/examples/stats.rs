//! Three linked rotations: a genesis self-rotation, then two new committees.
//! Two of each outgoing book's three equal-weight members sign its successor.
//!
//! All inputs, outputs, and broadcasts are round-tripped with the library's shared
//! encode/decode helpers, and both proof forms are verified after every rotation.
//! The final rotation prints one compact table of individual named types, with
//! separate rows for enum variants whose encodings differ. Shared setup artifacts
//! are included. Raw proof/key payload sizes are reported in a separate table.
//! Sizes use decimal KB (1 KB = 1,000 bytes). A timing table covers setup calls and
//! the final rotation, excluding example serialization and reporting overhead.
//! Serialization checks are silent; secret values are never printed.
//!
//! Needs power-15 or larger powers-of-tau files under params/, or WRAPS_PTAU_DIR:
//! ```bash
//! cargo run --release -p novawraps --example stats
//! ```

use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use std::{
  collections::BTreeMap,
  path::PathBuf,
  time::{Duration, Instant},
};
use novawraps::{
  decode, encode, AddressBook, Base, BitVector, RotationMessage, RoundMessage,
  SchnorrMultiSignature, SchnorrSecretKey, SigningProtocolMessage, SigningProtocolObject,
  SigningProtocolPhase, E2, ENTROPY_SIZE, WRAPS,
};

fn main() {
  const ROTATIONS: usize = 3;
  println!("WRAPS: three linked rotations, two of three members signing each");

  let mut setup_timings = TimingReport::new(true);

  // Check setup serialization now; defer its size report to the final rotation.
  let dir = round_trip(
    "setup_public_params input: ptau_dir",
    &std::env::var_os("WRAPS_PTAU_DIR")
      .map(PathBuf::from)
      .unwrap_or_else(|| PathBuf::from("params")),
  );
  println!("Loading powers of tau from {}...", dir.display());
  let pp = round_trip(
    "PublicParams",
    &setup_timings
      .measure("WRAPS::setup_public_params", || {
        WRAPS::setup_public_params(&dir)
      })
      .expect("powers-of-tau setup"),
  );
  let pk = round_trip(
    "ProverKey",
    &setup_timings
      .measure("WRAPS::setup_prover", || WRAPS::setup_prover(&pp))
      .expect("prover key setup"),
  );
  let vk = round_trip(
    "VerifierKey",
    &setup_timings
      .measure("WRAPS::setup_verifier", || WRAPS::setup_verifier(&pp))
      .expect("verifier key setup"),
  );
  let vk_bytes = round_trip(
    "verification key: Vec<u8>",
    &setup_timings
      .measure("WRAPS::get_compressed_verification_key_bytes", || {
        WRAPS::get_compressed_verification_key_bytes(&vk)
      })
      .expect("encode verifier key"),
  );
  let mut quiet_timings = TimingReport::new(false);
  let mut previous = random_address_book(&mut quiet_timings);
  let genesis_hash = round_trip(
    "genesis AddressBookHash",
    &quiet_timings
      .measure("WRAPS::compute_addressbook_hash", || {
        WRAPS::compute_addressbook_hash(&previous.0)
      })
      .expect("valid genesis book"),
  );
  let mut running_proof: Option<Vec<u8>> = None;

  for rotation in 0..ROTATIONS {
    println!("--- rotation {} of {ROTATIONS}", rotation + 1);
    let mut report = SizeReport::new(rotation + 1 == ROTATIONS);
    let mut timings = TimingReport::new(rotation + 1 == ROTATIONS);
    let start = Instant::now();
    report.size("PublicParams", &pp);
    report.size("ProverKey", &pk);
    report.size("VerifierKey", &vk);
    report.artifact("Verification key (bincode)", vk_bytes.len());
    report.size("AddressBookHash<E2>", &genesis_hash);
    report_address_book_types(&mut report, &previous.0, &previous.1);

    // The first step attests genesis itself; later committees are freshly generated.
    let next = if rotation == 0 {
      previous.clone()
    } else {
      random_address_book(&mut timings)
    };
    let next_hash = round_trip(
      "compute_addressbook_hash return: successor AddressBookHash",
      &timings
        .measure("WRAPS::compute_addressbook_hash", || {
          WRAPS::compute_addressbook_hash(&next.0)
        })
        .expect("valid successor book"),
    );
    let hints_vk = round_trip(
      "compute_hints_vk_hash input: hints_vk",
      &vec![rotation as u8; 1480],
    );
    let hints_vk_hash = round_trip(
      "compute_hints_vk_hash return: HintsVKHash",
      &timings.measure("WRAPS::compute_hints_vk_hash", || {
        WRAPS::compute_hints_vk_hash(&hints_vk)
      }),
    );
    let (next_book, hints_vk) = round_trip(
      "compute_rotation_message inputs: (AddressBook, hints_vk)",
      &(next.0.clone(), hints_vk),
    );
    let message = round_trip(
      "compute_rotation_message return: serialized RotationMessage",
      &timings
        .measure("WRAPS::compute_rotation_message", || {
          WRAPS::compute_rotation_message(&next_book, &hints_vk)
        })
        .expect("valid successor book"),
    );
    let decoded_message: RotationMessage<E2> = decode(&message).expect("decode rotation message");
    assert_eq!(decoded_message, [next_hash, hints_vk_hash]);
    assert_eq!(
      encode(&decoded_message).expect("encode rotation message"),
      message
    );
    report.size("HintsVKHash<E2>", &hints_vk_hash);
    report.size("RotationMessage<E2>", &decoded_message);
    let multisignature = sign(
      &message,
      &previous.0,
      &previous.1,
      &mut report,
      &mut timings,
    );

    let (book, message, multisignature) = round_trip(
      "verify_signature inputs: (AddressBook, rotation message bytes, SchnorrMultiSignature)",
      &(previous.0.clone(), message, multisignature),
    );
    assert!(round_trip(
      "verify_signature return: bool",
      &timings
        .measure("WRAPS::verify_signature", || WRAPS::verify_signature(
          &book,
          &message,
          &multisignature
        ))
        .expect("valid verification inputs"),
    ));

    assert_eq!(running_proof.is_none(), rotation == 0);
    let previous_proof = round_trip(
      "construct_wraps_proof input: prev_proof Option<Vec<u8>>",
      &running_proof.take(),
    );
    let (proof_genesis, prev_book, next_book, previous_proof, proof_hints, signature) = round_trip(
      "construct_wraps_proof inputs: (genesis hash, prev book, next book, prev proof, hints vk, multisignature); pp/pk/vk reused",
      &(genesis_hash, book, next_book, previous_proof, hints_vk, multisignature),
    );
    let proofs = timings
      .measure("WRAPS::construct_wraps_proof", || {
        WRAPS::construct_wraps_proof(
          &pp,
          &pk,
          &vk,
          &proof_genesis,
          &prev_book,
          &next_book,
          previous_proof,
          &proof_hints,
          &signature,
        )
      })
      .expect("the rotation is authorised");
    report.artifact("Running proof (bincode)", proofs.0.len());
    report.artifact("Compressed proof (bincode)", proofs.1.len());
    let (running, compressed) = round_trip(
      "construct_wraps_proof return: (running Vec<u8>, compressed Vec<u8>)",
      &proofs,
    );
    let running = round_trip("running proof: Vec<u8>", &running);
    let compressed = round_trip("compressed proof: Vec<u8>", &compressed);

    let (verifier_key, compressed, proof_genesis, proof_hints) = round_trip(
      "verify_compressed_wraps_proof inputs: (vk bytes, proof bytes, genesis hash, hints vk)",
      &(vk_bytes.clone(), compressed, proof_genesis, proof_hints),
    );
    assert!(round_trip(
      "verify_compressed_wraps_proof return: bool",
      &timings
        .measure("WRAPS::verify_compressed_wraps_proof", || {
          WRAPS::verify_compressed_wraps_proof(
            &verifier_key,
            &compressed,
            &proof_genesis,
            &proof_hints,
          )
        })
        .expect("valid compressed proof inputs"),
    ));

    let (running, proof_genesis, proof_hints) = round_trip(
      "verify_uncompressed_wraps_proof inputs: (running proof, genesis hash, hints vk); pp reused",
      &(running, proof_genesis, proof_hints),
    );
    assert!(round_trip(
      "verify_uncompressed_wraps_proof return: bool",
      &timings
        .measure("WRAPS::verify_uncompressed_wraps_proof", || {
          WRAPS::verify_uncompressed_wraps_proof(&pp, &running, &proof_genesis, &proof_hints)
        })
        .expect("valid running proof inputs"),
    ));
    previous = next;
    running_proof = Some(running);
    println!(
      "Rotation {} verified (signature and both proof forms), took {:?}",
      rotation + 1,
      start.elapsed()
    );
    report.print();
    timings.print(&setup_timings);
  }
  println!("Three linked rotations complete; all serialization and verification checks passed.");
}

/// Generate a three-member, equal-weight committee and retain its signing keys.
fn random_address_book(timings: &mut TimingReport) -> (AddressBook<E2>, Vec<SchnorrSecretKey<E2>>) {
  let mut rng = rand::thread_rng();
  let mut address_book: AddressBook<E2> = Vec::new();
  let mut keys = Vec::new();
  for member in 0..3 {
    let seed = round_trip("keygen input: seed", &rng.gen::<[u8; ENTROPY_SIZE]>());
    let (sk, (pk, pok)) = round_trip(
      "keygen return",
      &timings.measure("WRAPS::keygen", || WRAPS::keygen(seed)),
    );
    let sk = round_trip("SchnorrSecretKey", &sk);
    let pk = round_trip("SchnorrPublicKey", &pk);
    let pok = round_trip("SchnorrPoK", &pok);
    let attested = round_trip("SchnorrAttestedPubKey", &(pk, pok));
    let entry = round_trip(
      "AddressBookEntry",
      &(Base::from(member as u64), attested, 1u64),
    );
    keys.push(sk);
    address_book.push(entry);
  }
  let keys = round_trip("signing keys: Vec<SchnorrSecretKey>", &keys);
  let address_book = round_trip("hashing/signing input: AddressBook", &address_book);

  (address_book, keys)
}

/// Each outgoing committee runs one signing instance with fresh entropy.
fn sign(
  message: &[u8],
  address_book: &AddressBook<E2>,
  keys: &[SchnorrSecretKey<E2>],
  report: &mut SizeReport,
  timings: &mut TimingReport,
) -> SchnorrMultiSignature<E2> {
  let mut rng = rand::thread_rng();
  // A noncontiguous majority; round messages retain this signing-subset order.
  let signers = [0usize, 2];
  let bitvector = round_trip(
    "signing_protocol input: BitVector",
    &BitVector::from(core::array::from_fn(|i| signers.contains(&i))),
  );
  // Fresh entropy per signer, reused only across the three rounds of this instance.
  let entropy = round_trip(
    "signing entropy: Vec<[u8; ENTROPY_SIZE]>",
    &signers
      .iter()
      .map(|_| rng.gen::<[u8; ENTROPY_SIZE]>())
      .collect::<Vec<_>>(),
  );

  let mut run = |phase,
                 signer: Option<usize>,
                 key: Option<&SchnorrSecretKey<E2>>,
                 r1: &[SigningProtocolMessage],
                 r2: &[SigningProtocolMessage],
                 r3: &[SigningProtocolMessage]| {
    let phase = round_trip("SigningProtocolPhase", &phase);
    let seed = round_trip(
      "protocol_instance_entropy: Option<seed>",
      &signer.map(|i| entropy[i]),
    );
    let key = round_trip("signing_key: Option<SchnorrSecretKey>", &key.copied());
    let (phase, seed, message, key, book, bits, r1, r2, r3) = round_trip(
      "signing_protocol inputs: (phase, entropy, message, key, book, bits, r1, r2, r3)",
      &(
        phase,
        seed,
        message.to_vec(),
        key,
        address_book.clone(),
        bitvector,
        r1.to_vec(),
        r2.to_vec(),
        r3.to_vec(),
      ),
    );
    let output = timings
      .measure("WRAPS::signing_protocol", || {
        WRAPS::signing_protocol(
          phase,
          seed,
          &message,
          key.as_ref(),
          &book,
          bits,
          &r1,
          &r2,
          &r3,
        )
      })
      .expect("honest signers follow the protocol");
    round_trip("signing_protocol return: SigningProtocolObject", &output)
  };

  // Collect every commitment before any signer opens its nonce.
  let mut round1 = Vec::new();
  for i in 0..signers.len() {
    let SigningProtocolObject::ProtocolMessage(outgoing) =
      run(SigningProtocolPhase::R1, Some(i), None, &[], &[], &[])
    else {
      unreachable!("R1 returns a commitment");
    };
    // ProtocolMessage is already encoded; transport its bytes directly.
    let received = round_trip("R1 broadcast: SigningProtocolMessage", &outgoing);
    round1.push(received);
  }
  let round1 = round_trip("round1_messages: Vec<SigningProtocolMessage>", &round1);

  // Openings are received and ordered before anyone creates a partial signature.
  let mut round2 = Vec::new();
  for i in 0..signers.len() {
    let SigningProtocolObject::ProtocolMessage(outgoing) =
      run(SigningProtocolPhase::R2, Some(i), None, &round1, &[], &[])
    else {
      unreachable!("R2 returns an opening");
    };
    let received = round_trip("R2 broadcast: SigningProtocolMessage", &outgoing);
    round2.push(received);
  }
  let round2 = round_trip("round2_messages: Vec<SigningProtocolMessage>", &round2);

  let mut round3 = Vec::new();
  for (i, &member) in signers.iter().enumerate() {
    let SigningProtocolObject::ProtocolMessage(outgoing) = run(
      SigningProtocolPhase::R3,
      Some(i),
      Some(&keys[member]),
      &round1,
      &round2,
      &[],
    ) else {
      unreachable!("R3 returns a partial signature");
    };
    let received = round_trip("R3 broadcast: SigningProtocolMessage", &outgoing);
    round3.push(received);
  }
  let round3 = round_trip("round3_messages: Vec<SigningProtocolMessage>", &round3);

  let SigningProtocolObject::ProtocolOutput((bits, signature)) = run(
    SigningProtocolPhase::Aggregate,
    None,
    None,
    &round1,
    &round2,
    &round3,
  ) else {
    unreachable!("aggregation returns a multisignature");
  };
  let signature = round_trip("aggregate Signature", &signature);
  let multisignature = round_trip("SchnorrMultiSignature", &(bits, signature));
  assert_eq!(multisignature.0, bitvector);

  report.size("BitVector", &bitvector);
  report.size("SchnorrChallenge<E2>", &multisignature.1.e);
  report.size("SchnorrResponse<E2>", &multisignature.1.s);
  report.size("Signature<E2>", &multisignature.1);
  report.size("SchnorrMultiSignature<E2>", &multisignature);
  report.size("SigningProtocolPhase", &SigningProtocolPhase::R1);
  // Decode only to inspect/report the named wire types. Protocol calls above use
  // the original bytes returned by WRAPS, without adding a second round envelope.
  let decoded_round1 = inspect_round_message(&round1[0]);
  let RoundMessage::Round1(payload) = &decoded_round1 else {
    unreachable!("R1 encodes a commitment");
  };
  let payload = round_trip("MultisigRound1", payload);
  report.size("MultisigRound1", &payload);
  report.size("RoundMessage<E2>::Round1", &decoded_round1);
  report.size("SigningProtocolMessage (round 1)", &round1[0]);

  let decoded_round2 = inspect_round_message(&round2[0]);
  let RoundMessage::Round2(payload) = &decoded_round2 else {
    unreachable!("R2 encodes an opening");
  };
  let payload = round_trip("MultisigRound2", payload);
  report.size("MultisigRound2<E2>", &payload);
  report.size("RoundMessage<E2>::Round2", &decoded_round2);
  report.size("SigningProtocolMessage (round 2)", &round2[0]);

  let decoded_round3 = inspect_round_message(&round3[0]);
  let RoundMessage::Round3(payload) = &decoded_round3 else {
    unreachable!("R3 encodes a partial signature");
  };
  let payload = round_trip("MultisigRound3", payload);
  round_trip("partial Signature", &payload.partial_signature);
  report.size("MultisigRound3<E2>", &payload);
  report.size("RoundMessage<E2>::Round3", &decoded_round3);
  report.size("SigningProtocolMessage (round 3)", &round3[0]);
  report.size(
    "SigningProtocolObject::ProtocolMessage (round 1)",
    &SigningProtocolObject::<E2>::ProtocolMessage(round1[0].clone()),
  );
  report.size(
    "SigningProtocolObject::ProtocolMessage (round 2)",
    &SigningProtocolObject::<E2>::ProtocolMessage(round2[0].clone()),
  );
  report.size(
    "SigningProtocolObject::ProtocolMessage (round 3)",
    &SigningProtocolObject::<E2>::ProtocolMessage(round3[0].clone()),
  );
  report.size(
    "SigningProtocolObject<E2>::ProtocolOutput",
    &SigningProtocolObject::ProtocolOutput(multisignature.clone()),
  );
  multisignature
}

/// Inspect an already encoded round message without changing its transport bytes.
fn inspect_round_message(bytes: &[u8]) -> RoundMessage<E2> {
  let message = decode(bytes).expect("decode tagged round message");
  assert_eq!(
    encode(&message).expect("reencode tagged round message"),
    bytes,
    "round message encoding must survive a round trip"
  );
  message
}

/// Measure each named key, field, and address-book type using the final committee.
fn report_address_book_types(
  report: &mut SizeReport,
  book: &AddressBook<E2>,
  keys: &[SchnorrSecretKey<E2>],
) {
  let entry = &book[0];
  let (public_key, pok) = &entry.1;
  report.size("Base", &entry.0);
  report.size("SchnorrSecretKey<E2>", &keys[0]);
  report.size("SchnorrPublicKey<E2>", public_key);
  report.size("SchnorrPoK<E2>", pok);
  report.size("SchnorrPoKChallenge<E2>", &pok.challenge);
  report.size("SchnorrAttestedPubKey<E2>", &entry.1);
  report.size("Weight", &entry.2);
  report.size("NodeId<E2>", &entry.0);
  report.size("AddressBookEntry<E2>", entry);
  report.size("AddressBook<E2>", book);
}

/// Reuses the library codec without coupling serialization checks to reporting.
fn round_trip<T: Serialize + DeserializeOwned>(label: &str, value: &T) -> T {
  let bytes = encode(value).expect("serialize example value");
  let decoded: T = decode(&bytes).expect("deserialize example value");
  assert!(
    bytes == encode(&decoded).expect("reserialize example value"),
    "{label}: round trip changed the encoding"
  );
  decoded
}

/// Collect individual type sizes; print once, after the final rotation verifies.
struct SizeReport {
  enabled: bool,
  types: BTreeMap<&'static str, usize>,
  artifacts: BTreeMap<&'static str, usize>,
}

impl SizeReport {
  fn new(enabled: bool) -> Self {
    Self {
      enabled,
      types: BTreeMap::new(),
      artifacts: BTreeMap::new(),
    }
  }

  fn size<T: Serialize>(&mut self, name: &'static str, value: &T) {
    if self.enabled {
      let bytes = encode(value).expect("serialize type size report").len();
      assert!(
        self.types.insert(name, bytes).is_none(),
        "duplicate type: {name}"
      );
    }
  }

  fn artifact(&mut self, name: &'static str, bytes: usize) {
    if self.enabled {
      assert!(
        self.artifacts.insert(name, bytes).is_none(),
        "duplicate artifact: {name}"
      );
    }
  }

  fn print(&self) {
    if !self.enabled {
      return;
    }
    println!(
      "\nSerialized type sizes at rotation 3 (1 KB = 1,000 bytes; AddressBook has 3 entries):"
    );
    let name_width = self
      .types
      .keys()
      .map(|name| name.len())
      .max()
      .unwrap_or(0)
      .max(46);
    println!("{:<name_width$} {:>12}", "Type / enum variant", "KB");
    for (name, bytes) in &self.types {
      println!("{name:<name_width$} {:>12.3}", *bytes as f64 / 1000.0);
    }
    println!("\nEncoded artifacts as returned by WRAPS (excluding Vec framing):");
    println!("{:<46} {:>12}", "Artifact", "KB");
    for (name, bytes) in &self.artifacts {
      println!("{name:<46} {:>12.3}", *bytes as f64 / 1000.0);
    }
  }
}

#[derive(Default)]
struct MethodTiming {
  calls: usize,
  total: Duration,
}

/// Time direct library calls; all example-side work stays outside the timed closure.
struct TimingReport {
  enabled: bool,
  methods: BTreeMap<&'static str, MethodTiming>,
}

impl TimingReport {
  fn new(enabled: bool) -> Self {
    Self {
      enabled,
      methods: BTreeMap::new(),
    }
  }

  fn measure<T>(&mut self, method: &'static str, call: impl FnOnce() -> T) -> T {
    if !self.enabled {
      return call();
    }
    let start = Instant::now();
    let value = call();
    let elapsed = start.elapsed();
    let timing = self.methods.entry(method).or_default();
    timing.calls += 1;
    timing.total += elapsed;
    value
  }

  fn print(&self, setup: &TimingReport) {
    if !self.enabled {
      return;
    }
    // Setup and per-rotation methods are disjoint. Merge them into one sorted table.
    let mut methods = BTreeMap::new();
    for (method, timing) in setup.methods.iter().chain(self.methods.iter()) {
      assert!(
        methods.insert(*method, timing).is_none(),
        "duplicate timing: {method}"
      );
    }
    println!("\nWRAPS method timings (setup once + rotation 3; direct calls only):");
    println!("Includes internal library work; excludes example serialization and reporting.");
    println!(
      "{:<46} {:>7} {:>14} {:>14}",
      "Method", "Calls", "Total ms", "Mean ms"
    );
    for (method, timing) in methods {
      let total_ms = timing.total.as_secs_f64() * 1000.0;
      println!(
        "{method:<46} {:>7} {:>14.3} {:>14.3}",
        timing.calls,
        total_ms,
        total_ms / timing.calls as f64
      );
    }
  }
}
