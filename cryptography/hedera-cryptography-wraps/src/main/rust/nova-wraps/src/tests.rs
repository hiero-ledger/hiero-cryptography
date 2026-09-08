use super::*;
use crate::{
  poseidon::shared_constants,
  schnorr::{Keypair, Multisig, Schnorr, SchnorrNonce},
  utils::{encode_point, expand_seed, fits_in_bits, pad_bitvector},
  wraps::{
    hash_address_book, meets_threshold, pad_address_book, sentinel_pubkey, signing_subset,
    subset_weight, verify_address_book, CompressedWrapsProof, UncompressedWrapsProof,
  },
};
use ff::{Field, PrimeField};
use nova_snark::{
  frontend::{num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem},
  provider::traits::DlogGroup,
  traits::{circuit::StepCircuit, Engine},
};
use rand_core::OsRng;
use std::sync::OnceLock;

// Simulation helpers.

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
      let (sk, attested) = WRAPS::keygen(rng.gen());
      keys.push(sk);
      (
        Base::from(i as u64),
        attested,
        rng.gen_range(475u64..=525u64),
      )
    })
    .collect();

  (ab, keys)
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

  let run = |phase, i: usize, sk, r1: &[_], r2: &[_], r3: &[_]| {
    WRAPS::signing_protocol(
      phase,
      Some(seeds[i]),
      message,
      sk,
      address_book,
      bitvector,
      r1,
      r2,
      r3,
    )
    .expect("honest signers follow the protocol")
  };

  // Round 1: everyone is bound to a nonce before any nonce is revealed.
  let round1 = (0..signing_keys.len())
    .map(
      |i| match run(SigningProtocolPhase::R1, i, None, &[], &[], &[]) {
        SigningProtocolObject::ProtocolMessage(m) => m,
        _ => unreachable!("R1 returns a round-1 message"),
      },
    )
    .collect::<Vec<_>>();

  // Round 2: the openings.
  let round2 = (0..signing_keys.len())
    .map(
      |i| match run(SigningProtocolPhase::R2, i, None, &round1, &[], &[]) {
        SigningProtocolObject::ProtocolMessage(m) => m,
        _ => unreachable!("R2 returns a round-2 message"),
      },
    )
    .collect::<Vec<_>>();

  // Round 3: partial signatures over the shared challenge.
  let round3 = (0..signing_keys.len())
    .map(|i| {
      match run(
        SigningProtocolPhase::R3,
        i,
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

  match WRAPS::signing_protocol(
    SigningProtocolPhase::Aggregate,
    None,
    message,
    None,
    address_book,
    bitvector,
    &round1,
    &round2,
    &round3,
  )
  .expect("honest shares aggregate")
  {
    SigningProtocolObject::ProtocolOutput(sig) => sig,
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

/// A valid two-of-three transcript, with the middle member excluded.
struct SigningFixture {
  book: AddressBook<E2>,
  keys: Vec<SchnorrSecretKey<E2>>,
  bits: BitVector,
  message: Vec<u8>,
  seeds: [[u8; ENTROPY_SIZE]; 2],
  rounds: [Vec<SigningProtocolMessage>; 3],
}

impl SigningFixture {
  fn new() -> Self {
    let members = (1..=3u8)
      .map(|i| WRAPS::keygen([i; ENTROPY_SIZE]))
      .collect::<Vec<_>>();
    let keys = members.iter().map(|member| member.0).collect::<Vec<_>>();
    let book: AddressBook<E2> = members
      .iter()
      .enumerate()
      .map(|(i, (_, attested))| (Base::from(i as u64), attested.clone(), 1))
      .collect();
    let message = WRAPS::compute_rotation_message(&book, b"signing fixture").unwrap();
    let typed_message = decode::<RotationMessage<E2>>(&message).unwrap();
    let bits = BitVector::from(core::array::from_fn(|i| i == 0 || i == 2));
    let seeds = [[21; ENTROPY_SIZE], [22; ENTROPY_SIZE]];
    let participants = [members[0].1 .0, members[2].1 .0];
    let round1 = seeds.map(Multisig::<E2>::round1);
    let round2 = seeds.map(Multisig::<E2>::round2);
    let round3 = [0usize, 2]
      .into_iter()
      .enumerate()
      .map(|(i, member)| {
        Multisig::<E2>::round3(
          &shared_constants(),
          seeds[i],
          &typed_message,
          &keys[member],
          &participants,
          &round1,
          &round2,
        )
        .unwrap()
      })
      .collect::<Vec<_>>();
    let rounds = [
      round1
        .into_iter()
        .map(|m| encode(&RoundMessage::<E2>::Round1(m)).unwrap())
        .collect(),
      round2
        .into_iter()
        .map(|m| encode(&RoundMessage::<E2>::Round2(m)).unwrap())
        .collect(),
      round3
        .into_iter()
        .map(|m| encode(&RoundMessage::<E2>::Round3(m)).unwrap())
        .collect(),
    ];
    Self {
      book,
      keys,
      bits,
      message,
      seeds,
      rounds,
    }
  }

  fn call(
    &self,
    phase: SigningProtocolPhase,
    entropy: Option<[u8; ENTROPY_SIZE]>,
    key: Option<&SchnorrSecretKey<E2>>,
    rounds: [&[SigningProtocolMessage]; 3],
  ) -> Result<SigningProtocolObject<E2>, WrapsError> {
    WRAPS::signing_protocol(
      phase,
      entropy,
      &self.message,
      key,
      &self.book,
      self.bits,
      rounds[0],
      rounds[1],
      rounds[2],
    )
  }

  fn histories(&self) -> [&[SigningProtocolMessage]; 3] {
    [&self.rounds[0], &self.rounds[1], &self.rounds[2]]
  }
}

/// A rotation message that is well formed but stands for nothing in particular.
fn arbitrary_message() -> RotationMessage<E2> {
  [Base::from(7u64), Base::from(11u64)]
}

/// Synthesizes one step against the given witness and returns the constraint system,
/// so a test can assert on satisfiability directly instead of paying for an IVC step.
fn synthesize_step(
  prev_ab: &AddressBook<E2>,
  bitvector: BitVector,
  sig: Signature<E2>,
  msg: RotationMessage<E2>,
) -> (TestConstraintSystem<Base>, Vec<AllocatedNum<Base>>) {
  let pc = shared_constants();
  // Padding on the way in, exactly as `construct_wraps_proof` does it.
  let prev_ab = pad_address_book::<E2>(prev_ab).unwrap();
  let mut cs = TestConstraintSystem::<Base>::new();
  let z_in = [hash_address_book::<E2>(&pc, &prev_ab), Base::ZERO]
    .iter()
    .enumerate()
    .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z_in {i}")), || Ok(*v)).unwrap())
    .collect::<Vec<_>>();

  let z_out = RotationCircuit::<E2> {
    pc,
    prev_ab,
    bitvector,
    sig,
    msg,
  }
  .synthesize(&mut cs, &z_in)
  .unwrap();

  (cs, z_out)
}

// ---------------------------------------------------------------------
// Keys and proofs of knowledge
// ---------------------------------------------------------------------

#[test]
fn keygen_is_deterministic_in_its_seed() {
  use rand_core::SeedableRng;

  let seed = [7u8; ENTROPY_SIZE];
  let generated = WRAPS::keygen(seed);
  assert_eq!(generated, WRAPS::keygen(seed));

  let (sk, (pk, pok)) = generated;
  let (other_sk, (other_pk, other_pok)) = WRAPS::keygen([8u8; ENTROPY_SIZE]);
  assert_ne!(sk, other_sk);
  assert_ne!(pk, other_pk);
  assert_ne!(pok, other_pok);
  assert!(Schnorr::<E2>::verify_knowledge(&pk, &pok));
  assert!(Schnorr::<E2>::verify_knowledge(&other_pk, &other_pok));

  // Branch 0 samples the secret; branch 1 independently samples the PoK nonce.
  let [key_seed, pok_seed] = expand_seed(seed);
  let expected_sk =
    SchnorrSecretKey::<E2>::random(&mut rand_chacha::ChaCha20Rng::from_seed(key_seed));
  let expected_nonce =
    SchnorrNonce::<E2>::random(&mut rand_chacha::ChaCha20Rng::from_seed(pok_seed));
  let generator = <E2 as Engine>::GE::gen();
  assert_eq!(sk, expected_sk);
  assert_eq!(pk, generator * expected_sk);
  assert_eq!(pok.commitment, generator * expected_nonce);
  assert_ne!(pok.commitment, pk, "the key and nonce streams must differ");
}

#[test]
fn keygen_seed_expansion_matches_sha256_known_answer() {
  // Independently computed with Python hashlib.sha256(bytes([7]) * 32 +
  // bytes([counter])).digest(), for the one-byte counters 0 and 1.
  assert_eq!(
    expand_seed([7u8; ENTROPY_SIZE]),
    [
      [
        0x15, 0x63, 0x24, 0xad, 0xc0, 0xa9, 0xd5, 0x3a, 0xce, 0x5a, 0x8e, 0x2a, 0xc1, 0xf6, 0xa4,
        0x33, 0x17, 0x90, 0x0a, 0xa2, 0x09, 0xb1, 0x40, 0x71, 0x2e, 0xf3, 0x8f, 0x0a, 0x53, 0xc6,
        0x78, 0x4d,
      ],
      [
        0x84, 0x2e, 0xf3, 0xc3, 0xb4, 0xe4, 0xa5, 0xb4, 0x77, 0x25, 0x7c, 0xff, 0x94, 0x6c, 0xda,
        0xf6, 0x9f, 0xbe, 0x8c, 0x73, 0x93, 0x95, 0xf2, 0xb2, 0xe0, 0x92, 0x03, 0x9b, 0x83, 0x0e,
        0xb6, 0x90,
      ],
    ],
  );
}

#[test]
fn proof_of_knowledge_sha256_mod_known_answer() {
  use sha2::{Digest, Sha256};

  // Independently derived with integer arithmetic on y^2 = x^3 - 17 and
  // Python hashlib: G, pk = 2G, commitment = 3G, each encoded as three
  // canonical 32-byte little-endian field elements (x, y, infinity).
  let generator = <E2 as Engine>::GE::gen();
  let pk = generator * SchnorrSecretKey::<E2>::from(2u64);
  let commitment = generator * SchnorrNonce::<E2>::from(3u64);
  let mut transcript = b"WRAPS-schnorr-pok-sha256-mod-v4".to_vec();
  for point in [generator, pk, commitment] {
    for element in encode_point::<E2>(&point) {
      transcript.extend_from_slice(element.to_repr().as_ref());
    }
  }
  assert_eq!(transcript.len(), 319);
  let digest: [u8; 32] = Sha256::digest(&transcript).into();
  assert_eq!(
    digest,
    [
      0x31, 0x34, 0x74, 0x9a, 0x54, 0xfe, 0x19, 0x14, 0x0d, 0x2a, 0x3d, 0x51, 0xa6, 0x3b, 0x0a,
      0x98, 0x4a, 0x75, 0xae, 0xbf, 0x2a, 0x2c, 0xee, 0x76, 0x7a, 0xd9, 0x32, 0x70, 0xbd, 0x33,
      0xa2, 0x6d,
    ]
  );

  // The digest integer exceeds the scalar modulus, so the fixture must
  // exercise reduction rather than merely embed an already-small value.
  // Grumpkin's canonical scalar representation is little-endian.
  let mut digest_repr = <SchnorrPoKChallenge<E2> as PrimeField>::Repr::default();
  for (target, byte) in digest_repr.as_mut().iter_mut().zip(digest.iter().rev()) {
    *target = *byte;
  }
  assert!(bool::from(
    SchnorrPoKChallenge::<E2>::from_repr(digest_repr).is_none()
  ));

  // Interpret all 32 bytes as a big-endian integer modulo the Grumpkin
  // scalar order. The expected remainder has 248 bits.
  let challenge = SchnorrPoKChallenge::<E2>::from_str_vartime(
    "367767519468030578647326648728420925774146699493422225493741190979981321510",
  )
  .unwrap();
  assert!(!fits_in_bits(&challenge, 224));
  assert_eq!(Schnorr::<E2>::pok_challenge(&pk, &commitment), challenge);
  let pok = SchnorrPoK {
    commitment,
    challenge,
    response: SchnorrResponse::<E2>::from_str_vartime(
      "735535038936061157294653297456841851548293398986844450987482381959962643023",
    )
    .unwrap(),
  };
  assert!(Schnorr::<E2>::verify_knowledge(&pk, &pok));

  let restored: SchnorrPoK<E2> = decode(&encode(&pok).unwrap()).unwrap();
  assert_eq!(restored, pok);
  assert!(Schnorr::<E2>::verify_knowledge(&pk, &restored));
}

#[test]
fn proof_of_knowledge_rejects_previous_hash_suites() {
  let generator = <E2 as Engine>::GE::gen();
  let pk = generator * SchnorrSecretKey::<E2>::from(2u64);
  // Known proofs for the former SHA-256-v1, SHA-256-XMD-v2, and SHA-224-v3
  // suites, all with pk = 2G and commitment = 3G. Their response equations
  // hold, but v4 must rederive its own challenge rather than accept them.
  for (challenge, response) in [
    (
      "164233662700517953597573855129836218885",
      "328467325401035907195147710259672437773",
    ),
    (
      "783935678375889246394801688009063047002083270929865452545591975562234022787",
      "1567871356751778492789603376018126094004166541859730905091183951124468045577",
    ),
    (
      "6613386075054679280527479911590346531607287069682128975559063053003",
      "13226772150109358561054959823180693063214574139364257951118126106009",
    ),
  ] {
    let legacy = SchnorrPoK {
      commitment: generator * SchnorrNonce::<E2>::from(3u64),
      challenge: SchnorrPoKChallenge::<E2>::from_str_vartime(challenge).unwrap(),
      response: SchnorrResponse::<E2>::from_str_vartime(response).unwrap(),
    };
    assert_eq!(
      generator * legacy.response,
      legacy.commitment + pk * legacy.challenge
    );
    assert!(!Schnorr::<E2>::verify_knowledge(&pk, &legacy));
  }
}

#[test]
fn proof_of_knowledge_rejects_tampered_fields() {
  let (_, (pk, pok)) = WRAPS::keygen([19u8; ENTROPY_SIZE]);
  assert!(Schnorr::<E2>::verify_knowledge(&pk, &pok));

  let mut changed_commitment = pok.clone();
  changed_commitment.commitment += <E2 as Engine>::GE::gen();
  let mut changed_challenge = pok.clone();
  changed_challenge.challenge += SchnorrPoKChallenge::<E2>::ONE;
  let mut changed_response = pok.clone();
  changed_response.response += SchnorrResponse::<E2>::ONE;
  for changed in [changed_commitment, changed_challenge, changed_response] {
    assert!(!Schnorr::<E2>::verify_knowledge(&pk, &changed));
  }
}

#[test]
fn proof_of_knowledge_binds_a_key_to_its_secret() {
  let (_, (pk, pok)) = WRAPS::keygen([1u8; ENTROPY_SIZE]);
  assert!(Schnorr::<E2>::verify_knowledge(&pk, &pok));

  // A proof does not carry over to another key ...
  let (_, (other_pk, other_pok)) = WRAPS::keygen([2u8; ENTROPY_SIZE]);
  assert!(!Schnorr::<E2>::verify_knowledge(&other_pk, &pok));

  // ... and a rogue key, chosen to cancel others rather than generated, has no proof
  // at all: its discrete log is not known to whoever published it.
  let rogue = other_pk - pk;
  assert!(!Schnorr::<E2>::verify_knowledge(&rogue, &other_pok));
  assert!(!Schnorr::<E2>::verify_knowledge(&rogue, &pok));
}

#[test]
fn sentinel_key_is_the_identity_and_never_carries_weight() {
  let (pk, pok) = WRAPS::sentinel_keygen();
  assert_eq!(pk, WRAPS::sentinel_keygen().0);
  assert!(
    pk.to_coordinates().2,
    "the sentinel is the point at infinity"
  );

  // Its placeholder proof is not a real one, and is never checked ...
  assert!(!Schnorr::<E2>::verify_knowledge(&pk, &pok));

  // ... so a book of nothing but empty seats validates.
  let ab: AddressBook<E2> = (0..MAX_AB_SIZE)
    .map(|i| (Base::from(i as u64), WRAPS::sentinel_keygen(), 0))
    .collect();
  assert!(verify_address_book::<E2>(&ab));

  // Even the maximum 64-bit weight on an empty seat contributes to neither sum.
  let mut weighted = ab.clone();
  weighted[3].2 = u64::MAX;
  assert!(verify_address_book::<E2>(&weighted));
  assert!(WRAPS::compute_addressbook_hash(&weighted).is_ok());
  assert_eq!(
    subset_weight::<E2>(&weighted, &[true; MAX_AB_SIZE].into()),
    Some((0, 0)),
    "an empty seat contributes to neither sum, whatever its entry says"
  );

  // A real key in a seat, at any weight, still owes a proof of possession.
  let mut tampered = ab.clone();
  tampered[3].1 .0 = <E2 as Engine>::GE::gen();
  assert!(!verify_address_book::<E2>(&tampered));
}

#[test]
fn weights_use_exactly_eight_bytes() {
  for weight in [0, 1, u64::MAX] {
    let weight: Weight = weight;
    let encoded = encode(&weight).unwrap();
    assert_eq!(encoded, weight.to_le_bytes());
    assert_eq!(decode::<Weight>(&encoded).unwrap(), weight);
    assert!(decode::<Weight>(&encoded[..7]).is_err());
    assert!(decode::<Weight>(&[encoded, vec![0]].concat()).is_err());
  }

  let f = SigningFixture::new();
  let entry = &f.book[0];
  assert_eq!(
    encode(entry).unwrap().len(),
    encode(&entry.0).unwrap().len() + encode(&entry.1).unwrap().len() + 8,
    "the address-book representation contains an eight-byte weight"
  );
}

#[test]
fn maximum_weight_is_accepted_natively_and_in_circuit() {
  let f = SigningFixture::new();
  let mut book = f.book[..1].to_vec();
  book[0].2 = u64::MAX;
  let bits = BitVector::from(core::array::from_fn(|i| i == 0));
  assert!(verify_address_book::<E2>(&book));
  assert!(WRAPS::compute_addressbook_hash(&book).is_ok());
  assert_eq!(
    subset_weight::<E2>(&book, &bits),
    Some((u64::MAX, u64::MAX))
  );

  let msg = arbitrary_message();
  let signature = threshold_sign(&encode(&msg).unwrap(), &book, &f.keys[..1], &bits);
  assert!(WRAPS::verify_signature(&book, &encode(&msg).unwrap(), &signature).unwrap());
  let (cs, _) = synthesize_step(&book, bits, signature.1, msg);
  assert!(cs.is_satisfied(), "{:?}", cs.which_is_unsatisfied());
}

#[test]
fn overflowing_total_weight_is_rejected_natively_and_in_circuit() {
  let f = SigningFixture::new();
  let mut book = f.book[..2].to_vec();
  book[0].2 = u64::MAX;
  book[1].2 = 1;
  let bits = BitVector::from(core::array::from_fn(|i| i < book.len()));
  assert!(!verify_address_book::<E2>(&book));
  assert!(WRAPS::compute_addressbook_hash(&book).is_err());
  assert!(subset_weight::<E2>(&book, &bits).is_none());

  // Obtain a sound signature under the same keys from a valid book; the witness book
  // itself is rejected by native signing before it could produce a transcript.
  let msg = arbitrary_message();
  let valid_book = f.book[..2].to_vec();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &valid_book, &f.keys[..2], &bits);
  assert!(!WRAPS::verify_signature(&book, &encode(&msg).unwrap(), &(bits, sig.clone())).unwrap());
  let (cs, _) = synthesize_step(&book, bits, sig, msg);
  assert!(!cs.is_satisfied());
  assert!(cs
    .which_is_unsatisfied()
    .is_some_and(|path| path.contains("total weight") && path.contains("range")));

  // An empty seat contributes nothing even when its stored weight is maximal.
  book[1].1 = WRAPS::sentinel_keygen();
  book[1].2 = u64::MAX;
  assert!(verify_address_book::<E2>(&book));
  assert_eq!(
    subset_weight::<E2>(&book, &bits),
    Some((u64::MAX, u64::MAX))
  );
}

#[test]
fn address_book_hash_commits_to_every_field_of_every_entry() {
  let pc = shared_constants();
  let (ab, _) = random_address_book();
  let ab = pad_address_book::<E2>(&ab).unwrap();
  let base = hash_address_book::<E2>(&pc, &ab);

  // Each of the five elements an entry contributes moves the hash.
  let mut changed_key = ab.clone();
  changed_key[5].1 .0 = WRAPS::keygen([99u8; ENTROPY_SIZE]).1 .0;
  let mut changed_weight = ab.clone();
  changed_weight[5].2 += 1;
  let mut changed_node_id = ab.clone();
  changed_node_id[5].0 += Base::ONE;
  for perturbed in [&changed_key, &changed_weight, &changed_node_id] {
    assert_ne!(base, hash_address_book::<E2>(&pc, perturbed));
  }

  // The proof of knowledge is deliberately *not* covered: it attests the key, and the
  // key is what the state commits to.
  let mut reproved = ab.clone();
  reproved[5].1 .1 = Schnorr::<E2>::prove_knowledge(
    &Keypair {
      sk: SchnorrSecretKey::<E2>::ZERO,
      pk: reproved[5].1 .0,
    },
    &mut OsRng,
  );
  assert_eq!(base, hash_address_book::<E2>(&pc, &reproved));

  // Node id and weight occupy distinct positions, so swapping them within an entry is
  // a different book even when the pair of values is the same.
  let mut swapped = ab.clone();
  let weight = swapped[5].2;
  swapped[5].2 = 5;
  swapped[5].0 = Base::from(weight);
  assert_ne!(base, hash_address_book::<E2>(&pc, &swapped));
}

#[test]
fn hints_vk_hash_binds_length_and_every_byte() {
  // Zero-padding the last word must not erase the key's original length, including
  // immediately before and after an 8-byte boundary.
  let mut zero_hashes = Vec::new();
  for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32] {
    let hash = WRAPS::compute_hints_vk_hash(vec![0u8; len]);
    assert!(
      !zero_hashes.contains(&hash),
      "zero-filled keys of different lengths must have distinct hashes"
    );
    zero_hashes.push(hash);
  }

  // Exercise two full words and a partial word. Every byte, including each word's
  // high byte, must affect the hash; a zero suffix must remain significant too.
  let key = [0xffu8; 17];
  let hash = WRAPS::compute_hints_vk_hash(key);
  for i in 0..key.len() {
    let mut changed = key;
    changed[i] ^= 0x80;
    assert_ne!(hash, WRAPS::compute_hints_vk_hash(changed), "byte {i}");
  }
  let mut extended = key.to_vec();
  extended.push(0);
  assert_ne!(hash, WRAPS::compute_hints_vk_hash(extended));
}

#[test]
fn padding_makes_short_books_indistinguishable_from_their_padded_form() {
  let (ab, _) = random_address_book();
  assert!(ab.len() < MAX_AB_SIZE || ab.len() == MAX_AB_SIZE);

  // Hashing a book and hashing it after padding give the same commitment, because
  // `compute_addressbook_hash` pads on the way in.
  let padded = pad_address_book::<E2>(&ab).unwrap();
  assert_eq!(padded.len(), MAX_AB_SIZE);
  assert_eq!(
    WRAPS::compute_addressbook_hash(&ab).unwrap(),
    WRAPS::compute_addressbook_hash(&padded).unwrap(),
    "a committee's commitment must not depend on how many seats it fills"
  );

  // Padding is idempotent, so a book that has already been padded is left alone.
  assert_eq!(padded, pad_address_book::<E2>(&padded).unwrap());

  // Padding seats carry no weight, so they cannot move a threshold ...
  let bits = sufficient_bitvector(ab.len());
  let (signing_short, total_short) = subset_weight::<E2>(&ab, &bits).unwrap();
  let (signing_padded, total_padded) = subset_weight::<E2>(&padded, &bits).unwrap();
  assert_eq!((signing_short, total_short), (signing_padded, total_padded));

  // ... and are never named by a padded bitvector, so they never join the joint key.
  assert_eq!(
    signing_subset(&ab, &bits).len(),
    signing_subset(&padded, &bits).len()
  );
  assert!(
    pad_bitvector(&vec![true; ab.len()]).unwrap()[ab.len()..]
      .iter()
      .all(|bit| !bit),
    "a seat that does not exist did not sign"
  );
}

#[test]
fn oversized_books_and_bitvectors_are_refused() {
  let (ab, _) = random_address_book();
  let mut too_big = pad_address_book::<E2>(&ab).unwrap();
  too_big.push(too_big[0].clone());

  assert!(!verify_address_book::<E2>(&too_big));
  assert!(pad_address_book::<E2>(&too_big).is_err());
  assert!(WRAPS::compute_addressbook_hash(&too_big).is_err());
  assert!(pad_bitvector(&[true; MAX_AB_SIZE + 1]).is_err());
}

/// A book may hold identity keys at any 64-bit weight, because that weight never counts —
/// on either side of the threshold.
///
/// The identity is the additive unit, so a seat holding it contributes nothing to a
/// joint key and anyone can "sign" for it. That would be a free majority if its weight
/// were counted, so the weight rule drops it: out of the signing subset, and out of
/// the total it is measured against. Once it reaches neither sum there is nothing left
/// for `verify_address_book` to refuse.
#[test]
fn identity_seats_are_accepted_and_contribute_to_neither_sum() {
  let pc = shared_constants();
  let identity = <E2 as Engine>::GE::gen() * SchnorrSecretKey::<E2>::ZERO;
  // The sentinel *is* the identity, which is safe precisely because of the rule this
  // test pins down: an empty seat may hold any 64-bit weight because it claims nothing.
  assert_eq!(sentinel_pubkey::<E2>(), identity);

  // Its proof of knowledge is forgeable by anyone: `z·G == commitment + e·O` collapses
  // to `z·G == commitment`, so the exemption a sentinel needs would be meaningless.
  let forged = Schnorr::<E2>::prove_knowledge(
    &Keypair {
      sk: SchnorrSecretKey::<E2>::ZERO,
      pk: identity,
    },
    &mut OsRng,
  );
  assert!(Schnorr::<E2>::verify_knowledge(&identity, &forged));

  // Adding identity seats to a signing subset leaves the joint key untouched ...
  let (ab, keys) = random_address_book();
  let real = signing_subset(&ab, &sufficient_bitvector(ab.len()));
  let padded_out = [real.clone(), vec![identity, identity]].concat();
  assert_eq!(
    Multisig::<E2>::aggregate_key(&real).unwrap(),
    Multisig::<E2>::aggregate_key(&padded_out).unwrap()
  );

  // ... so a signature from the real signers alone also verifies for a subset that
  // claims every empty seat as well, picking up their weight for nothing.
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(
    &encode(&msg).unwrap(),
    &ab,
    &keys,
    &sufficient_bitvector(ab.len()),
  );
  let mut inflated_book = ab.clone();
  let mut inflated_bits = sufficient_bitvector(ab.len());
  for i in 0..ab.len() {
    if !inflated_bits[i] {
      inflated_book[i].1 .0 = identity;
      inflated_bits[i] = true;
    }
  }
  assert!(
    Schnorr::<E2>::verify(
      &pc,
      &Multisig::<E2>::aggregate_key(&signing_subset(&inflated_book, &inflated_bits)).unwrap(),
      &msg,
      &sig
    ),
    "an identity seat leaves the joint key untouched, so nobody has to sign for it"
  );

  // The book is accepted: the weight on those blanked seats is weight nobody can pick
  // up, since neither `subset_weight` nor the circuit counts it.
  assert!(verify_address_book::<E2>(&inflated_book));
  assert!(WRAPS::compute_addressbook_hash(&inflated_book).is_ok());

  // What it holds is the live seats and nothing else, on *both* sides of the
  // threshold — which is why claiming a blanked seat gains the claimant nothing.
  let live = ab
    .iter()
    .zip(sufficient_bitvector(ab.len()))
    .filter_map(|(entry, signed)| signed.then_some(entry.2))
    .sum::<Weight>();
  assert_eq!(
    subset_weight::<E2>(&inflated_book, &inflated_bits),
    Some((live, live))
  );

  // Zeroing those seats' weight is therefore a no-op as far as every rule is
  // concerned ...
  let mut emptied = inflated_book.clone();
  for entry in emptied.iter_mut() {
    if entry.1 .0.to_coordinates().2 {
      entry.2 = 0;
    }
  }
  assert!(verify_address_book::<E2>(&emptied));
  assert_eq!(
    subset_weight::<E2>(&emptied, &inflated_bits),
    Some((live, live)),
    "zeroing weight the rules already ignore must change nothing"
  );

  // ... but not as far as the *commitment* is concerned. `H(ab)` covers the raw
  // weight of every entry, ignored or not, so the two books are different states.
  assert_ne!(
    hash_address_book::<E2>(&pc, &pad_address_book::<E2>(&inflated_book).unwrap()),
    hash_address_book::<E2>(&pc, &pad_address_book::<E2>(&emptied).unwrap()),
    "the book's hash commits to weight the weight rules discard"
  );

  // The circuit reaches the same verdict by a different route: it strips the blanked
  // seats out of the *total* as well as out of the signing subset, so what is left is
  // a book of live seats every one of which signed. Claiming a dead seat is a no-op
  // rather than an attack, which is why the step is satisfied here.
  // `weight_on_a_seat_keyed_to_the_point_at_infinity_is_ignored` is the case that
  // tells the two rules apart.
  let (cs, _) = synthesize_step(&inflated_book, inflated_bits, sig, msg);
  assert!(
    cs.is_satisfied(),
    "unsatisfied: {:?}",
    cs.which_is_unsatisfied()
  );
}

/// Weight parked on a seat nobody can sign for must not count — not for the subset
/// claiming it, and not for the total it is measured against.
///
/// The identity contributes nothing to a joint key, so a signature over a subset that
/// claims identity seats is the same signature as one over the live seats alone. If
/// those seats' weight were counted, a minority could claim them and rotate.
#[test]
fn weight_on_a_seat_keyed_to_the_point_at_infinity_is_ignored() {
  let pc = shared_constants();

  // Twelve seats of weight 1. Four sign: a third of the book, well short of half.
  const SEATS: usize = 12;
  const SIGNERS: usize = 4;
  let mut keys = Vec::with_capacity(SEATS);
  let ab: AddressBook<E2> = (0..SEATS)
    .map(|i| {
      let (sk, attested) = WRAPS::keygen([i as u8; ENTROPY_SIZE]);
      keys.push(sk);
      (Base::from(i as u64), attested, 1)
    })
    .collect();
  let signing_bits = BitVector::from(core::array::from_fn(|i| i < SIGNERS));
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &signing_bits);

  // Four of twelve is refused, as it should be.
  let (cs, _) = synthesize_step(&ab, signing_bits, sig.clone(), msg);
  assert!(!cs.is_satisfied());

  // Now blank out four seats that did *not* sign — keeping their weight — and claim
  // them. A rule that counted their weight would see eight of twelve and let this
  // through.
  let mut blanked = ab.clone();
  let mut claimed = signing_bits;
  for entry in blanked.iter_mut().take(SIGNERS * 2).skip(SIGNERS) {
    entry.1 = WRAPS::sentinel_keygen();
  }
  for bit in claimed.iter_mut().take(SIGNERS * 2).skip(SIGNERS) {
    *bit = true;
  }

  // The signature still verifies: the blanked seats add nothing to the joint key, so
  // it is the same key the four real signers produced a signature under. Whatever
  // stops this cannot be the signature check.
  let padded = pad_address_book::<E2>(&blanked).unwrap();
  assert!(Schnorr::<E2>::verify(
    &pc,
    &Multisig::<E2>::aggregate_key(&signing_subset(&padded, &claimed)).unwrap(),
    &msg,
    &sig
  ));

  // Natively, the four dead seats are in neither sum: eight live seats, four signing.
  let (signing, total) = subset_weight::<E2>(&padded, &claimed).unwrap();
  assert_eq!(
    (signing, total),
    (SIGNERS as u64, (SEATS - SIGNERS) as u64),
    "an identity seat contributes to neither the subset nor the total"
  );
  assert!(!meets_threshold(&signing, &total), "four of eight is a tie");

  // And the circuit draws the line in the same place, on the weight rather than on
  // the signature.
  let (cs, _) = synthesize_step(&blanked, claimed, sig, msg);
  assert!(!cs.is_satisfied());
  assert!(cs
    .which_is_unsatisfied()
    .is_some_and(|path| path.contains("majority of the weight")));
}

/// The effective-weight rule is written against the point at infinity, and the
/// sentinel is the point at infinity, so the rule covers every entry keyed to the
/// sentinel. This pins that equivalence: if the sentinel ever stops being the
/// identity, the rule stops covering it and this test says so.
#[test]
fn sentinel_is_the_identity_so_the_weight_rule_covers_it() {
  let sentinel = sentinel_pubkey::<E2>();
  assert!(sentinel.to_coordinates().2);

  // The two ways of asking agree, including on an identity that was arrived at by
  // arithmetic rather than constructed directly.
  let real = Schnorr::<E2>::keygen(&mut OsRng).pk;
  let arrived_at = real - real;
  for pk in [sentinel, arrived_at, real] {
    assert_eq!(
      pk == sentinel,
      pk.to_coordinates().2,
      "the two predicates disagree"
    );
  }

  // A seat keyed to the sentinel is accepted at any 64-bit weight, and carries
  // none of it into either sum.
  let mut ab = random_address_book().0;
  ab[2].1 = WRAPS::sentinel_keygen();
  ab[2].2 = 0;
  let bits = BitVector::from(core::array::from_fn(|i| i < ab.len()));
  let baseline = subset_weight::<E2>(&ab, &bits);
  assert!(verify_address_book::<E2>(&ab));

  for weight in [1, u64::MAX] {
    let mut weighted = ab.clone();
    weighted[2].2 = weight;
    assert!(
      verify_address_book::<E2>(&weighted),
      "an empty seat is accepted whatever weight it carries"
    );
    assert!(WRAPS::compute_addressbook_hash(&weighted).is_ok());
    assert_eq!(
      subset_weight::<E2>(&weighted, &bits),
      baseline,
      "the sentinel seat's weight reached a sum it must not touch"
    );
  }
}

#[test]
fn address_book_hash_commits_to_order() {
  let pc = shared_constants();
  let (ab, _) = random_address_book();
  let ab = pad_address_book::<E2>(&ab).unwrap();
  let mut permuted = ab.clone();
  permuted.swap(0, 1);

  assert_ne!(
    hash_address_book::<E2>(&pc, &ab),
    hash_address_book::<E2>(&pc, &permuted)
  );
}

// ---------------------------------------------------------------------
// The multisignature
// ---------------------------------------------------------------------

#[test]
fn aggregate_is_an_ordinary_schnorr_signature_over_the_signing_subset() {
  let pc = shared_constants();
  let (ab, keys) = random_address_book();
  let bitvector = sufficient_bitvector(ab.len());
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);

  // Nothing downstream can tell that 43 parties produced this rather than one.
  let joint = Multisig::<E2>::aggregate_key(&signing_subset(&ab, &bitvector)).unwrap();
  assert!(Schnorr::<E2>::verify(&pc, &joint, &msg, &sig));

  // The subset is what it speaks for: the joint key of the whole book does not verify.
  let everyone = signing_subset(&ab, &[true; MAX_AB_SIZE].into());
  let all_joint = Multisig::<E2>::aggregate_key(&everyone).unwrap();
  assert!(!Schnorr::<E2>::verify(&pc, &all_joint, &msg, &sig));

  // Nor does another message.
  assert!(!Schnorr::<E2>::verify(
    &pc,
    &joint,
    &[Base::ONE, Base::ZERO],
    &sig
  ));
}

#[test]
fn nonce_commitments_are_deterministic_and_distinguish_nonces() {
  let a = <E2 as Engine>::GE::gen() * SchnorrNonce::<E2>::random(&mut OsRng);
  let b = <E2 as Engine>::GE::gen() * SchnorrNonce::<E2>::random(&mut OsRng);

  // Deterministic, so every signer recomputing an opening lands on the same digest.
  assert_eq!(
    Multisig::<E2>::commit_nonce(&a),
    Multisig::<E2>::commit_nonce(&a)
  );
  // ... and binding in the sense the protocol needs: different nonces, different
  // commitments, so an opening cannot be swapped after the fact.
  assert_ne!(
    Multisig::<E2>::commit_nonce(&a),
    Multisig::<E2>::commit_nonce(&b)
  );

  // The negation shares a coordinate with the point, so it is the case a commitment to
  // the x-coordinate alone would miss.
  assert_ne!(
    Multisig::<E2>::commit_nonce(&a),
    Multisig::<E2>::commit_nonce(&-a)
  );

  // Round 1 is the commitment, so it inherits all of that.
  let seed = [5u8; ENTROPY_SIZE];
  assert_eq!(
    Multisig::<E2>::round1(seed),
    Multisig::<E2>::commit_nonce(&(<E2 as Engine>::GE::gen() * Multisig::<E2>::nonce(seed)))
  );
}

#[test]
fn signing_protocol_rejects_a_nonce_that_does_not_open_its_commitment() {
  use rand::Rng;
  let pc = shared_constants();
  let (ab, keys) = random_address_book();
  let bitvector = sufficient_bitvector(ab.len());
  let participants = signing_subset(&ab, &bitvector);
  let n = participants.len();
  let msg = arbitrary_message();

  let seeds = (0..n)
    .map(|_| rand::thread_rng().gen::<[u8; ENTROPY_SIZE]>())
    .collect::<Vec<_>>();
  let round1 = seeds
    .iter()
    .map(|s| Multisig::<E2>::round1(*s))
    .collect::<Vec<_>>();
  let mut round2 = seeds
    .iter()
    .map(|s| Multisig::<E2>::round2(*s))
    .collect::<Vec<_>>();

  // A signer who tries to choose its nonce after seeing the others is caught in round
  // 3 by every other signer, not only by the aggregator.
  round2[1].nonce_point = <E2 as Engine>::GE::gen() * SchnorrNonce::<E2>::random(&mut OsRng);
  let signing_key = keys
    .iter()
    .zip(bitvector.iter())
    .find_map(|(sk, &signed)| signed.then_some(sk))
    .unwrap();
  let err = Multisig::<E2>::round3(
    &pc,
    seeds[0],
    &msg,
    signing_key,
    &participants,
    &round1,
    &round2,
  )
  .unwrap_err();
  assert!(
    format!("{err}").contains("signer 1"),
    "the faulty signer should be named, got: {err}"
  );
}

#[test]
fn one_seed_per_instance_spans_all_three_rounds() {
  use rand::Rng;
  let pc = shared_constants();
  let (ab, keys) = random_address_book();
  let bitvector = sufficient_bitvector(ab.len());
  let participants = signing_subset(&ab, &bitvector);
  let n = participants.len();
  let msg = arbitrary_message();
  let signing_key = keys
    .iter()
    .zip(bitvector.iter())
    .find_map(|(sk, &signed)| signed.then_some(sk))
    .unwrap();

  let seeds = (0..n)
    .map(|_| rand::thread_rng().gen::<[u8; ENTROPY_SIZE]>())
    .collect::<Vec<_>>();
  let round1 = seeds
    .iter()
    .map(|s| Multisig::<E2>::round1(*s))
    .collect::<Vec<_>>();

  // Carrying the seed forward is what makes round 2 open round 1: the rounds hold no
  // state, so the nonce has to come back out of the same entropy.
  let round2 = seeds
    .iter()
    .map(|s| Multisig::<E2>::round2(*s))
    .collect::<Vec<_>>();
  assert!(Multisig::<E2>::round3(
    &pc,
    seeds[0],
    &msg,
    signing_key,
    &participants,
    &round1,
    &round2
  )
  .is_ok());

  // Switching seeds mid-instance breaks it, and is caught as a failed opening rather
  // than silently producing an unverifiable signature.
  let mut divergent = round2.clone();
  divergent[0] = Multisig::<E2>::round2(rand::thread_rng().gen());
  let err = Multisig::<E2>::round3(
    &pc,
    seeds[0],
    &msg,
    signing_key,
    &participants,
    &round1,
    &divergent,
  )
  .unwrap_err();
  assert!(
    format!("{err}").contains("signer 0"),
    "expected signer 0's opening to fail, got: {err}"
  );

  // Across instances the seed must change, and nothing in the API can enforce that —
  // reusing one silently repeats the nonce, which is what the contract forbids.
  let other_instance = Multisig::<E2>::round1(seeds[0]);
  assert_eq!(
    other_instance, round1[0],
    "a repeated seed repeats the nonce commitment; the caller owns this"
  );
}

#[test]
fn signing_protocol_enforces_its_round_order() {
  use SigningProtocolPhase::{Aggregate, R1, R2, R3};
  let f = SigningFixture::new();
  let seed = Some(f.seeds[0]);
  let key = Some(&f.keys[0]);
  let phases = [R1, R2, R3, Aggregate];

  // A signer can commit before receiving the book or rotation message.
  assert_eq!(
    WRAPS::signing_protocol(R1, seed, [], None, &vec![], [], &[], &[], &[]).unwrap(),
    SigningProtocolObject::ProtocolMessage(f.rounds[0][0].clone())
  );
  assert_eq!(
    WRAPS::signing_protocol(R2, seed, [], None, &f.book, f.bits, &f.rounds[0], &[], &[]).unwrap(),
    SigningProtocolObject::ProtocolMessage(f.rounds[1][0].clone())
  );
  assert_eq!(
    decode::<RotationMessage<E2>>(&f.message).unwrap(),
    [
      WRAPS::compute_addressbook_hash(&f.book).unwrap(),
      WRAPS::compute_hints_vk_hash(b"signing fixture"),
    ]
  );
  for (index, phase) in phases.into_iter().enumerate() {
    let entropy = (phase != Aggregate).then_some(f.seeds[0]);
    let signing_key = (phase == R3).then_some(&f.keys[0]);
    let histories: [&[SigningProtocolMessage]; 3] = core::array::from_fn(|round| {
      if round < index {
        &f.rounds[round][..]
      } else {
        &[]
      }
    });
    let output = f.call(phase, entropy, signing_key, histories).unwrap();
    if index < 3 {
      assert_eq!(
        output,
        SigningProtocolObject::ProtocolMessage(f.rounds[index][0].clone())
      );
    } else {
      let SigningProtocolObject::ProtocolOutput(signature) = output else {
        panic!("aggregation must return a signature")
      };
      assert!(WRAPS::verify_signature(&f.book, &f.message, &signature).unwrap());
    }

    // Exactly one prior message per selected seat, and none from future rounds.
    for round in 0..3 {
      let mut wrong = histories;
      wrong[round] = if round < index {
        &f.rounds[round][..1]
      } else {
        &f.rounds[round]
      };
      assert!(
        f.call(phase, entropy, signing_key, wrong).is_err(),
        "{phase:?}, round {round}"
      );
      if round < index {
        let mut extra = f.rounds[round].clone();
        extra.push(extra[0].clone());
        wrong[round] = &extra;
        assert!(f.call(phase, entropy, signing_key, wrong).is_err());
      }
    }
    if phase != Aggregate {
      assert!(f.call(phase, None, signing_key, histories).is_err());
    } else {
      // Aggregation ignores both a signer's session entropy and unrelated entropy.
      for provided_entropy in [f.seeds[0], [99; ENTROPY_SIZE]] {
        assert_eq!(
          f.call(phase, Some(provided_entropy), None, histories)
            .unwrap(),
          f.call(phase, None, None, histories).unwrap()
        );
      }
    }
    if phase == R3 {
      assert!(f.call(phase, entropy, None, histories).is_err());
    } else {
      assert_eq!(
        f.call(phase, entropy, key, histories).unwrap(),
        f.call(phase, entropy, None, histories).unwrap()
      );
    }
  }
}

#[test]
fn signing_protocol_rejects_malformed_or_wrong_round_bytes() {
  use SigningProtocolPhase::{Aggregate, R2, R3};
  let f = SigningFixture::new();

  for (round, phase) in [R2, R3, Aggregate].into_iter().enumerate() {
    let mut truncated = f.rounds[round][0].clone();
    truncated.pop();
    let mut trailing = f.rounds[round][0].clone();
    trailing.push(0);
    for malformed in [
      Vec::new(),
      truncated,
      trailing,
      vec![255; 4],
      f.rounds[(round + 1) % 3][0].clone(),
    ] {
      let mut histories = f.rounds.clone();
      histories[round][0] = malformed;
      for future in histories.iter_mut().skip(round + 1) {
        future.clear();
      }
      assert!(matches!(
        f.call(
          phase,
          (phase != Aggregate).then_some(f.seeds[0]),
          (phase == R3).then_some(&f.keys[0]),
          [&histories[0], &histories[1], &histories[2]],
        ),
        Err(WrapsError::InvalidInput(_))
      ));
    }
  }

  let SigningProtocolObject::ProtocolOutput(signature) =
    f.call(Aggregate, None, None, f.histories()).unwrap()
  else {
    unreachable!()
  };
  assert_eq!(f.message.len(), 64);
  let mut trailing = f.message.clone();
  trailing.push(0);
  for malformed in [
    Vec::new(),
    f.message[..63].to_vec(),
    trailing,
    vec![255; 64],
  ] {
    for phase in [R3, Aggregate] {
      assert!(matches!(
        WRAPS::signing_protocol(
          phase,
          (phase == R3).then_some(f.seeds[0]),
          &malformed,
          (phase == R3).then_some(&f.keys[0]),
          &f.book,
          f.bits,
          &f.rounds[0],
          &f.rounds[1],
          if phase == Aggregate {
            &f.rounds[2]
          } else {
            &[]
          },
        ),
        Err(WrapsError::InvalidInput(_))
      ));
    }
    assert!(matches!(
      WRAPS::verify_signature(&f.book, &malformed, &signature),
      Err(WrapsError::InvalidInput(_))
    ));
  }
}

#[test]
fn signing_protocol_checks_membership_openings_and_each_share() {
  use SigningProtocolPhase::{Aggregate, R2, R3};
  let f = SigningFixture::new();
  let r3_histories = [&f.rounds[0][..], &f.rounds[1][..], &[]];
  assert!(f
    .call(R2, Some([99; ENTROPY_SIZE]), None, [&f.rounds[0], &[], &[]])
    .is_err());
  assert!(f
    .call(R3, Some([99; ENTROPY_SIZE]), Some(&f.keys[0]), r3_histories)
    .is_err());
  assert!(f
    .call(R3, Some(f.seeds[0]), Some(&f.keys[1]), r3_histories)
    .is_err());

  // Even consistent openings cannot be reassigned to different selected keys.
  let mut swapped = f.rounds.clone();
  swapped[0].swap(0, 1);
  swapped[1].swap(0, 1);
  assert!(f
    .call(
      R3,
      Some(f.seeds[0]),
      Some(&f.keys[0]),
      [&swapped[0], &swapped[1], &[]]
    )
    .is_err());

  let mut wrong_commitment = f.rounds[0].clone();
  let RoundMessage::Round1(mut commitment) =
    decode::<RoundMessage<E2>>(&wrong_commitment[0]).unwrap()
  else {
    unreachable!()
  };
  commitment.nonce_commitment[0] ^= 1;
  wrong_commitment[0] = encode(&RoundMessage::<E2>::Round1(commitment)).unwrap();
  for phase in [R3, Aggregate] {
    assert!(f
      .call(
        phase,
        (phase == R3).then_some(f.seeds[0]),
        (phase == R3).then_some(&f.keys[0]),
        [
          &wrong_commitment,
          &f.rounds[1],
          if phase == Aggregate {
            &f.rounds[2]
          } else {
            &[]
          }
        ],
      )
      .is_err());
  }

  let RoundMessage::Round3(share) = decode::<RoundMessage<E2>>(&f.rounds[2][0]).unwrap() else {
    unreachable!()
  };
  for change_challenge in [false, true] {
    let mut corrupt = share.clone();
    if change_challenge {
      corrupt.partial_signature.e += Base::ONE;
    } else {
      corrupt.partial_signature.s += SchnorrResponse::<E2>::ONE;
    }
    let mut shares = f.rounds[2].clone();
    shares[0] = encode(&RoundMessage::<E2>::Round3(corrupt)).unwrap();
    assert!(f
      .call(Aggregate, None, None, [&f.rounds[0], &f.rounds[1], &shares])
      .is_err());
  }
  // Swapping valid shares leaves their sum unchanged, but each must match its seat.
  let mut shares = f.rounds[2].clone();
  shares.swap(0, 1);
  assert!(f
    .call(Aggregate, None, None, [&f.rounds[0], &f.rounds[1], &shares])
    .is_err());
}

#[test]
fn signing_protocol_validates_the_selected_book() {
  use SigningProtocolPhase::{Aggregate, R1, R2};
  let f = SigningFixture::new();
  let SigningProtocolObject::ProtocolOutput(mut signature) =
    f.call(Aggregate, None, None, f.histories()).unwrap()
  else {
    unreachable!()
  };
  let seed = Some(f.seeds[0]);
  let mut outside = f.bits;
  outside[f.book.len()] = true;
  assert!(WRAPS::signing_protocol(R1, seed, [], None, &f.book, outside, &[], &[], &[],).is_err());
  for bits in [outside, BitVector::from([false; MAX_AB_SIZE])] {
    assert!(
      WRAPS::signing_protocol(R2, seed, [], None, &f.book, bits, &f.rounds[0], &[], &[],).is_err()
    );
  }
  signature.0 = outside;
  assert!(!WRAPS::verify_signature(&f.book, &f.message, &signature).unwrap());
  assert!(WRAPS::signing_protocol(R2, seed, [], None, &vec![], [], &[], &[], &[],).is_err());
  assert!(WRAPS::signing_protocol(
    R1,
    seed,
    [],
    None,
    &f.book,
    [false; MAX_AB_SIZE + 1],
    &[],
    &[],
    &[],
  )
  .is_err());
  let oversized = vec![f.book[0].clone(); MAX_AB_SIZE + 1];
  assert!(WRAPS::signing_protocol(R1, seed, [], None, &oversized, [], &[], &[], &[],).is_err());
  let mut invalid_book = f.book.clone();
  invalid_book[0].1 .1.response += SchnorrResponse::<E2>::ONE;
  for phase in [R1, R2] {
    assert!(WRAPS::signing_protocol(
      phase,
      seed,
      [],
      None,
      &invalid_book,
      f.bits,
      if phase == R2 { &f.rounds[0] } else { &[] },
      &[],
      &[],
    )
    .is_err());
  }
}

#[test]
fn duplicate_live_keys_are_rejected_even_outside_the_signing_subset() {
  use SigningProtocolPhase::{Aggregate, R1, R2, R3};
  let mut f = SigningFixture::new();
  let SigningProtocolObject::ProtocolOutput(signature) =
    f.call(Aggregate, None, None, f.histories()).unwrap()
  else {
    unreachable!()
  };
  assert!(WRAPS::verify_signature(&f.book, &f.message, &signature).unwrap());

  // A different, valid proof must not make a repeated public key look unique.
  let attested = f.book[0].1.clone();
  let fresh_pok = Schnorr::<E2>::prove_knowledge(
    &Keypair {
      sk: f.keys[0],
      pk: attested.0,
    },
    &mut OsRng,
  );
  assert_ne!(encode(&fresh_pok).unwrap(), encode(&attested.1).unwrap());
  let duplicates = [
    f.book[0].clone(),
    (Base::ONE, attested.clone(), 0),
    (Base::ONE, (attested.0, fresh_pok), 2),
  ];
  f.book[2].2 = 3;
  for duplicate in duplicates {
    // The middle seat is unselected, so the existing transcript, joint key, and
    // strict-majority signature remain valid apart from the duplicate-key policy.
    f.book[1] = duplicate;
    let (signing, total) = subset_weight::<E2>(&f.book, &f.bits).unwrap();
    assert!(meets_threshold(&signing, &total));
    assert!(f
      .book
      .iter()
      .all(|(_, (pk, pok), _)| Schnorr::<E2>::verify_knowledge(pk, pok)));
    assert!(Schnorr::<E2>::verify(
      &shared_constants(),
      &Multisig::<E2>::aggregate_key(&signing_subset(&f.book, &f.bits)).unwrap(),
      &decode::<RotationMessage<E2>>(&f.message).unwrap(),
      &signature.1,
    ));
    assert!(!verify_address_book::<E2>(&f.book));
    assert!(WRAPS::compute_addressbook_hash(&f.book).is_err());
    assert!(WRAPS::compute_rotation_message(&f.book, b"duplicate keys").is_err());
    assert!(!WRAPS::verify_signature(&f.book, &f.message, &signature).unwrap());

    for phase in [R1, R2, R3, Aggregate] {
      let histories = match phase {
        R1 => [&[][..], &[][..], &[][..]],
        R2 => [&f.rounds[0][..], &[], &[]],
        R3 => [&f.rounds[0][..], &f.rounds[1][..], &[]],
        Aggregate => f.histories(),
      };
      assert_eq!(
        f.call(
          phase,
          (phase != Aggregate).then_some(f.seeds[0]),
          (phase == R3).then_some(&f.keys[0]),
          histories,
        )
        .unwrap_err(),
        WrapsError::invalid_input("invalid signing address book"),
        "{phase:?} must reject the book before processing a valid transcript",
      );
    }
  }

  // A real public key still occupies a seat when both copies have zero weight.
  f.book[0].2 = 0;
  f.book[1].2 = 0;
  assert!(!verify_address_book::<E2>(&f.book));
}

#[test]
fn signing_protocol_ignores_selected_duplicate_sentinel_seats() {
  use SigningProtocolPhase::{Aggregate, R1, R2, R3};
  let mut f = SigningFixture::new();
  f.book = vec![
    (Base::from(3), WRAPS::sentinel_keygen(), u64::MAX),
    f.book[0].clone(),
    (Base::from(4), WRAPS::sentinel_keygen(), u64::MAX),
    f.book[1].clone(),
    (Base::from(5), WRAPS::sentinel_keygen(), u64::MAX),
    f.book[2].clone(),
    (Base::from(6), WRAPS::sentinel_keygen(), u64::MAX),
  ];
  f.bits = BitVector::from(core::array::from_fn(|i| i < f.book.len() && i != 3));
  assert!(verify_address_book::<E2>(&f.book));
  assert!(WRAPS::compute_addressbook_hash(&f.book).is_ok());
  assert_eq!(subset_weight::<E2>(&f.book, &f.bits), Some((2, 3)));

  // The original two real signers keep their transcript positions despite the
  // selected sentinel seats before, between, and after them. Sentinels send nothing.
  for (signer, key) in [0, 2].into_iter().enumerate() {
    for (round, phase) in [R1, R2, R3].into_iter().enumerate() {
      let histories = match phase {
        R1 => [&[][..], &[][..], &[][..]],
        R2 => [&f.rounds[0][..], &[], &[]],
        R3 => [&f.rounds[0][..], &f.rounds[1][..], &[]],
        Aggregate => unreachable!(),
      };
      assert_eq!(
        f.call(
          phase,
          Some(f.seeds[signer]),
          (phase == R3).then_some(&f.keys[key]),
          histories,
        )
        .unwrap(),
        SigningProtocolObject::ProtocolMessage(f.rounds[round][signer].clone()),
      );
    }
  }
  let SigningProtocolObject::ProtocolOutput(signature) =
    f.call(Aggregate, None, None, f.histories()).unwrap()
  else {
    unreachable!()
  };
  assert!(WRAPS::verify_signature(&f.book, &f.message, &signature).unwrap());

  assert_eq!(
    f.call(
      R3,
      Some(f.seeds[0]),
      Some(&SchnorrSecretKey::<E2>::ZERO),
      [&f.rounds[0], &f.rounds[1], &[]],
    )
    .unwrap_err(),
    WrapsError::invalid_input("R3 signing key is not in the signing subset"),
  );
}

#[test]
fn cancelling_attested_keys_are_rejected_natively_and_in_circuit() {
  let pc = shared_constants();
  let (sk, attested) = WRAPS::keygen([31; ENTROPY_SIZE]);
  let opposite = Keypair::<E2> {
    sk: -sk,
    pk: -attested.0,
  };
  let opposite_pok = Schnorr::<E2>::prove_knowledge(&opposite, &mut OsRng);
  let book = vec![
    (Base::ZERO, attested, 1),
    (Base::ONE, (opposite.pk, opposite_pok), 1),
  ];
  assert!(verify_address_book::<E2>(&book));
  let bits = BitVector::from(core::array::from_fn(|i| i < 2));
  let participants = signing_subset(&book, &bits);
  let joint = Multisig::<E2>::aggregate_key(&participants).unwrap();
  assert!(joint.to_coordinates().2);
  let message = WRAPS::compute_rotation_message(&book, b"cancelled keys").unwrap();
  let typed = decode::<RotationMessage<E2>>(&message).unwrap();
  let seeds = [[41; ENTROPY_SIZE], [42; ENTROPY_SIZE]];
  let round1 = seeds.map(Multisig::<E2>::round1);
  let round2 = seeds.map(Multisig::<E2>::round2);
  assert!(
    Multisig::<E2>::round3(&pc, seeds[0], &typed, &sk, &participants, &round1, &round2).is_err()
  );

  // Anyone can sign for this joint key with the publicly known joint secret zero.
  let forged = Schnorr::<E2>::sign(
    &pc,
    &Keypair {
      sk: SchnorrSecretKey::<E2>::ZERO,
      pk: joint,
    },
    &typed,
  );
  assert!(Schnorr::<E2>::verify(&pc, &joint, &typed, &forged));
  assert!(!WRAPS::verify_signature(&book, &message, &(bits, forged.clone())).unwrap());
  let (cs, _) = synthesize_step(&book, bits, forged, typed);
  assert!(!cs.is_satisfied());
  assert!(cs
    .which_is_unsatisfied()
    .is_some_and(|path| path.contains("joint signing key is not infinity")));
}

#[test]
fn threshold_comparison_handles_the_full_u64_range() {
  for (signing, total, expected) in [
    (0, 0, false),
    (0, 1, false),
    (1, 1, true),
    (1, 2, false),
    (1, 3, false),
    (2, 3, true),
    (2, 2, true),
    (4, 3, false),
    (u64::MAX / 2, u64::MAX, false),
    (u64::MAX / 2 + 1, u64::MAX, true),
    (u64::MAX - 1, u64::MAX, true),
    (u64::MAX, u64::MAX, true),
    (u64::MAX, u64::MAX - 1, false),
    (u64::MAX / 2, u64::MAX - 1, false),
    (u64::MAX / 2 + 1, u64::MAX - 1, true),
  ] {
    assert_eq!(
      meets_threshold(&signing, &total),
      expected,
      "signing={signing}, total={total}"
    );
  }
}

#[test]
fn maximum_total_preserves_the_threshold_natively_and_in_circuit() {
  let f = SigningFixture::new();
  let mut book = f.book[..2].to_vec();
  book[0].2 = u64::MAX / 2;
  book[1].2 = u64::MAX / 2 + 1;
  assert!(verify_address_book::<E2>(&book));
  let msg = arbitrary_message();
  let encoded = encode(&msg).unwrap();

  // The two shares straddle half of an odd total; doubling the winning share would
  // overflow u64, but it must still clear the threshold both natively and in R1CS.
  for (signer, expected) in [(0, false), (1, true)] {
    let bits = BitVector::from(core::array::from_fn(|i| i == signer));
    let (signing, total) = subset_weight::<E2>(&book, &bits).unwrap();
    assert_eq!(total, u64::MAX);
    assert_eq!(meets_threshold(&signing, &total), expected);
    let signature = threshold_sign(&encoded, &book, &f.keys[..2], &bits);
    assert_eq!(
      WRAPS::verify_signature(&book, &encoded, &signature).unwrap(),
      expected
    );
    let (cs, _) = synthesize_step(&book, bits, signature.1, msg);
    assert_eq!(
      cs.is_satisfied(),
      expected,
      "{:?}",
      cs.which_is_unsatisfied()
    );
    if !expected {
      assert!(cs
        .which_is_unsatisfied()
        .is_some_and(|path| path.contains("majority of the weight")));
    }
  }
}

#[test]
fn the_threshold_is_strictly_more_than_half_natively_and_in_circuit() {
  let (mut ab, mut keys) = random_address_book();
  // Weight 1 everywhere, an even number of seats, and exactly half of them signing, so
  // the tie is exact. Padding seats carry zero weight, so they cannot tip it either way.
  ab.truncate(ab.len() & !1);
  keys.truncate(ab.len());
  for entry in ab.iter_mut() {
    entry.2 = 1;
  }
  let bitvector = BitVector::from(core::array::from_fn(|i| i < ab.len() / 2));

  let padded = pad_address_book::<E2>(&ab).unwrap();
  let (signing, total) = subset_weight::<E2>(&padded, &bitvector).unwrap();
  assert_eq!(signing * 2, total, "exactly half, by construction");
  assert!(
    !meets_threshold(&signing, &total),
    "half is not a majority: the rule is 2·signing > total, not >="
  );

  // One more unit of weight on a seat that signs tips it over.
  let mut over = ab.clone();
  over[0].2 = 2;
  let padded = pad_address_book::<E2>(&over).unwrap();
  let (signing, total) = subset_weight::<E2>(&padded, &bitvector).unwrap();
  assert!(meets_threshold(&signing, &total));

  // The circuit draws the line in the same place, and for the tie it is the margin
  // range check that fails rather than anything to do with the signature.
  let msg = arbitrary_message();
  for (book, expected) in [(&ab, false), (&over, true)] {
    let (_, sig) = threshold_sign(&encode(&msg).unwrap(), book, &keys, &bitvector);
    let (cs, _) = synthesize_step(book, bitvector, sig, msg);
    assert_eq!(
      cs.is_satisfied(),
      expected,
      "circuit disagreed with meets_threshold"
    );
    if !expected {
      assert!(cs
        .which_is_unsatisfied()
        .is_some_and(|path| path.contains("majority of the weight")));
    }
  }
}

#[test]
fn verify_signature_follows_the_weight_threshold() {
  let (ab, keys) = random_address_book();
  let msg = arbitrary_message();

  for (bitvector, expected) in [
    (sufficient_bitvector(ab.len()), true),
    (insufficient_bitvector(ab.len()), false),
  ] {
    let multisignature = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);
    assert_eq!(
      WRAPS::verify_signature(&ab, encode(&msg).unwrap(), &multisignature).unwrap(),
      expected,
      "a subset holding {} of {MAX_AB_SIZE} seats",
      bitvector.iter().filter(|b| **b).count(),
    );
  }
}

// ---------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------

#[test]
fn circuit_accepts_a_committee_above_the_threshold() {
  let (ab, keys) = random_address_book();
  let bitvector = sufficient_bitvector(ab.len());
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);

  let (cs, z_out) = synthesize_step(&ab, bitvector, sig, msg);
  assert!(
    cs.is_satisfied(),
    "unsatisfied: {:?}",
    cs.which_is_unsatisfied()
  );
  assert_eq!(z_out[0].get_value().unwrap(), msg[0]);
  assert_eq!(z_out[1].get_value().unwrap(), msg[1]);
}

#[test]
fn circuit_rejects_a_committee_below_the_threshold() {
  // The shares are honest and the aggregate is a valid signature under the subset's
  // joint key — it is the weight rule alone that stops the rotation.
  let pc = shared_constants();
  let (ab, keys) = random_address_book();
  let bitvector = insufficient_bitvector(ab.len());
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);

  let joint = Multisig::<E2>::aggregate_key(&signing_subset(&ab, &bitvector)).unwrap();
  assert!(
    Schnorr::<E2>::verify(&pc, &joint, &msg, &sig),
    "the signature itself is sound; only the weight is short"
  );

  let (cs, _) = synthesize_step(&ab, bitvector, sig, msg);
  assert!(!cs.is_satisfied());
  assert!(cs
    .which_is_unsatisfied()
    .is_some_and(|path| path.contains("majority of the weight")));
}

#[test]
fn circuit_rejects_claiming_weight_for_a_seat_that_did_not_sign() {
  // The attack the per-key infinity check exists to stop, approached the other way:
  // flipping a bit on to pick up weight changes the joint key, so the signature no
  // longer verifies.
  let (ab, keys) = random_address_book();
  let bitvector = insufficient_bitvector(ab.len());
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);

  let mut inflated = bitvector;
  for bit in inflated.iter_mut() {
    *bit = true;
  }
  let (cs, _) = synthesize_step(&ab, inflated, sig, msg);
  assert!(!cs.is_satisfied());
}

#[test]
fn circuit_rejects_an_address_book_the_state_does_not_commit_to() {
  let (ab, keys) = random_address_book();
  let bitvector = sufficient_bitvector(ab.len());
  let msg = arbitrary_message();
  let (_, sig) = threshold_sign(&encode(&msg).unwrap(), &ab, &keys, &bitvector);

  // `z_in` is built from `ab`, but the advice swaps two of its entries. The joint key
  // is unchanged, so the signature still verifies — the book's hash is what fails.
  let pc = shared_constants();
  let permuted = {
    let mut permuted = pad_address_book::<E2>(&ab).unwrap();
    permuted.swap(0, 1);
    permuted
  };
  let ab = pad_address_book::<E2>(&ab).unwrap();
  let mut cs = TestConstraintSystem::<Base>::new();
  let z_in = [hash_address_book::<E2>(&pc, &ab), Base::ZERO]
    .iter()
    .enumerate()
    .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z_in {i}")), || Ok(*v)).unwrap())
    .collect::<Vec<_>>();
  RotationCircuit::<E2> {
    pc,
    prev_ab: permuted,
    bitvector,
    sig,
    msg,
  }
  .synthesize(&mut cs, &z_in)
  .unwrap();

  assert!(!cs.is_satisfied());
  assert!(cs
    .which_is_unsatisfied()
    .is_some_and(|path| path.contains("H(ab) == z_in[0]")));
}

// ---------------------------------------------------------------------
// End-to-end simulations
// ---------------------------------------------------------------------
//
// These run a full trusted setup plus several folding and compression steps, so they
// are the slow part of the suite — a couple of minutes in release mode. They need
// `ppot_pruned_XX.ptau` files under `params/`, or `WRAPS_PTAU_DIR` pointing at a
// directory holding them:
//
//   WRAPS_PTAU_DIR=../Nova/params cargo test --release -- --nocapture
//
// `params/` is git-ignored, so a fresh checkout has to supply it.

/// One trusted setup, shared by every simulation in this run.
fn wraps_setup() -> &'static (PublicParams, ProverKey, VerifierKey) {
  static SETUP: OnceLock<(PublicParams, ProverKey, VerifierKey)> = OnceLock::new();
  SETUP.get_or_init(|| {
    let pp = WRAPS::setup_public_params(&ptau_dir()).expect("powers-of-tau setup");
    let pk = WRAPS::setup_prover(&pp).expect("prover key setup");
    let vk = WRAPS::setup_verifier(&pp).expect("verifier key setup");
    (pp, pk, vk)
  })
}

#[test]
fn setup_public_params_and_keys_are_deterministic() {
  // Independent setup from the same ceremony produces identical parameters and keys.
  let (expected_pp, expected_pk, expected_vk) = wraps_setup();
  let pp = WRAPS::setup_public_params(&ptau_dir()).unwrap();
  let pk = WRAPS::setup_prover(&pp).unwrap();
  let vk = WRAPS::setup_verifier(&pp).unwrap();

  assert_eq!(pp.num_constraints(), expected_pp.num_constraints());
  assert_eq!(pp.digest(), expected_pp.digest());
  assert_eq!(encode(&pk).unwrap(), encode(expected_pk).unwrap());
  assert_eq!(
    WRAPS::get_compressed_verification_key_bytes(&vk).unwrap(),
    WRAPS::get_compressed_verification_key_bytes(expected_vk).unwrap(),
  );
}

/// Every artifact the library hands out, measured on a real one-rotation chain.
///
/// The assertions are order-of-magnitude guards rather than golden values:
/// they catch an artifact growing by a factor without fixing its size across
/// changes to the circuit or proving system.
#[test]
fn artifact_sizes() {
  let (wraps_pp, wraps_pk, wraps_vk) = wraps_setup();

  // Public parameters and keys are separate artifacts, each counted once.
  let pp_bytes = encode(wraps_pp).unwrap().len();
  let prover_key_bytes = encode(wraps_pk).unwrap().len();
  let verification_key_bytes = encode(wraps_vk).unwrap().len();
  // What a standalone verifier is actually shipped: `vk` alone, deflated. It never
  // touches the folding parameters, so `pp` is not part of it.
  let compressed_vk_bytes = WRAPS::get_compressed_verification_key_bytes(wraps_vk)
    .unwrap()
    .len();

  // One genesis rotation, to get a proof of each kind.
  let (genesis_ab, genesis_keys) = random_address_book();
  let ab_genesis_hash = WRAPS::compute_addressbook_hash(&genesis_ab).unwrap();
  let hints_vk = [0u8; 1480];
  let message = WRAPS::compute_rotation_message(&genesis_ab, hints_vk).unwrap();
  let multisignature = threshold_sign(
    &message,
    &genesis_ab,
    &genesis_keys,
    &sufficient_bitvector(genesis_ab.len()),
  );
  let (running, compressed) = WRAPS::construct_wraps_proof(
    wraps_pp,
    wraps_pk,
    wraps_vk,
    &ab_genesis_hash,
    &genesis_ab,
    &genesis_ab,
    None,
    hints_vk,
    &multisignature,
  )
  .expect("the genesis rotation is authorised");

  // Succinct proofs use the ordinary bincode encoding, without zlib.
  let proof = decode::<CompressedWrapsProof>(&compressed).unwrap();
  assert_eq!(encode(&proof).unwrap(), compressed);

  // The shape these numbers have to keep. Compression is the point of the whole
  // exercise: the artifact a verifier receives is two orders of magnitude smaller
  // than the running state it summarises.
  assert!(
    compressed.len() < running.len() / 100,
    "compression should buy two orders of magnitude"
  );
  assert!(
    compressed_vk_bytes <= verification_key_bytes,
    "deflating must not grow the verification key"
  );

  // Absolute guards, generously sized.
  assert!(
    pp_bytes < 512 * 1024 * 1024,
    "public parameters: {pp_bytes} bytes"
  );
  assert!(
    compressed.len() < 128 * 1024,
    "compressed proof: {} bytes",
    compressed.len()
  );
  assert!(
    running.len() < 16 * 1024 * 1024,
    "running proof: {} bytes",
    running.len()
  );
  assert!(
    compressed_vk_bytes < 32 * 1024 * 1024,
    "compressed vk: {compressed_vk_bytes} bytes"
  );
  assert!(
    prover_key_bytes < 512 * 1024 * 1024,
    "proving key: {prover_key_bytes} bytes"
  );
}

#[test]
fn wraps_simulation() {
  let num_steps = 5;
  let (wraps_pp, wraps_pk, wraps_vk) = wraps_setup();
  let vk_bytes = WRAPS::get_compressed_verification_key_bytes(wraps_vk).unwrap();

  let (genesis_ab, genesis_keys) = random_address_book();
  let ab_genesis_hash = WRAPS::compute_addressbook_hash(&genesis_ab).unwrap();

  let mut prev = (genesis_ab, genesis_keys);
  let mut running_proof: Option<Vec<u8>> = None;
  let mut succinct_proof_size = None;

  for i in 0..num_steps {
    // The genesis step rotates the book onto itself; later steps propose a fresh one.
    let next = if i == 0 {
      prev.clone()
    } else {
      random_address_book()
    };
    let hints_vk = [i as u8; 1480];
    let message = WRAPS::compute_rotation_message(&next.0, hints_vk).unwrap();

    let multisignature = threshold_sign(
      &message,
      &prev.0,
      &prev.1,
      &sufficient_bitvector(prev.0.len()),
    );
    assert!(WRAPS::verify_signature(&prev.0, &message, &multisignature).unwrap());

    let (uncompressed, compressed) = WRAPS::construct_wraps_proof(
      wraps_pp,
      wraps_pk,
      wraps_vk,
      &ab_genesis_hash,
      &prev.0,
      &next.0,
      running_proof.clone(),
      hints_vk,
      &multisignature,
    )
    .expect("WRAPS proof should be created");
    let running = decode::<UncompressedWrapsProof>(&uncompressed).unwrap();
    let succinct = decode::<CompressedWrapsProof>(&compressed).unwrap();
    // The circuit shape is fixed despite new books, hints, and rotation counts.
    // Its succinct proof encoding must keep the same length across rotations.
    let expected_size = *succinct_proof_size.get_or_insert(compressed.len());
    assert_eq!(compressed.len(), expected_size, "proof size at step {i}");
    assert_eq!(running.num_steps, i + 1);
    assert_eq!(running.num_steps, running.snark.num_steps());
    assert_eq!(running.zi, running.snark.outputs());
    assert_eq!(running.num_steps, succinct.num_steps);
    assert_eq!(running.z0, succinct.z0);
    assert_eq!(running.zi, succinct.zi);
    assert!(WRAPS::verify_compressed_wraps_proof(
      &vk_bytes,
      &compressed,
      &ab_genesis_hash,
      hints_vk
    )
    .unwrap());
    assert!(WRAPS::verify_uncompressed_wraps_proof(
      wraps_pp,
      &uncompressed,
      &ab_genesis_hash,
      hints_vk
    )
    .unwrap());

    if i == 0 {
      let mut trailing = compressed.clone();
      trailing.push(0);
      assert!(matches!(
        WRAPS::verify_compressed_wraps_proof(
          &vk_bytes,
          &trailing,
          &ab_genesis_hash,
          hints_vk,
        ),
        Err(WrapsError::InvalidInput(reason)) if reason.contains("trailing bytes")
      ));

      // Padding must not turn a claimed nonexistent seat into an accepted sentinel.
      let mut shorter_book = prev.0.clone();
      shorter_book.pop();
      let mut outside_book = multisignature.clone();
      outside_book.0[shorter_book.len()] = true;
      let err = WRAPS::construct_wraps_proof(
        wraps_pp,
        wraps_pk,
        wraps_vk,
        &WRAPS::compute_addressbook_hash(&shorter_book).unwrap(),
        &shorter_book,
        &shorter_book,
        None,
        hints_vk,
        &outside_book,
      )
      .unwrap_err();
      assert!(
        matches!(err, WrapsError::InvalidInput(reason) if reason.contains("outside the previous address book"))
      );

      // Explicit metadata must be authenticated, including when resuming a chain.
      let mut wrong_count = running.clone();
      wrong_count.num_steps += 1;
      let mut wrong_endpoint = running.clone();
      wrong_endpoint.zi[0] += Base::ONE; // Keep the expected hints hash unchanged.
      let mut short_endpoint = running.clone();
      short_endpoint.zi.pop();
      for tampered in [wrong_count, wrong_endpoint, short_endpoint] {
        let bytes = encode(&tampered).unwrap();
        assert!(!WRAPS::verify_uncompressed_wraps_proof(
          wraps_pp,
          &bytes,
          &ab_genesis_hash,
          hints_vk,
        )
        .unwrap());
        assert!(matches!(
          WRAPS::construct_wraps_proof(
            wraps_pp,
            wraps_pk,
            wraps_vk,
            &ab_genesis_hash,
            &prev.0,
            &next.0,
            Some(bytes),
            hints_vk,
            &multisignature,
          ),
          Err(WrapsError::InvalidInput(_))
        ));
      }
    }

    // A committee below the threshold cannot rotate, however honest its shares are.
    let short = threshold_sign(
      &message,
      &prev.0,
      &prev.1,
      &insufficient_bitvector(prev.0.len()),
    );
    assert!(
      WRAPS::construct_wraps_proof(
        wraps_pp,
        wraps_pk,
        wraps_vk,
        &ab_genesis_hash,
        &prev.0,
        &next.0,
        running_proof.clone(),
        hints_vk,
        &short,
      )
      .is_err(),
      "step {i}: a one-third committee should not be able to rotate",
    );

    prev = next;
    running_proof = Some(uncompressed);
  }
}

/// The same simulation for the first `SUFFICIENT_STEPS` rotations, after which the
/// committee stops reaching the threshold: only about a third of the total weight signs
/// each remaining rotation. Every step from then on must be rejected, so the chain
/// stops advancing at `SUFFICIENT_STEPS`.
#[test]
fn wraps_simulation_fails_below_weight_threshold() {
  const SUFFICIENT_STEPS: usize = 4;
  let num_steps = 10;
  let (wraps_pp, wraps_pk, wraps_vk) = wraps_setup();
  let vk_bytes = WRAPS::get_compressed_verification_key_bytes(wraps_vk).unwrap();

  let (genesis_ab, genesis_keys) = random_address_book();
  let ab_genesis_hash = WRAPS::compute_addressbook_hash(&genesis_ab).unwrap();

  let mut prev = (genesis_ab, genesis_keys);
  let mut running_proof: Option<Vec<u8>> = None;
  let mut proven_steps = 0;

  for i in 0..num_steps {
    let next = if i == 0 {
      prev.clone()
    } else {
      random_address_book()
    };
    let hints_vk = [i as u8; 1480];
    let message = WRAPS::compute_rotation_message(&next.0, hints_vk).unwrap();

    let has_sufficient_weight = i < SUFFICIENT_STEPS;
    let bitvector = if has_sufficient_weight {
      sufficient_bitvector(prev.0.len())
    } else {
      insufficient_bitvector(prev.0.len())
    };

    let multisignature = threshold_sign(&message, &prev.0, &prev.1, &bitvector);
    // Sanity-check the premise: the aggregate is only acceptable while the signing
    // subset carries more than half of the total weight.
    assert_eq!(
      WRAPS::verify_signature(&prev.0, &message, &multisignature).unwrap(),
      has_sufficient_weight,
      "step {i}: acceptance should follow whether the weight threshold is met",
    );

    let result = WRAPS::construct_wraps_proof(
      wraps_pp,
      wraps_pk,
      wraps_vk,
      &ab_genesis_hash,
      &prev.0,
      &next.0,
      running_proof.clone(),
      hints_vk,
      &multisignature,
    );

    if !has_sufficient_weight {
      // This step must fail, and fail for the weight rather than for some unrelated
      // inconsistency in the inputs.
      match result {
        Err(WrapsError::InvalidInput(msg)) => assert!(
          msg.contains("Schnorr multisignature verification failed"),
          "step {i}: expected a threshold rejection, got: {msg}",
        ),
        Err(e) => panic!("step {i}: expected a threshold rejection, got {e:?}"),
        Ok(_) => panic!("step {i}: a one-third committee should not be able to rotate"),
      }
      // A rejected rotation does not advance the chain: the address book, the keys and
      // the running proof all stay as they were, so the next step retries from here.
      continue;
    }

    let (uncompressed, compressed) = result.expect("WRAPS proof should be created");
    assert!(
      WRAPS::verify_compressed_wraps_proof(&vk_bytes, &compressed, &ab_genesis_hash, hints_vk)
        .unwrap(),
      "step {i}: compressed proof failed to verify",
    );

    prev = next;
    running_proof = Some(uncompressed);
    proven_steps += 1;
  }

  assert_eq!(
    proven_steps, SUFFICIENT_STEPS,
    "exactly the first {SUFFICIENT_STEPS} steps should have produced a proof",
  );
}
