// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use circuits_analog_adder::FieldWrappingSum;
use circuits_sha256::{derived, ConcreteDerived, ConcreteGiven, Sha256};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_eval::FieldID;
use core_algebra::SerializableField;
use core_algebra::AlgebraicField;
use runtime_algebra::field::RuntimeField;

use super::test_support;

fn push_u32_bits<const W: usize, FR: RuntimeField<W>>(inputs: &mut Vec<FR::E>, val: u32, fr: &FR) {
    for k in 0..32 {
        let bit = (val >> k) & 1;
        inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
    }
}

fn make_inputs<const W: usize, FR: RuntimeField<W>>(
    given: &ConcreteGiven,
    derived: &ConcreteDerived,
    fr: &FR,
) -> Vec<FR::E> {
    let mut inputs = compile_eval::initial_inputs(fr);
    for &val in &given.input_block {
        push_u32_bits(&mut inputs, val, fr);
    }
    for &val in &given.h0 {
        push_u32_bits(&mut inputs, val, fr);
    }
    for &val in &derived.outw {
        push_u32_bits(&mut inputs, val, fr);
    }
    for &val in &derived.oute {
        push_u32_bits(&mut inputs, val, fr);
    }
    for &val in &derived.outa {
        push_u32_bits(&mut inputs, val, fr);
    }
    for &val in &derived.h1 {
        push_u32_bits(&mut inputs, val, fr);
    }
    inputs
}

fn test_compile_sha256_for_field<
    'a,
    const W: usize,
    FC: CompileField + FieldWrappingSum + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
    expected_stats: compile_eval::CircuitGeometry,
) {
    let input = [
        0, 0xdeadbeef, 0xbd5b7dde, 0x9c093ccd, 0x7ab6fbbc, 0x5964baab, 0x3812799a, 0x16c03889,
        0xf56df778, 0xd41bb667, 0xb2c97556, 0x91773445, 0x7024f334, 0x4ed2b223, 0x2d807112,
        0xc2e3001,
    ];
    let h0 = [
        0, 0xabadcafe, 0x575b95fc, 0x30960fa, 0xaeb72bf8, 0x5a64f6f6, 0x612c1f4, 0xb1c08cf2,
    ];
    let given = ConcreteGiven {
        input_block: input,
        h0,
    };
    let derived_val = derived(&given);

    let (circuit, stats, symbols) = compile_compiler::compile(fc, |iologic| {
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let sha256 = Sha256::new(&iologic);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires = circuits_sha256::allocate_given(&bv, &mut pos);
        let derived_wires = circuits_sha256::allocate_derived(&bv, &mut pos);

        (
            sha256.assert_transform_block(&given_wires, &derived_wires),
            1,
            0,
        )
    });

    compile_compiler::dump_stats(name, &circuit, &stats);

    assert_eq!(stats, expected_stats);

    // Verify valid compile-time circuit evaluation
    let inputs = make_inputs(&given, &derived_val, fr);
    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_sha256() {
    let p256_c = P256Field::new();
    let p256_r = runtime_algebra::p256::P256Field::new();
    test_compile_sha256_for_field::<4, _, _>(
        &p256_c,
        &p256_r,
        "sha256_p256",
        FieldID::P256,
        compile_eval::CircuitGeometry {
            ninput: 6657,
            npublic_input: 1,
            noutput: 176,
            nlayers: 6,
            nwires: 30354,
            nterms: 118114,
            nassertions: 6840,
        },
    );
    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_sha256_for_field::<2, _, _>(
        &gf2_c,
        &gf2_r,
        "sha256_gf2_128",
        FieldID::Gf2_128,
        compile_eval::CircuitGeometry {
            ninput: 6657,
            npublic_input: 1,
            noutput: 128,
            nlayers: 12,
            nwires: 51473,
            nterms: 98993,
            nassertions: 6840,
        },
    );
}

#[test]
fn test_compile_sha256_tampering() {
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let input = [
        0, 0xdeadbeef, 0xbd5b7dde, 0x9c093ccd, 0x7ab6fbbc, 0x5964baab, 0x3812799a, 0x16c03889,
        0xf56df778, 0xd41bb667, 0xb2c97556, 0x91773445, 0x7024f334, 0x4ed2b223, 0x2d807112,
        0xc2e3001,
    ];
    let h0 = [
        0, 0xabadcafe, 0x575b95fc, 0x30960fa, 0xaeb72bf8, 0x5a64f6f6, 0x612c1f4, 0xb1c08cf2,
    ];
    let given = ConcreteGiven {
        input_block: input,
        h0,
    };
    let derived_val = derived(&given);

    let (circuit, _stats, symbols) = compile_compiler::compile(&fc, |iologic| {
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let sha256 = Sha256::new(&iologic);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires = circuits_sha256::allocate_given(&bv, &mut pos);
        let derived_wires = circuits_sha256::allocate_derived(&bv, &mut pos);

        (
            sha256.assert_transform_block(&given_wires, &derived_wires),
            1,
            0,
        )
    });

    let corruptors = test_support::all_sha256_corruptors();

    for c in corruptors {
        let mut g = given.clone();
        let mut d = derived_val.clone();
        (c.corrupt)(&mut g, &mut d);

        let inputs = make_inputs(&g, &d, &fr);
        let eval_res =
            compile_eval::eval_circuit_fc(&fc, &fr, &circuit, &symbols, &inputs, FieldID::P256)
                .unwrap();
        assert!(
            eval_res.is_err(),
            "Corruptor '{}' failed to cause circuit evaluation error",
            c.name
        );
    }
}

#[test]
fn test_private_seed_sha256_commitment() {
    use compile_logic::{Logic, LogicIO};

    // SHA-256 initial hash values (FIPS 180-4).
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Test seed: 00 01 02 ... 0f
    let seed: [u8; 16] = std::array::from_fn(|i| i as u8);

    // SHA-256 padding for a 16-byte message:
    // seed || 0x80 || zero padding || bit_length(128).
    let mut padded = [0u8; 64];
    padded[..16].copy_from_slice(&seed);
    padded[16] = 0x80;
    padded[63] = 128;

    let block: [u32; 16] = std::array::from_fn(|i| {
        u32::from_be_bytes(
            padded[i * 4..i * 4 + 4].try_into().unwrap()
        )
    });

    let given = ConcreteGiven {
        input_block: block,
        h0: IV,
    };
    let derived_val = derived(&given);

    // Independently known SHA256(000102...0f).
    const EXPECTED: [u32; 8] = [
        0xbe45cb26, 0x05bf36be, 0xbde68484, 0x1a28f0fd,
        0x43c69850, 0xa3dce5fe, 0xdba69928, 0xee3a8991,
    ];

    assert_eq!(
        derived_val.h1, EXPECTED,
        "SHA-256 result differs from the reference digest"
    );

    let fc = Gf2_128Field::new();
    let fr = runtime_algebra::gf2_128::Gf2_128Field::new();

    let (circuit, stats, symbols) =
        compile_compiler::compile(&fc, |logic| {
            // Position 0 is the reserved constant 1.
            //
            // Positions 1..256 are the public digest bits.
            // Positions 257 onward are the private SHA witness.

            let mut pos = 257;
            let bv = circuits_bitvec::BitvecLogic::new(&logic);
            let sha = Sha256::new(&logic);

            let given_wires =
                circuits_sha256::allocate_given(&bv, &mut pos);
            let derived_wires =
                circuits_sha256::allocate_derived(&bv, &mut pos);

            let sha_checks =
                sha.assert_transform_block(
                    &given_wires,
                    &derived_wires,
                );

            // SHA input_block begins at position 257.
            // The first 128 bits contain the private seed.
            // All remaining bits must equal fixed SHA padding.
            let padding_checks =
                logic.assert_mapi("fixed_padding", 128..512, |i| {
                    let word = block[i / 32];
                    let expected_bit = (word >> (i % 32)) & 1;
                    let expected = if expected_bit == 1 {
                        logic.one()
                    } else {
                        logic.zero()
                    };

                    logic.assert_eq(
                        "padding_bit",
                        &logic.input(257 + i),
                        &expected,
                    )
                });

            // h0 follows the 512 message-block bits.
            let h0_start = 257 + 512;

            let iv_checks =
                logic.assert_mapi("fixed_iv", 0..256, |i| {
                    let expected_bit =
                        (IV[i / 32] >> (i % 32)) & 1;

                    let expected = if expected_bit == 1 {
                        logic.one()
                    } else {
                        logic.zero()
                    };

                    logic.assert_eq(
                        "iv_bit",
                        &logic.input(h0_start + i),
                        &expected,
                    )
                });

            // In the allocated SHA witness, h1 is the final
            // 256 bits after block, h0, outw, oute and outa.
            let h1_start = 257 + (16 + 8 + 48 + 64 + 64) * 32;

            let digest_checks =
                logic.assert_mapi("public_digest", 0..256, |i| {
                    logic.assert_eq(
                        "digest_bit",
                        &logic.input(1 + i),
                        &logic.input(h1_start + i),
                    )
                });

            let assertions = logic.assert_all(
                "seed_commitment",
                &[
                    sha_checks,
                    padding_checks,
                    iv_checks,
                    digest_checks,
                ],
            );

            // 1 reserved constant + 256 digest bits are public.
            (assertions, 257, 0)
        });

    assert_eq!(stats.npublic_input, 257);
    compile_compiler::dump_stats(
        "private_seed_sha256",
        &circuit,
        &stats,
    );

    // Construct the complete witness in exactly the
    // order used when compiling the circuit.
    let mut inputs = compile_eval::initial_inputs(&fr);

    for &word in &EXPECTED {
        push_u32_bits(&mut inputs, word, &fr);
    }

    let sha_inputs = make_inputs(&given, &derived_val, &fr);
    inputs.extend(sha_inputs.into_iter().skip(1));

    assert_eq!(inputs.len(), stats.ninput);

    // Positive test.
    compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols, &inputs,
        FieldID::Gf2_128,
    )
    .unwrap()
    .assert_all_passed();

    println!("Valid private seed commitment accepted");

    // Negative test 1: change the public digest.
    let mut wrong_digest = inputs.clone();
    wrong_digest[1] = fr.one(); // Expected bit 0 is zero.

    let result = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols, &wrong_digest,
        FieldID::Gf2_128,
    )
    .unwrap();

    assert!(result.result.is_err());
    println!("Incorrect public digest rejected");

    // Negative test 2: change the required SHA padding.
    let mut wrong_padding = inputs.clone();
    // The top bit of block word 4 represents byte 16's 0x80.
    let padding_bit_position = 257 + 4 * 32 + 31;
    wrong_padding[padding_bit_position] = fr.zero();

    let result = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols, &wrong_padding,
        FieldID::Gf2_128,
    )
    .unwrap();

    assert!(result.result.is_err());
    println!("Incorrect SHA-256 padding rejected");


    // -------------------------------------------------------
    // Real Longfellow zero-knowledge proof
    // -------------------------------------------------------
    use core_proto::{reader::CircuitReader, writer::CircuitWriter};
    use runtime_algebra::{
        lch14_reed_solomon::Lch14InterpolatorFactory,
        subfield::BinarySubfield,
    };
    use runtime_ligero::LigeroConfig;
    use runtime_random::{SecureRandomEngine, Transcript};
    use runtime_zk::{ZkProof, ZkProver, ZkVerifier};

    // Serialize the compiled SHA-256 circuit.
    let circuit_bytes =
        CircuitWriter::new(&fc, FieldID::Gf2_128)
            .to_bytes(&circuit);

    let (loaded, remaining) =
        CircuitReader::new(&fr, FieldID::Gf2_128)
            .from_bytes(&circuit_bytes, true)
            .expect("Cannot load the SHA-256 circuit");

    assert!(remaining.is_empty());

    println!("Circuit size: {} bytes", circuit_bytes.len());

    // Split public digest from private SHA-256 witness.
    let npublic = loaded.raw.npublic_input;

    let public_inputs = inputs[..npublic].to_vec();
    let private_inputs = inputs[npublic..].to_vec();

    assert_eq!(npublic, 257);

    // Initialize Longfellow runtime.
    let sf = BinarySubfield::new(
        &core_algebra::proto::GF2_16_BASIS_V1
    );

    let interpolator =
        Lch14InterpolatorFactory::new(&fr, &sf);

    let ctx = runtime_zk::common::ZkContext {
        f: &fr,
        make_interpolator: &interpolator,
    };

    // Small parameters for a local functional experiment.
    // Not security parameters for deployment.
    let config = LigeroConfig {
        rateinv: 4,
        nreq: 16,
        block_enc: 256,
    };

    let prover = ZkProver::new(loaded, config);

    let mut rng = SecureRandomEngine::new();

    let transcript_seed = b"sha256_seed_commitment_test_v1";
    let mut tp = Transcript::new(transcript_seed);

    // Commit to the private witness.
    let (commitment, geometry) = prover.commit(
        &private_inputs,
        &ctx,
        &mut tp,
        &mut rng,
        &sf,
    );

    // Generate the cryptographic proof.
    let proof = prover.prove(
        public_inputs.clone(),
        private_inputs,
        &commitment,
        &mut tp,
        &ctx,
    ).expect("SHA-256 proof generation failed");

    // Serialize the proof.
    let proof_bytes = proof.write(&geometry, &fr, &sf)
        .expect("Cannot serialize the proof");

    println!("Proof size: {} bytes", proof_bytes.len());

    // Construct the verifier from the same circuit.
    let verifier = ZkVerifier::new(prover.circuit, config);
    let verification_geometry = verifier.geometry(&ctx);

    // Deserialize the proof.
    let mut proof_slice = proof_bytes.as_slice();

    let decoded = ZkProof::read(
        &mut proof_slice,
        &verification_geometry,
        &fr,
        &sf,
    ).expect("Cannot deserialize the proof");

    assert!(proof_slice.is_empty());

    // Positive test: verify with the correct public digest.
    let mut tv = Transcript::new(transcript_seed);

    verifier.recv_commitment(
        &decoded,
        &mut tv,
        &ctx,
    );

    verifier.verify(
        public_inputs.clone(),
        &decoded,
        &mut tv,
        &ctx,
    ).expect("Valid SHA-256 proof was rejected");

    println!("Valid SHA-256 ZK proof accepted");

    // Negative test: change one public digest bit.
    let mut wrong_public = public_inputs;
    wrong_public[1] = fr.one();

    let mut tv_bad = Transcript::new(transcript_seed);

    verifier.recv_commitment(
        &decoded,
        &mut tv_bad,
        &ctx,
    );

    assert!(
        verifier.verify(
            wrong_public,
            &decoded,
            &mut tv_bad,
            &ctx,
        ).is_err(),
        "Verifier accepted an incorrect public digest!"
    );

    println!("Incorrect public digest proof rejected");

    println!("Private seed SHA-256 circuit tests passed");
}

#[test]
fn test_peter_pseudonym_combined() {
    use compile_logic::{Logic, LogicIO};
    use core_algebra::AlgebraicField;

    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const SSC: [u32; 8] = [
        0xbe45cb26, 0x05bf36be, 0xbde68484, 0x1a28f0fd,
        0x43c69850, 0xa3dce5fe, 0xdba69928, 0xee3a8991,
    ];

    const V: [u32; 8] = [
        0xc646dcfa, 0x083d2353, 0x32279b17, 0xd0b59cd6,
        0xae219c2a, 0xbdaad837, 0x5dac9a25, 0xccd33b15,
    ];

    const NYM: [u32; 8] = [
        0x15005e59, 0x6c36da82, 0xde27f358, 0x493d1858,
        0x138ee155, 0xc56002ca, 0x5f3780f7, 0x6092c21c,
    ];

    // SHA-256 padding and block conversion.
    fn padded_blocks(message: &[u8]) -> Vec<[u32; 16]> {
        let mut data = message.to_vec();
        let bit_len = (message.len() as u64) * 8;

        data.push(0x80);
        while data.len() % 64 != 56 {
            data.push(0);
        }
        data.extend_from_slice(&bit_len.to_be_bytes());

        data.chunks_exact(64)
            .map(|chunk| {
                std::array::from_fn(|i| {
                    u32::from_be_bytes(
                        chunk[4*i..4*i+4].try_into().unwrap()
                    )
                })
            })
            .collect()
    }

    // Input-wire bit index for a byte in a SHA-256 block.
    // Each u32 is represented least-significant-bit first.
    fn bitpos(byte: usize, bit: usize) -> usize {
        (byte / 4) * 32 + (3 - byte % 4) * 8 + bit
    }

    let seed: [u8; 16] = std::array::from_fn(|i| i as u8);
    let dst = b"nym_auth/v1/known-offender-matching-ssc";

    let mut v_bytes = Vec::new();
    for word in V {
        v_bytes.extend_from_slice(&word.to_be_bytes());
    }

    let mut message = Vec::new();
    message.extend_from_slice(dst);
    message.extend_from_slice(&seed);
    message.extend_from_slice(&[0u8; 32]);
    message.extend_from_slice(&v_bytes);

    assert_eq!(message.len(), 119);

    let a = padded_blocks(&seed);
    let b = padded_blocks(&message);

    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 2);

    // A: SHA256(seed)
    // B1, B2: SHA256(DST || seed || zeros || V)
    let g0 = ConcreteGiven { input_block: a[0], h0: IV };
    let d0 = derived(&g0);

    let g1 = ConcreteGiven { input_block: b[0], h0: IV };
    let d1 = derived(&g1);

    let g2 = ConcreteGiven {
        input_block: b[1],
        h0: d1.h1,
    };
    let d2 = derived(&g2);

    assert_eq!(d0.h1, SSC);
    assert_eq!(d2.h1, NYM);

    let givens = [g0, g1, g2];
    let derived_values = [d0, d1, d2];

    let fc = Gf2_128Field::new();
    let fr = runtime_algebra::gf2_128::Gf2_128Field::new();

    // Public positions:
    // 0       reserved constant 1
    // 1..256  SSC
    // 257..512 V
    // 513..768 NYM
    //
    // Each SHA compression witness occupies 6656 bits.
    const BASE: usize = 769;
    const BLOCK_SIZE: usize = 6656;
    const H0_OFFSET: usize = 512;
    const H1_OFFSET: usize = 6400;

    let (circuit, stats, symbols) =
        compile_compiler::compile(&fc, |logic| {
            let bv = circuits_bitvec::BitvecLogic::new(&logic);
            let sha = Sha256::new(&logic);

            let mut pos = BASE;
            let mut gw = Vec::new();
            let mut dw = Vec::new();

            for _ in 0..3 {
                gw.push(circuits_sha256::allocate_given(
                    &bv, &mut pos
                ));
                dw.push(circuits_sha256::allocate_derived(
                    &bv, &mut pos
                ));
            }

            let sha_checks = logic.assert_mapi(
                "sha_blocks", 0..3, |j| {
                    sha.assert_transform_block(&gw[j], &dw[j])
                }
            );

            // Enforce all fixed message bytes, share the
            // same seed, and bind V to public input bits.
            let message_checks = logic.assert_mapi(
                "message_structure", 0..3, |j| {
                    logic.assert_mapi(
                        "bits", 0..512, |i| {
                            let byte =
                                (i / 32) * 4 + 3 - (i % 32) / 8;
                            let bit = i % 8;
                            let wire = logic.input(
                                BASE + j * BLOCK_SIZE + i
                            );

                            if j == 0 && byte < 16 {
                                // This is the private seed.
                                // Its bits are not fixed.
                                logic.assert0(
                                    "seed_input",
                                    &logic.zero(),
                                )
                            } else if j == 1 &&
                                      (39..55).contains(&byte) {
                                // Same seed as SHA block A.
                                let original = logic.input(
                                    BASE + bitpos(byte - 39, bit)
                                );
                                logic.assert_eq(
                                    "shared_seed",
                                    &wire,
                                    &original,
                                )
                            } else if j == 2 &&
                                      (23..55).contains(&byte) {
                                // Public V (32 bytes).
                                let vbit = logic.input(
                                    257 + (byte - 23) * 8 + bit
                                );
                                logic.assert_eq(
                                    "verifier_input",
                                    &wire,
                                    &vbit,
                                )
                            } else {
                                // All other message bits are
                                // fixed constants, including
                                // domain separator and padding.
                                let word =
                                    givens[j].input_block[i / 32];
                                let expected =
                                    (word >> (i % 32)) & 1;

                                let constant = if expected == 1 {
                                    logic.one()
                                } else {
                                    logic.zero()
                                };

                                logic.assert_eq(
                                    "fixed_message",
                                    &wire,
                                    &constant,
                                )
                            }
                        }
                    )
                }
            );

            // Fixed SHA-256 IV for A and B1.
            let iv_checks = logic.assert_mapi(
                "fixed_iv", 0..2, |j| {
                    logic.assert_mapi(
                        "iv_bits", 0..256, |i| {
                            let wire = logic.input(
                                BASE + j * BLOCK_SIZE
                                    + H0_OFFSET + i
                            );
                            let expected =
                                (IV[i / 32] >> (i % 32)) & 1;

                            let constant = if expected == 1 {
                                logic.one()
                            } else {
                                logic.zero()
                            };

                            logic.assert_eq(
                                "iv_constant",
                                &wire,
                                &constant,
                            )
                        }
                    )
                }
            );

            // B2 initial state must equal B1 final state.
            let chain_checks = logic.assert_mapi(
                "sha_chaining", 0..256, |i| {
                    logic.assert_eq(
                        "chain_bit",
                        &logic.input(
                            BASE + 2 * BLOCK_SIZE
                                + H0_OFFSET + i
                        ),
                        &logic.input(
                            BASE + BLOCK_SIZE
                                + H1_OFFSET + i
                        ),
                    )
                }
            );

            // Bind both final digests to public inputs.
            let digest_checks = logic.assert_mapi(
                "digest_outputs", 0..256, |i| {
                    let ssc_check = logic.assert_eq(
                        "ssc",
                        &logic.input(1 + i),
                        &logic.input(BASE + H1_OFFSET + i),
                    );

                    let nym_check = logic.assert_eq(
                        "nym",
                        &logic.input(513 + i),
                        &logic.input(
                            BASE + 2 * BLOCK_SIZE
                                + H1_OFFSET + i
                        ),
                    );

                    logic.assert_all(
                        "digest_pair",
                        &[ssc_check, nym_check],
                    )
                }
            );

            let all = logic.assert_all(
                "peter_pseudonym",
                &[
                    sha_checks,
                    message_checks,
                    iv_checks,
                    chain_checks,
                    digest_checks,
                ],
            );

            (all, BASE, 0)
        });

    assert_eq!(stats.npublic_input, 769);

    compile_compiler::dump_stats(
        "peter_pseudonym",
        &circuit,
        &stats,
    );

    // Construct public inputs in the specified order.
    let mut inputs = compile_eval::initial_inputs(&fr);

    for word in SSC {
        push_u32_bits(&mut inputs, word, &fr);
    }

    for byte in &v_bytes {
        for bit in 0..8 {
            inputs.push(if (byte >> bit) & 1 == 1 {
                fr.one()
            } else {
                fr.zero()
            });
        }
    }

    for word in NYM {
        push_u32_bits(&mut inputs, word, &fr);
    }

    // Append the three private SHA witnesses.
    for j in 0..3 {
        let witness =
            make_inputs(&givens[j], &derived_values[j], &fr);
        inputs.extend(witness.into_iter().skip(1));
    }

    assert_eq!(inputs.len(), stats.ninput);

    let result = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols,
        &inputs, FieldID::Gf2_128,
    ).unwrap();

    result.assert_all_passed();
    println!("Valid Peter pseudonym relation accepted");

    // Wrong public pseudonym must fail.
    let mut wrong_nym = inputs.clone();
    wrong_nym[513] = if wrong_nym[513] == fr.zero() {
        fr.one()
    } else {
        fr.zero()
    };

    let bad = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols,
        &wrong_nym, FieldID::Gf2_128,
    ).unwrap();

    assert!(bad.result.is_err());
    println!("Wrong public pseudonym rejected");

    // Modifying the second occurrence of the seed
    // must break the shared-secret constraint.
    let mut wrong_seed = inputs.clone();
    let seed_bit = BASE + BLOCK_SIZE + bitpos(39, 0);

    wrong_seed[seed_bit] =
        if wrong_seed[seed_bit] == fr.zero() {
            fr.one()
        } else {
            fr.zero()
        };

    let bad = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols,
        &wrong_seed, FieldID::Gf2_128,
    ).unwrap();

    assert!(bad.result.is_err());
    println!("Different seed in pseudonym rejected");


    // Real ZK proof for Peter's combined pseudonym relation.
    use core_proto::{reader::CircuitReader, writer::CircuitWriter};
    use runtime_algebra::{
        lch14_reed_solomon::Lch14InterpolatorFactory,
        subfield::BinarySubfield,
    };
    use runtime_ligero::LigeroConfig;
    use runtime_random::{SecureRandomEngine, Transcript};
    use runtime_zk::{ZkProof, ZkProver, ZkVerifier};

    let circuit_bytes = CircuitWriter::new(
        &fc, FieldID::Gf2_128
    ).to_bytes(&circuit);

    let (loaded, remaining) =
        CircuitReader::new(&fr, FieldID::Gf2_128)
            .from_bytes(&circuit_bytes, true)
            .expect("Failed to load pseudonym circuit");

    assert!(remaining.is_empty());
    println!("Circuit size: {} bytes", circuit_bytes.len());

    let npublic = loaded.raw.npublic_input;
    assert_eq!(npublic, 769);

    let public_inputs = inputs[..npublic].to_vec();
    let private_inputs = inputs[npublic..].to_vec();

    let sf = BinarySubfield::new(
        &core_algebra::proto::GF2_16_BASIS_V1
    );
    let interpolator =
        Lch14InterpolatorFactory::new(&fr, &sf);

    let ctx = runtime_zk::common::ZkContext {
        f: &fr,
        make_interpolator: &interpolator,
    };

    // Local experimental parameters, not production security settings.
    let config = LigeroConfig {
        rateinv: 4,
        nreq: 16,
        block_enc: 256,
    };

    let prover = ZkProver::new(loaded, config);
    let mut rng = SecureRandomEngine::new();
    let transcript_seed = b"peter_pseudonym_test_v1";
    let mut tp = Transcript::new(transcript_seed);

    let (commitment, geometry) = prover.commit(
        &private_inputs, &ctx, &mut tp, &mut rng, &sf
    );

    let proof = prover.prove(
        public_inputs.clone(),
        private_inputs,
        &commitment,
        &mut tp,
        &ctx,
    ).expect("Pseudonym proof generation failed");

    let proof_bytes = proof.write(&geometry, &fr, &sf)
        .expect("Failed to serialize proof");

    println!("Proof size: {} bytes", proof_bytes.len());

    let verifier = ZkVerifier::new(prover.circuit, config);
    let v_geometry = verifier.geometry(&ctx);

    let mut slice = proof_bytes.as_slice();
    let decoded = ZkProof::read(
        &mut slice, &v_geometry, &fr, &sf
    ).expect("Failed to decode pseudonym proof");

    assert!(slice.is_empty());

    // Correct public pseudonym should verify.
    let mut tv = Transcript::new(transcript_seed);
    verifier.recv_commitment(&decoded, &mut tv, &ctx);

    verifier.verify(
        public_inputs.clone(), &decoded, &mut tv, &ctx
    ).expect("Valid pseudonym ZK proof rejected");

    println!("Valid pseudonym ZK proof accepted");

    // A different pseudonym must fail verification.
    let mut bad_public = public_inputs.clone();
    bad_public[513] = if bad_public[513] == fr.zero() {
        fr.one()
    } else {
        fr.zero()
    };

    let mut tv_bad = Transcript::new(transcript_seed);
    verifier.recv_commitment(&decoded, &mut tv_bad, &ctx);

    assert!(
        verifier.verify(
            bad_public, &decoded, &mut tv_bad, &ctx
        ).is_err(),
        "Modified pseudonym was accepted"
    );

    println!("Modified pseudonym proof rejected");

    // A different verifier input must also fail verification.
    let mut wrong_verifier = public_inputs;
    wrong_verifier[257] = if wrong_verifier[257] == fr.zero() {
        fr.one()
    } else {
        fr.zero()
    };

    let mut tv_wrong = Transcript::new(transcript_seed);
    verifier.recv_commitment(&decoded, &mut tv_wrong, &ctx);

    assert!(
        verifier.verify(
            wrong_verifier, &decoded, &mut tv_wrong, &ctx
        ).is_err(),
        "Modified verifier input was accepted"
    );

    println!("Modified verifier input proof rejected");


    // ============================================================
    // Reusability test: same compiled circuit, different inputs.
    // ============================================================

    let original_verifier: [u8; 32] =
        v_bytes.as_slice().try_into().unwrap();

    let seed_a = seed;
    let seed_b = [0xa5u8; 16];

    let verifier_a = original_verifier;
    let verifier_b = [0x42u8; 32];

    // Generate fresh witnesses without changing the circuit.
    let build_case = |new_seed: [u8; 16],
                      new_v: [u8; 32]| {

        let seed_blocks = padded_blocks(&new_seed);

        let mut nym_message = Vec::new();
        nym_message.extend_from_slice(dst);
        nym_message.extend_from_slice(&new_seed);
        nym_message.extend_from_slice(&[0u8; 32]);
        nym_message.extend_from_slice(&new_v);

        let nym_blocks = padded_blocks(&nym_message);

        assert_eq!(seed_blocks.len(), 1);
        assert_eq!(nym_blocks.len(), 2);

        let ga = ConcreteGiven {
            input_block: seed_blocks[0],
            h0: IV,
        };
        let da = derived(&ga);

        let gb1 = ConcreteGiven {
            input_block: nym_blocks[0],
            h0: IV,
        };
        let db1 = derived(&gb1);

        let gb2 = ConcreteGiven {
            input_block: nym_blocks[1],
            h0: db1.h1,
        };
        let db2 = derived(&gb2);

        let new_givens = [ga, gb1, gb2];
        let new_derived = [da, db1, db2];

        let mut witness = compile_eval::initial_inputs(&fr);

        // Public SSC
        for &word in &new_derived[0].h1 {
            push_u32_bits(&mut witness, word, &fr);
        }

        // Public V
        for &byte in &new_v {
            for bit in 0..8 {
                witness.push(if (byte >> bit) & 1 == 1 {
                    fr.one()
                } else {
                    fr.zero()
                });
            }
        }

        // Public pseudonym
        for &word in &new_derived[2].h1 {
            push_u32_bits(&mut witness, word, &fr);
        }

        // Private SHA-256 witnesses, in circuit input order.
        for j in 0..3 {
            let block_witness =
                make_inputs(&new_givens[j], &new_derived[j], &fr);

            witness.extend(block_witness.into_iter().skip(1));
        }

        assert_eq!(witness.len(), stats.ninput);
        witness
    };

    let cases = [
        ("original", seed_a, verifier_a),
        ("new_seed", seed_b, verifier_a),
        ("new_verifier", seed_a, verifier_b),
        ("both_changed", seed_b, verifier_b),
    ];

    let mut examples = Vec::new();

    for (name, test_seed, test_v) in cases {
        let witness = build_case(test_seed, test_v);

        // Evaluate with the original compiled circuit.
        compile_eval::eval_circuit_fc(
            &fc, &fr, &circuit, &symbols,
            &witness, FieldID::Gf2_128,
        )
        .unwrap()
        .assert_all_passed();

        println!("{name}: circuit accepted");

        examples.push((name, witness));
    }

    // A changed seed must produce a different SSC and NYM.
    assert_ne!(
        &examples[0].1[1..257],
        &examples[1].1[1..257]
    );

    assert_ne!(
        &examples[0].1[513..769],
        &examples[1].1[513..769]
    );

    // A different verifier must produce a different NYM.
    assert_ne!(
        &examples[0].1[513..769],
        &examples[2].1[513..769]
    );

    println!("Distinct seed/verifier outputs confirmed");

    // Negative test: pair seed B's private witness
    // with seed A's public SSC.
    let mut mismatched = examples[1].1.clone();

    mismatched[1..257]
        .clone_from_slice(&examples[0].1[1..257]);

    let result = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols,
        &mismatched, FieldID::Gf2_128,
    ).unwrap();

    assert!(result.result.is_err());

    println!("Mismatched seed commitment rejected");

    // A different public SSC with the original witness
    // must also be rejected.
    let mut corrupted_ssc = examples[0].1.clone();

    corrupted_ssc[1] = if corrupted_ssc[1] == fr.zero() {
        fr.one()
    } else {
        fr.zero()
    };

    let result = compile_eval::eval_circuit_fc(
        &fc, &fr, &circuit, &symbols,
        &corrupted_ssc, FieldID::Gf2_128,
    ).unwrap();

    assert!(result.result.is_err());
    println!("Corrupted public SSC rejected");

    // Generate and verify independent proofs for all cases.
    for (name, witness) in &examples {
        let (fresh_circuit, rest) =
            CircuitReader::new(&fr, FieldID::Gf2_128)
                .from_bytes(&circuit_bytes, true)
                .expect("Cannot reload circuit");

        assert!(rest.is_empty());

        let npublic = fresh_circuit.raw.npublic_input;
        let pub_inputs = witness[..npublic].to_vec();
        let priv_inputs = witness[npublic..].to_vec();

        let fresh_prover = ZkProver::new(fresh_circuit, config);

        let mut test_rng = SecureRandomEngine::new();
        let mut test_tp =
            Transcript::new(b"peter_pseudonym_multi_v1");

        let (commitment, geom) = fresh_prover.commit(
            &priv_inputs,
            &ctx,
            &mut test_tp,
            &mut test_rng,
            &sf,
        );

        let new_proof = fresh_prover.prove(
            pub_inputs.clone(),
            priv_inputs,
            &commitment,
            &mut test_tp,
            &ctx,
        ).expect("Failed to generate multi-case proof");

        let encoded = new_proof.write(&geom, &fr, &sf)
            .expect("Cannot serialize multi-case proof");

        let vgeom = verifier.geometry(&ctx);
        let mut bytes = encoded.as_slice();

        let decoded_proof = ZkProof::read(
            &mut bytes, &vgeom, &fr, &sf
        ).expect("Cannot decode multi-case proof");

        assert!(bytes.is_empty());

        let mut verify_tp =
            Transcript::new(b"peter_pseudonym_multi_v1");

        verifier.recv_commitment(
            &decoded_proof, &mut verify_tp, &ctx
        );

        verifier.verify(
            pub_inputs,
            &decoded_proof,
            &mut verify_tp,
            &ctx,
        ).expect("Valid multi-case proof rejected");

        println!(
            "{name}: ZK proof accepted ({} bytes)",
            encoded.len()
        );
    }

    println!("All reusable pseudonym tests passed");

    println!("Combined pseudonym circuit tests passed");
}
