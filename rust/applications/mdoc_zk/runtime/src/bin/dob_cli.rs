use std::{env, fs, process};

use mdoc_zk_runtime::{
    req_attr,
    run_mdoc_prover_inner_with_birthdate,
    run_mdoc_verifier_inner_with_birthdate,
    CURRENT_ZK_SPECS,
};
use runtime_algebra::RuntimeNat;
use runtime_ligero::param::LigeroConfig;

const CIRCUIT_ID: &str =
    "b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926";

fn trusted_spec() -> mdoc_zk_runtime::ZkSpecStruct {
    let mut spec = CURRENT_ZK_SPECS[0];

    // Parameters from the successfully compiled DOB-only circuit.
    spec.num_attributes = 1;

    spec.ligero_hash = LigeroConfig {
        rateinv: 7,
        nreq: 132,
        block_enc: 5264,
    };

    spec.ligero_sig = LigeroConfig {
        rateinv: 7,
        nreq: 132,
        block_enc: 4445,
    };

    for i in 0..32 {
        spec.combined_hash[i] =
            u8::from_str_radix(&CIRCUIT_ID[2*i..2*i+2], 16)
                .expect("Invalid pinned circuit ID");
    }

    spec
}

fn date_bytes(s: &str) -> Result<[u8; 10], String> {
    let b = s.as_bytes();

    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || ![0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
    {
        return Err(format!("Invalid date format: {s}"));
    }

    let year: u32 = s[0..4].parse().map_err(|e| format!("{e}"))?;
    let month: u32 = s[5..7].parse().map_err(|e| format!("{e}"))?;
    let day: u32 = s[8..10].parse().map_err(|e| format!("{e}"))?;

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);

    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(format!("Invalid month: {s}")),
    };

    if day == 0 || day > max_day {
        return Err(format!("Invalid calendar date: {s}"));
    }

    b.try_into().map_err(|_| "Invalid date length".to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2
        || !matches!(
            (args[1].as_str(), args.len()),
            ("prove", 11) | ("verify", 10)
        )
    {
        return Err(
            "Usage:\n\
             dob_cli prove  <mdoc>  <transcript> <pkx> <pky> <doc_type> <now> <cutoff> <earliest> <proof_out>\n\
             dob_cli verify <proof> <transcript> <pkx> <pky> <doc_type> <now> <cutoff> <earliest>"
            .into()
        );
    }

    let mode = &args[1];
    let input = &args[2];
    let transcript_path = &args[3];
    let pkx = &args[4];
    let pky = &args[5];
    let doc_type = &args[6];
    let now = &args[7];

    let cutoff = date_bytes(&args[8])?;
    let earliest = date_bytes(&args[9])?;

    if cutoff > earliest {
        return Err("Lower DOB bound exceeds upper bound".into());
    }

    let archive_path = env::var("DOB_CIRCUITS_ZST")
        .unwrap_or_else(|_| {
            format!(
                "{}/longfellow-dob-only-export/circuits.zst",
                env::var("HOME").unwrap_or_else(|_| ".".into())
            )
        });

    let circuits = fs::read(&archive_path)
        .map_err(|e| format!("Cannot read circuit archive: {e}"))?;

    let transcript = fs::read(transcript_path)
        .map_err(|e| format!("Cannot read transcript: {e}"))?;

    // mDL document type and attribute namespace are different.
    let attribute_namespace = match doc_type.as_str() {
        "org.iso.18013.5.1.mDL" => "org.iso.18013.5.1",
        _ => doc_type.as_str(),
    };

    let spec = trusted_spec();

    if mode == "prove" {
        let mdoc = fs::read(input)
            .map_err(|e| format!("Cannot read mdoc: {e}"))?;

        let parsed =
            mdoc_zk_runtime::circuits::cbor::mdoc::parse_mdoc::<RuntimeNat<4>>(
                &mdoc,
                &transcript,
                doc_type,
            )
            .map_err(|e| format!("Cannot parse mdoc: {e:?}"))?;

        let birth = parsed.get_attribute(b"birth_date")
            .ok_or("Issuer-signed birth_date attribute not found")?;

        let attributes = vec![
            req_attr(attribute_namespace, b"birth_date", &birth.cbor_value),
        ];

        let mut rng = runtime_random::SecureRandomEngine::new();

        let proof = run_mdoc_prover_inner_with_birthdate(
            &spec,
            &circuits,
            &mdoc,
            pkx,
            pky,
            &transcript,
            &attributes,
            now,
            doc_type,
            &cutoff,
            &earliest,
            &mut rng,
        )
        .map_err(|e| format!("Proof generation failed: {e:?}"))?;

        fs::write(&args[10], &proof)
            .map_err(|e| format!("Cannot write proof: {e}"))?;

        println!("DOB proof generated successfully");
        println!("Proof bytes: {}", proof.len());
        println!("Circuit ID: {}", CIRCUIT_ID);
        println!("Proof saved to: {}", args[10]);

    } else {
        let proof = fs::read(input)
            .map_err(|e| format!("Cannot read proof: {e}"))?;

        // Placeholder CBOR value. The real DOB is never supplied
        // to the verifier.
        let mut dummy_birth = [0u8; 14];
        dummy_birth[..4].copy_from_slice(&[0xd9, 0x03, 0xec, 0x6a]);
        dummy_birth[4..].copy_from_slice(b"1999-01-01");

        let attributes = vec![
            req_attr(attribute_namespace, b"birth_date", &dummy_birth),
        ];

        run_mdoc_verifier_inner_with_birthdate(
            &spec,
            &circuits,
            pkx,
            pky,
            &transcript,
            &attributes,
            now,
            doc_type,
            &proof,
            &cutoff,
            &earliest,
        )
        .map_err(|e| format!("Verification failed: {e:?}"))?;

        println!("DOB PROOF VERIFIED");
        println!(
            "Verified interval: {} <= DOB <= {}",
            args[8], args[9]
        );
        println!("Circuit ID: {}", CIRCUIT_ID);
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }
}
