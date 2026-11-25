# Longfellow DOB-Only Age Verification

This branch implements privacy-preserving date-of-birth interval
verification using issuer-signed ISO mDL credentials and zero-knowledge
proofs.

The verifier specifies an inclusive interval:

    cutoff <= birth_date <= earliest

The prover demonstrates that the authenticated birth_date satisfies
the interval without revealing the actual date of birth.

## Supported credentials

- The credential must contain an issuer-signed `birth_date` attribute.
- The expected attribute namespace is `org.iso.18013.5.1`.
- The attribute uses the supported CBOR full-date encoding.
- Credentials may contain additional attributes.
- Only `birth_date` is requested for the DOB-only proof.
- A credential without `birth_date` cannot generate this proof.

This standalone circuit is specialized for DOB verification and
does not support arbitrary attribute predicates.

## Build

From the repository's `rust` directory:

    cargo build -p mdoc-zk-runtime --bin dob_cli

The executable is:

    target/debug/dob_cli

## Generate the circuit archive

From the `rust` directory:

    LONGFELLOW_DOB_EXPORT_DIR="$HOME/longfellow-dob-only-export" \
      cargo test -p mdoc-zk-runtime --test runtime_tests \
      test_google_dob_only -- --nocapture

This generates:

- circuits.zst
- circuits.lfa
- circuit-id.txt
- config.txt

The CLI loads the compressed archive from
`$HOME/longfellow-dob-only-export/circuits.zst` by default.

Set `DOB_CIRCUITS_ZST` to select another archive location.

The archive must match the circuit ID pinned in `dob_cli.rs`.

## Generate a DOB proof

    dob_cli prove \
      <mdoc> <transcript> <pkx> <pky> \
      <doc_type> <now> <cutoff> <earliest> <proof_out>

Inputs:

- mdoc: binary mDL credential
- transcript: binary session transcript
- pkx, pky: trusted issuer public-key coordinates
- doc_type: credential document type
- now: verification timestamp
- cutoff: inclusive lower DOB bound (YYYY-MM-DD)
- earliest: inclusive upper DOB bound (YYYY-MM-DD)
- proof_out: output proof file

For example, for a credential whose birth date is within
1960-01-01 and 1980-12-31:

    dob_cli prove \
      mdoc.bin transcript.bin \
      "$PKX" "$PKY" \
      org.iso.18013.5.1.mDL \
      2024-10-01T09:00:00Z \
      1960-01-01 1980-12-31 proof.bin

The issuer key, transcript, document type, and timestamp must
correspond to the actual credential and verification session.

## Verify a DOB proof

    dob_cli verify \
      <proof> <transcript> <pkx> <pky> \
      <doc_type> <now> <cutoff> <earliest>

Example:

    dob_cli verify \
      proof.bin transcript.bin \
      "$PKX" "$PKY" \
      org.iso.18013.5.1.mDL \
      2024-10-01T09:00:00Z \
      1960-01-01 1980-12-31

Successful verification prints:

    DOB PROOF VERIFIED

The verifier does not need to receive the actual birth date.

## Official Longfellow test fixture

The integration test uses an official mDL test vector with
birth_date 1971-09-01.

To export its inputs:

    DOB_CLI_FIXTURE_DIR=/tmp/longfellow-dob-cli-test \
      cargo test -p mdoc-zk-runtime --test runtime_tests \
      test_google_dob_only -- --nocapture

Generated files:

- mdoc.bin
- transcript.bin
- metadata.txt

The metadata contains four lines:

1. Issuer public-key X coordinate
2. Issuer public-key Y coordinate
3. Document type
4. Verification timestamp

The exported files can be used with `dob_cli prove` and
`dob_cli verify`.

## Tests

From the `rust` directory:

    cargo test -p mdoc-zk-circuits

    cargo test -p mdoc-zk-runtime --test runtime_tests \
      test_google_dob_only -- --nocapture

The DOB runtime regression covers successful verification,
invalid issuer keys, modified transcripts, DOB interval failures,
circuit ID integrity, and negative verifier cases.

## Security and limitations

- The DOB is not explicitly provided to the verifier.
- The verifier must independently trust the issuer public key.
- The verification policy must supply appropriate DOB bounds.
- Public bounds must be consistent with the intended age policy.
- The DOB circuit checks the expected date representation and
  lexicographic interval, but does not independently enforce full
  Gregorian calendar validity for the issuer-signed DOB.
- The CLI validates public interval bounds as calendar dates.
- The current implementation is specialized for one requested
  `birth_date` attribute and uses its own compiled circuit archive.
- This implementation is a research prototype; passing tests
  does not constitute an independent security audit.

## Age-verification example

For an age-at-least-18 policy, the verifier can select an upper
DOB bound equal to the verification date minus 18 calendar years,
together with a suitable lower bound.

The circuit then proves that the authenticated DOB belongs to
the selected interval.

Unlike issuer-signed `age_over_18` Boolean verification, this
approach can support different age thresholds using the same
authenticated DOB and circuit, provided the bounds are chosen
correctly.
