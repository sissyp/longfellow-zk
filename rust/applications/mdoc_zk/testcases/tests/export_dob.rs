use std::{env, fs, path::PathBuf};

use mdoc_zk_testcases::CASE_18PLUS__BIRTHDATE_1971_09_01_MDOC_3;

#[test]
fn export_longfellow_dob_example() {
    let data = &CASE_18PLUS__BIRTHDATE_1971_09_01_MDOC_3;

    let dir = PathBuf::from(
        env::var("HOME").expect("HOME missing")
    ).join("longfellow-dob-example");

    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join("mdoc.cbor"), data.mdoc).unwrap();
    fs::write(dir.join("transcript.cbor"), data.transcript).unwrap();
    fs::write(dir.join("pkx.txt"), data.pkx).unwrap();
    fs::write(dir.join("pky.txt"), data.pky).unwrap();
    fs::write(dir.join("doc-type.txt"), data.doc_type).unwrap();
    fs::write(dir.join("now.txt"), data.now).unwrap();

    println!("Exported example to {}", dir.display());
    println!("Document type: {}", data.doc_type);
    println!("Evaluation time: {}", data.now);
    println!("Issuer PKX: {}", data.pkx);
    println!("Issuer PKY: {}", data.pky);
    println!("Mdoc size: {} bytes", data.mdoc.len());
}
