use assert_cmd::Command;

#[test]
fn test_sig_keyfile() {
    static SIGSTRUCT: &'static [u8] = include_bytes!("./data/sig1.sigstruct.bin");
    let key_path = std::fs::canonicalize("tests/data/sig1.key.pem")
        .expect("can't get key path")
        .display()
        .to_string();
    let mut cmd = Command::cargo_bin("sgxs-sign").expect("cannot find binary");

    // check output hash of sig
    cmd.args(&[
        "--xfrm",
        "3/0xe4",
        "--date",
        "20160109",
        "--in-hash",
        "c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d",
        "--key",
        &key_path,
        "OUTPUT",
    ])
    .assert()
    .stdout("ENCLAVEHASH: c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d\n");

    // check output of signed struct
    let output = std::fs::read("./OUTPUT").expect("could not open key file");
    assert_eq!(output, SIGSTRUCT);
}

#[test]
fn test_sig_pipe_stdin() {
    static SIGSTRUCT: &'static [u8] = include_bytes!("./data/sig1.sigstruct.bin");
    let key = std::fs::read("tests/data/sig1.key.pem").expect("could not open key file");
    let mut cmd = Command::cargo_bin("sgxs-sign").expect("cannot find binary");

    // check output hash of sig
    cmd.write_stdin(key)
        .args(&[
            "--xfrm",
            "3/0xe4",
            "--date",
            "20160109",
            "--in-hash",
            "c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d",
            "OUTPUT",
        ])
        .assert()
        .stdout("ENCLAVEHASH: c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d\n");

    // check output of signed struct
    let output = std::fs::read("./OUTPUT").expect("could not open key file");
    assert_eq!(output, SIGSTRUCT);
}
