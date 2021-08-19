use assert_cmd::prelude::*;

use std::process::Command;

#[test]
fn hello_world() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let cmd = cmd.args(&["test", "-c", "./tests/hello_world.yaml"]);
    assert!(cmd.status().unwrap().success());
}
