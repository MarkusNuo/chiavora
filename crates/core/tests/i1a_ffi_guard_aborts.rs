//! Each case re-runs this binary as a child, since an abort cannot be observed from inside.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Stdio};

use chiavora_core::ffi_guard::{assert_not_key_material, live_key_material_count};
use chiavora_core::secret::{kind::Muk, Secret};

const MODE: &str = "CHIAVORA_FFI_GUARD_TEST_MODE";

fn run_child_if_asked() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let secret = Secret::<Muk>::from_derived_bytes(vec![0x5A; 32]);
    let bytes = secret.expose().to_vec();

    match mode.as_str() {
        "verbatim" => assert_not_key_material(&bytes),
        "embedded" => {
            let mut buffer = b"harmless prefix ".to_vec();
            buffer.extend_from_slice(&bytes);
            buffer.extend_from_slice(b" harmless suffix");
            assert_not_key_material(&buffer);
        }
        other => panic!("unknown child mode {other:?}"),
    }

    // Reached only if the guard did not abort.
    std::process::exit(0);
}

fn child_aborted(mode: &str) -> (bool, String) {
    run_child_if_asked();

    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new(exe)
        .env(MODE, mode)
        // Without `--nocapture` the guard's message stays in libtest's capture buffer
        // and is lost when the child aborts.
        .arg("--test-threads=1")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("child must launch");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // On Windows an abort is an exception code, not a signal, so check only for a non-zero exit.
    let aborted = !output.status.success();
    (aborted, stderr)
}

#[test]
fn the_guard_aborts_on_verbatim_key_material() {
    let (aborted, stderr) = child_aborted("verbatim");
    assert!(
        aborted,
        "the guard returned instead of aborting; child stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("I1(a) violated"),
        "the abort must name the invariant it defends; child stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("verbatim"),
        "the abort must say what happened; child stderr:\n{stderr}"
    );
}

#[test]
fn the_guard_aborts_on_key_material_embedded_in_a_larger_buffer() {
    let (aborted, stderr) = child_aborted("embedded");
    assert!(
        aborted,
        "the guard missed embedded key material; child stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("inside a buffer"),
        "the abort must distinguish embedded from verbatim; child stderr:\n{stderr}"
    );
}

#[test]
fn the_abort_message_names_no_bytes() {
    // The child's secret is 32 bytes of 0x5A.
    let (_aborted, stderr) = child_aborted("verbatim");
    let leaked = "5a".repeat(32);
    assert!(
        !stderr.to_lowercase().contains(&leaked),
        "the abort message leaked the key material it was reporting on"
    );
    assert!(
        !stderr.contains("ZZZZZZZZ"),
        "sanity: the marker byte pattern must not appear as text either"
    );
}

#[test]
fn the_guard_lets_unrelated_buffers_through_in_this_process() {
    let count_before = live_key_material_count();
    let secret = Secret::<Muk>::from_derived_bytes(vec![0x11; 32]);
    assert!(live_key_material_count() > count_before);

    assert_not_key_material(b"chiavora-ffi-node:ok");
    assert_not_key_material(&[0u8; 64]);

    drop(secret);
    assert_eq!(live_key_material_count(), count_before);
}
