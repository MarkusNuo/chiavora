//! Cost reports for the reference handset: ignored tests that print numbers to record.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use chiavora_core::derive::{
    derive_root_key, AccountIdentifiers, DeriveError, KdfParams, I4_FLOOR_ITERATIONS,
};
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::secret::{
    kind::{AccountPassword, Muk, SecretKeyMaterial},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};

const ACCOUNT_ID: &[u8] = b"0123456789abcdef";
const ACCOUNT_SALT: &[u8] = b"0123456789abcdef0123456789abcdef";

// External secrets have no public constructor, so these go through the real entry points.
fn password() -> Secret<AccountPassword> {
    accept::<PasswordField>(b"correct horse battery staple".to_vec()).expect("a valid password")
}

fn secret_key() -> Secret<SecretKeyMaterial> {
    accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec())
        .expect("a valid Secret Key")
}

fn ids() -> AccountIdentifiers<'static> {
    AccountIdentifiers {
        account_id: ACCOUNT_ID,
        account_salt: ACCOUNT_SALT,
    }
}

/// `MemTotal` and `MemAvailable` in KiB, when `/proc/meminfo` is readable.
fn meminfo() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let field = |name: &str| -> Option<u64> {
        text.lines()
            .find(|l| l.starts_with(name))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    };
    Some((field("MemTotal:")?, field("MemAvailable:")?))
}

fn print_meminfo(when: &str) {
    // Hundredths of a GiB in integer maths, to avoid a float cast.
    if let Some((total, avail)) = meminfo() {
        let hundredths = |kib: u64| (kib * 100) / (1024 * 1024);
        println!(
            "  [{when}] MemTotal {}.{:02} GiB, MemAvailable {}.{:02} GiB",
            hundredths(total) / 100,
            hundredths(total) % 100,
            hundredths(avail) / 100,
            hundredths(avail) % 100
        );
    } else {
        println!("  [{when}] /proc/meminfo not readable (not Linux)");
    }
}

fn time_one(memory_kib: u32, iterations: u32) -> Result<Duration, DeriveError> {
    let params = KdfParams::new(memory_kib, iterations)?;
    let t = Instant::now();
    let key = derive_root_key(&password(), &secret_key(), ids(), params)?;
    let elapsed = t.elapsed();
    drop(key);
    Ok(elapsed)
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// §2.1's procedure: the highest `m` that allocates, then the lowest `t` that costs ≥ 500 ms.
#[test]
#[ignore = "prints the Argon2id cost report for this machine; run explicitly"]
fn report_kdf_cost_on_this_machine() {
    const RUNS: usize = 5;
    const TARGET: Duration = Duration::from_millis(500);
    const MIB: u32 = 1024;

    println!();
    println!("=== Argon2id cost report (p = 4, per §2.1) ===");
    print_meminfo("before");
    println!();
    println!(
        "step 1: which memlimit allocates, at the I4 iteration floor t = {I4_FLOOR_ITERATIONS}"
    );
    println!("  {:>10}  {:>12}  {:>10}", "m", "allocates", "median");

    let mut highest_that_allocates: Option<u32> = None;
    for mib in [64_u32, 128, 256, 512, 1024] {
        let memory_kib = mib * MIB;
        let mut samples = Vec::with_capacity(RUNS);
        let mut failure: Option<DeriveError> = None;
        for _ in 0..RUNS {
            match time_one(memory_kib, I4_FLOOR_ITERATIONS) {
                Ok(d) => samples.push(d),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = failure {
            println!("  {mib:>8} MiB  {:>12}  {:>10}", "NO", format!("{e:?}"));
        } else {
            let m = median(samples);
            println!("  {mib:>8} MiB  {:>12}  {:>10?}", "yes", m);
            highest_that_allocates = Some(mib);
        }
    }

    // Capped at §2.1's 256 MiB target: the weakest device that unlocks the account bounds it.
    let chosen_mib = highest_that_allocates
        .map(|m| m.min(256))
        .expect("at least the I4 floor must allocate");
    println!();
    println!("  highest that allocated here: {highest_that_allocates:?} MiB");
    println!("  taken forward (capped at §2.1's 256 MiB target): {chosen_mib} MiB");

    println!();
    println!("step 2: raise t at m = {chosen_mib} MiB until the derivation costs >= 500 ms");
    println!("  {:>4}  {:>12}  {:>8}", "t", "median", "meets");
    let mut chosen_t: Option<u32> = None;
    for t in I4_FLOOR_ITERATIONS..=32 {
        let mut samples = Vec::with_capacity(RUNS);
        for _ in 0..RUNS {
            match time_one(chosen_mib * MIB, t) {
                Ok(d) => samples.push(d),
                Err(e) => panic!("allocation failed at t={t}: {e:?}"),
            }
        }
        let m = median(samples);
        let meets = m >= TARGET;
        println!(
            "  {t:>4}  {m:>12?}  {:>8}",
            if meets { "YES" } else { "no" }
        );
        if meets {
            chosen_t = Some(t);
            break;
        }
    }

    println!();
    print_meminfo("after");
    match chosen_t {
        Some(t) => {
            println!();
            println!("RESULT  m = {chosen_mib} MiB, t = {t}, p = 4");
            println!("        (allocate AND complete: allocation succeeded in the shell cgroup;");
            println!(" backgrounded-under-pressure is NOT settled here --)");
        }
        None => println!("RESULT  no t <= 32 reached 500 ms at m = {chosen_mib} MiB"),
    }
}

/// The local store's write cost at 1k, 10k and 50k items; a proxy, not the manifest write cost.
#[test]
#[ignore = "prints the store write-cost report for this machine; run explicitly"]
fn report_store_write_costs_on_this_machine() {
    const RECORD_BYTES: usize = 1024;

    println!();
    println!("=== store write cost (NOT the manifest measurement -- see the doc comment) ===");
    print_meminfo("before");
    println!("  {:>8}  {:>12}  {:>14}", "items", "total", "per item");

    let muk = Secret::<Muk>::from_derived_bytes(vec![0x4D; 32]);
    for count in [1_000_usize, 10_000, 50_000] {
        let dir = std::env::current_dir().expect("a working directory");
        let path = dir.join(format!("write-cost-{count}.sqlite"));
        let _ = std::fs::remove_file(&path);

        let payload = vec![0xA5_u8; RECORD_BYTES];
        let mut store = Store::open(&path, &muk, Box::new(Unanchored)).expect("store opens");
        let t = Instant::now();
        for n in 0..count {
            store
                .put_raw(b"vault-1", format!("item-{n:06}").as_bytes(), 1, &payload)
                .expect("put_raw");
        }
        let total = t.elapsed();
        drop(store);

        println!(
            "  {count:>8}  {total:>12?}  {:>14?}",
            total / u32::try_from(count).expect("count fits")
        );
        let _ = std::fs::remove_file(&path);
    }

    let path = std::env::current_dir()
        .expect("a working directory")
        .join("write-cost-bulk.sqlite");
    let _ = std::fs::remove_file(&path);
    let payload = vec![0xA5_u8; RECORD_BYTES];
    let mut store = Store::open(&path, &muk, Box::new(Unanchored)).expect("store opens");
    let t = Instant::now();
    let mut bulk = store.begin_bulk().expect("begin");
    for n in 0..10_000 {
        bulk.store()
            .put_raw(b"vault-1", format!("item-{n:06}").as_bytes(), 1, &payload)
            .expect("put_raw");
    }
    bulk.commit().expect("commit");
    let total = t.elapsed();
    drop(store);
    println!(
        " 10000 {total:>12?} {:>14?} (one transaction)",
        total / 10_000
    );
    let _ = std::fs::remove_file(&path);

    print_meminfo("after");
}
