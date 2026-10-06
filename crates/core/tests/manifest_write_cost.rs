#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Instant;
use chiavora_core::manifest::{CanonicalPrefix, ManifestError, StoredManifest};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{upload, CasRefused, ManifestTransport, StagedEdit, Uploaded};

const VAULT: &[u8] = b"vault-measure";

const BUDGET_P95_MILLIS: u128 = 500;
const BUDGET_BYTES: usize = 64 * 1024;

struct Server {
    root: Option<Vec<u8>>,
    segment: Option<Vec<u8>>,
    current_seq: u64,
    last_write_bytes: usize,
}

impl Server {
    const fn empty() -> Self {
        Self {
            root: None,
            segment: None,
            current_seq: 0,
            last_write_bytes: 0,
        }
    }

    fn seq_of(bytes: &[u8]) -> u64 {
        match StoredManifest::decode(bytes).expect("well-formed").fields() {
            chiavora_core::aad::AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }
}

impl ManifestTransport for Server {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.root.clone())
    }

    fn fetch_segment(
        &mut self,
        _prefix: CanonicalPrefix,
    ) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.segment.clone())
    }

    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused> {
        let offered = Self::seq_of(root);
        if offered != self.current_seq + 1 {
            return Err(CasRefused {
                current_manifest_seq: self.current_seq,
            });
        }
        self.last_write_bytes = root.len() + segments.iter().map(Vec::len).sum::<usize>();
        self.root = Some(root.to_vec());
        self.segment = segments.first().cloned();
        self.current_seq = offered;
        Ok(())
    }
}

struct Measurement {
    items: usize,
    edits: usize,
    p95_millis: u128,
    median_millis: u128,
    bytes: usize,
}

fn measure(items: usize, edits: usize) -> Measurement {
    let key = Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32]);
    let mut store = Store::open_in_memory(
        &Secret::<Muk>::from_derived_bytes(vec![0x4D; 32]),
        Box::new(Unanchored),
    )
    .expect("store");
    let mut server = Server::empty();

    let staged: Vec<StagedEdit> = (0..items)
        .map(|i| {
            let mut digest = [0_u8; 32];
            digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
            StagedEdit::new(format!("item-{i}").into_bytes(), 1, digest, false)
        })
        .collect();
    let out = upload(&mut server, &key, &mut store, VAULT, &staged).expect("seeds");
    assert!(matches!(out, Uploaded::Written { .. }), "seeding failed");

    let mut timings = Vec::with_capacity(edits);
    let mut bytes = 0;
    for n in 0..edits {
        let mut digest = [0xEE_u8; 32];
        digest[..8].copy_from_slice(&(n as u64).to_be_bytes());
        let edit = StagedEdit::new(b"item-0".to_vec(), (n as u64) + 2, digest, false);

        let started = Instant::now();
        let out = upload(&mut server, &key, &mut store, VAULT, &[edit]).expect("edit");
        timings.push(started.elapsed().as_millis());

        assert!(matches!(out, Uploaded::Written { .. }), "edit {n} lost");
        bytes = server.last_write_bytes;
    }

    timings.sort_unstable();
    // p95 by nearest rank; under 20 samples it is the maximum.
    let rank = (timings.len() * 95).div_ceil(100).saturating_sub(1);
    Measurement {
        items,
        edits: timings.len(),
        p95_millis: *timings.get(rank).expect("at least one timing"),
        median_millis: *timings.get(timings.len() / 2).expect("at least one"),
        bytes,
    }
}

fn report(m: &Measurement) {
    let time_ok = m.p95_millis <= BUDGET_P95_MILLIS;
    let bytes_ok = m.bytes <= BUDGET_BYTES;
    println!();
    println!("manifest write cost");
    println!("  items in vault      {}", m.items);
    println!("  edits timed         {}", m.edits);
    if m.edits < 20 {
        println!("  NOTE: under 20 samples, p95 by nearest rank is the maximum");
    }
    println!("  median              {} ms", m.median_millis);
    println!(
        "  p95                 {} ms   budget {BUDGET_P95_MILLIS} ms   {}",
        m.p95_millis,
        if time_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "  bytes per edit      {} B    budget {BUDGET_BYTES} B    {}",
        m.bytes,
        if bytes_ok { "PASS" } else { "FAIL" }
    );
    println!("  budget is PROVISIONAL -- revision allowed, with its reason");
    println!();
}

/// `CHIAVORA_MEASURE_ITEMS` and `CHIAVORA_MEASURE_EDITS` override the item and sample counts.
#[test]
#[ignore = "a measurement, not an assertion; run explicitly with --nocapture"]
fn measure_manifest_write_cost() {
    let items = std::env::var("CHIAVORA_MEASURE_ITEMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let edits = std::env::var("CHIAVORA_MEASURE_EDITS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    report(&measure(items, edits));
}

#[test]
fn the_measurement_path_runs_at_a_small_size() {
    let m = measure(50, 5);
    assert_eq!(m.items, 50);
    assert_eq!(m.edits, 5);
    assert!(m.bytes > 0, "a write that carried no bytes was not a write");
    assert!(
        m.p95_millis >= m.median_millis,
        "p95 below the median means the ranking is wrong"
    );
    report(&m);
}
