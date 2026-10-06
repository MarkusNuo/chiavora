#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{CanonicalPrefix, ManifestError, StoredManifest};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{
    upload_with_retry, Backoff, CasRefused, ManifestTransport, RetryPolicy, StagedEdit, SyncOutcome,
};

const VAULT: &[u8] = b"vault-1";

fn key() -> Secret<VaultKey> {
    Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32])
}

fn store() -> Store {
    Store::open_in_memory(
        &Secret::<Muk>::from_derived_bytes(vec![0x4D; 32]),
        Box::new(Unanchored),
    )
    .expect("store")
}

fn edit(id: &[u8], version: u64, fill: u8) -> StagedEdit {
    StagedEdit::new(id.to_vec(), version, [fill; 32], false)
}

#[derive(Default)]
struct RecordingBackoff {
    waits: Vec<Duration>,
}

impl Backoff for RecordingBackoff {
    fn wait(&mut self, d: Duration) {
        self.waits.push(d);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reporting {
    Honest,
    Advancing,
    Inflating,
    Deflating,
}

struct Server {
    root: Option<Vec<u8>>,
    segment: Option<Vec<u8>>,
    current_seq: u64,
    reporting: Reporting,
    claimed: u64,
    accept_after: Option<u32>,
    refusals: u32,
}

impl Server {
    const fn new(reporting: Reporting) -> Self {
        Self {
            root: None,
            segment: None,
            current_seq: 0,
            reporting,
            claimed: 0,
            accept_after: None,
            refusals: 0,
        }
    }

    fn seq_of(bytes: &[u8]) -> u64 {
        match StoredManifest::decode(bytes).expect("well-formed").fields() {
            AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }

    /// Seeds a real root so `served` is non-zero and the pair is meaningful.
    fn seeded(reporting: Reporting) -> Self {
        let mut s = Self::new(Reporting::Honest);
        let mut st = store();
        chiavora_core::sync::upload(&mut s, &key(), &mut st, VAULT, &[edit(b"seed", 1, 0x01)])
            .expect("seeds");
        s.reporting = reporting;
        s.claimed = s.current_seq;
        s
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
        let accept = self.accept_after.is_some_and(|n| self.refusals >= n)
            && offered == self.current_seq + 1;
        if accept {
            self.root = Some(root.to_vec());
            self.segment = segments.first().cloned();
            self.current_seq = offered;
            return Ok(());
        }
        if self.accept_after.is_none()
            && offered == self.current_seq + 1
            && self.reporting == Reporting::Honest
            && self.root.is_none()
        {
            self.root = Some(root.to_vec());
            self.segment = segments.first().cloned();
            self.current_seq = offered;
            return Ok(());
        }

        self.refusals += 1;
        let report = match self.reporting {
            Reporting::Honest => self.current_seq,
            Reporting::Advancing => {
                self.root = Some(root.to_vec());
                self.segment = segments.first().cloned();
                self.current_seq = offered;
                self.current_seq
            }
            Reporting::Inflating => {
                self.claimed += 1;
                self.claimed
            }
            Reporting::Deflating => self.current_seq.saturating_sub(1),
        };
        Err(CasRefused {
            current_manifest_seq: report,
        })
    }
}

#[test]
fn a_client_that_keeps_losing_stops() {
    let mut server = Server::seeded(Reporting::Honest);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    )
    .expect("a bounded give-up is an outcome, not an error");

    assert!(
        matches!(out, SyncOutcome::ServerRefusing { attempts: 5, .. }),
        "it did not stop at the bound: {out:?}"
    );
    assert_eq!(
        backoff.waits.len(),
        4,
        "five attempts means four waits -- a wait after the last attempt is \
         time a user spends waiting for nothing"
    );
}

#[test]
fn the_waits_grow_are_capped_and_never_collapse_to_nothing() {
    let policy =
        RetryPolicy::new(8, Duration::from_millis(200), Duration::from_secs(5)).expect("policy");
    let mut server = Server::seeded(Reporting::Honest);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        policy,
        &mut backoff,
    )
    .expect("gives up");

    assert_eq!(backoff.waits.len(), 7);
    for (n, w) in backoff.waits.iter().enumerate() {
        assert!(
            *w >= Duration::from_millis(100),
            "wait {n} was {w:?}; equal jitter must keep a floor under every wait"
        );
        assert!(
            *w <= Duration::from_secs(5),
            "wait {n} was {w:?}, above the cap"
        );
    }
    let first = *backoff.waits.first().expect("one");
    let last = *backoff.waits.last().expect("one");
    assert!(
        last > first,
        "the backoff did not grow: {:?}",
        backoff.waits
    );
}

#[test]
fn two_clients_do_not_wait_in_lockstep() {
    let runs: Vec<Vec<Duration>> = (0..6)
        .map(|_| {
            let mut server = Server::seeded(Reporting::Honest);
            let mut st = store();
            let mut backoff = RecordingBackoff::default();
            upload_with_retry(
                &mut server,
                &key(),
                &mut st,
                VAULT,
                &[edit(b"a", 1, 0x11)],
                RetryPolicy::new(6, Duration::from_millis(200), Duration::from_secs(5))
                    .expect("policy"),
                &mut backoff,
            )
            .expect("gives up");
            backoff.waits
        })
        .collect();

    let first = runs.first().expect("a run");
    assert!(
        runs.iter().any(|r| r != first),
        "six runs produced identical wait sequences, so nothing is jittered"
    );
}

#[test]
fn a_write_that_lands_on_the_second_attempt_reports_two() {
    let mut server = Server::seeded(Reporting::Honest);
    server.accept_after = Some(1);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    )
    .expect("lands");

    assert!(
        matches!(out, SyncOutcome::Written { attempts: 2, .. }),
        "{out:?}"
    );
    assert_eq!(backoff.waits.len(), 1, "it waited more than it needed to");
}

#[test]
fn a_sequence_that_advances_is_contention() {
    let mut server = Server::seeded(Reporting::Advancing);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    )
    .expect("gives up");

    assert!(
        matches!(out, SyncOutcome::Contended { attempts: 5, .. }),
        "{out:?}"
    );
}

#[test]
fn a_sequence_that_never_moves_is_a_refusing_server() {
    let mut server = Server::seeded(Reporting::Honest);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    )
    .expect("gives up");

    assert!(
        matches!(out, SyncOutcome::ServerRefusing { attempts: 5, .. }),
        "{out:?}"
    );
}

#[test]
fn contention_and_refusal_are_distinct_variants_not_distinct_strings() {
    let contended = SyncOutcome::Contended {
        attempts: 5,
        observed: 9,
    };
    let refusing = SyncOutcome::ServerRefusing {
        attempts: 5,
        observed: 9,
    };
    assert_ne!(
        contended, refusing,
        "the same numbers produce the same outcome, so the distinction is in \
         the message rather than in the type -- which puts it hands \
         and not in this module's"
    );
}

#[test]
fn an_inflating_server_is_caught_and_this_is_the_decisive_one() {
    let mut server = Server::seeded(Reporting::Inflating);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    );

    assert!(
        matches!(
            out,
            Err(ManifestError::ServerReportedImpossibleSequence { .. })
        ),
        "an inflating server was read as contention, which is the message that \
         tells a user to wait: {out:?}"
    );
}

#[test]
fn a_deflating_server_is_caught_and_this_is_the_weaker_one() {
    // Without this check the client reports a refusing server: less precise, not wrong.
    let mut server = Server::seeded(Reporting::Deflating);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    );

    assert!(
        matches!(
            out,
            Err(ManifestError::ServerReportedImpossibleSequence {
                served: 1,
                reported: 0
            })
        ),
        "{out:?}"
    );
}

#[test]
fn an_honestly_advancing_server_is_not_mistaken_for_a_liar() {
    let mut server = Server::seeded(Reporting::Advancing);
    let mut st = store();
    let mut backoff = RecordingBackoff::default();

    let out = upload_with_retry(
        &mut server,
        &key(),
        &mut st,
        VAULT,
        &[edit(b"a", 1, 0x11)],
        RetryPolicy::standard(),
        &mut backoff,
    );
    assert!(
        matches!(out, Ok(SyncOutcome::Contended { .. })),
        "a server that really is contended was accused of lying: {out:?}"
    );
}

#[test]
fn a_policy_that_cannot_retry_is_refused_at_construction() {
    let ms = Duration::from_millis;
    for (attempts, base, cap) in [
        (0, ms(200), ms(5000)),
        (5, ms(0), ms(5000)),
        (5, ms(5000), ms(200)),
        (5, ms(200), Duration::from_secs(60 * 60 * 24 * 7)),
    ] {
        let out = RetryPolicy::new(attempts, base, cap);
        assert!(
            matches!(out, Err(ManifestError::UnusableRetryPolicy)),
            "({attempts}, {base:?}, {cap:?}) was accepted"
        );
    }
    RetryPolicy::new(3, ms(100), ms(1000)).expect("an ordinary policy");
}

#[test]
fn the_retry_path_reads_no_wall_clock() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sync.rs"),
    )
    .expect("sync.rs");
    // The module's comments name `SystemTime` to forbid it, so only code is scanned.
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    assert!(
        !code.contains("SystemTime"),
        "sync.rs reads the wall clock; ordering in §2.5 comes from manifestSeq"
    );
    assert!(
        source.contains("SystemTime"),
        "the module no longer says what it forbids, so this scan is guarding          a rule nobody reading the file would know about"
    );
}
