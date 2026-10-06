//! Compared by eye rather than through the server, since a server could tailor it per device.

use crate::manifest::{ManifestError, ManifestRoot, StoredManifest};

/// Taken from a single root, so the sequence and the digest cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMark {
    manifest_seq: u64,
    root_digest: [u8; 32],
}

impl DeviceMark {
    /// `stored` is the sealed record that `root` was opened from.
    pub fn of(root: &ManifestRoot, stored: &StoredManifest) -> Result<Self, ManifestError> {
        Ok(Self {
            manifest_seq: root.manifest_seq(),
            root_digest: stored.digest()?,
        })
    }

    #[must_use]
    pub const fn manifest_seq(&self) -> u64 {
        self.manifest_seq
    }

    #[must_use]
    pub const fn root_digest(&self) -> &[u8; 32] {
        &self.root_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkComparison {
    Agree {
        manifest_seq: u64,
    },
    Forked {
        manifest_seq: u64,
    },
    /// Not decisive: a device frozen by the server and a phone nobody has opened look
    /// the same. This is the accepted N3 residual.
    Behind {
        ahead: u64,
        behind: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N3Posture {
    /// No second device was reachable, so N3 is unmitigated; never shown as agreement.
    Unverified,
    Compared(MarkComparison),
}

#[must_use]
pub fn compare_with(mine: &DeviceMark, theirs: Option<&DeviceMark>) -> N3Posture {
    let Some(theirs) = theirs else {
        return N3Posture::Unverified;
    };
    N3Posture::Compared(compare(mine, theirs))
}

/// Symmetric, since each device passes its own mark first.
#[must_use]
pub fn compare(a: &DeviceMark, b: &DeviceMark) -> MarkComparison {
    if a.manifest_seq() != b.manifest_seq() {
        let (ahead, behind) = if a.manifest_seq() > b.manifest_seq() {
            (a.manifest_seq(), b.manifest_seq())
        } else {
            (b.manifest_seq(), a.manifest_seq())
        };
        return MarkComparison::Behind { ahead, behind };
    }
    if a.root_digest() == b.root_digest() {
        MarkComparison::Agree {
            manifest_seq: a.manifest_seq(),
        }
    } else {
        MarkComparison::Forked {
            manifest_seq: a.manifest_seq(),
        }
    }
}
