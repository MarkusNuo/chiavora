//! Input is `u16le(len) ‖ AAD ‖ body`: the server picks the AAD independently of the body.
#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::aad::{self, AadFields};
use chiavora_core::manifest::{ManifestRoot, ManifestSegment, StoredManifest};

const PROBES: [u64; 8] = [
    0,
    1,
    u64::MAX,
    u64::MAX - 1,
    0x8000_0000_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x5555_5555_5555_5555,
    0xaaaa_aaaa_aaaa_aaaa,
];

fuzz_target!(|data: &[u8]| {
    // The same bytes also go to the stored-record framing the server actually sends.
    if let Ok(stored) = StoredManifest::decode(data) {
        let digest = stored.digest().expect("an accepted record digests");
        let encoded = stored.encode().expect("an accepted record re-encodes");
        let again = StoredManifest::decode(&encoded).expect("a re-encoded record decodes");
        assert_eq!(again, stored, "a round trip changed the stored record");
        assert_eq!(
            again.digest().expect("digest"),
            digest,
            "a round trip changed the digest a root entry vouches for"
        );
    }

    if data.len() < 2 {
        return;
    }
    let (len_bytes, rest) = data.split_at(2);
    let len = usize::from(u16::from_le_bytes([
        *len_bytes.first().unwrap_or(&0),
        *len_bytes.get(1).unwrap_or(&0),
    ]));
    if len > rest.len() {
        return;
    }
    let (aad_bytes, body) = rest.split_at(len);

    let Ok(fields) = aad::decode(aad_bytes) else {
        return;
    };

    match fields {
        AadFields::ManifestRoot { segment_count, .. } => {
            let Ok(root) = ManifestRoot::decode(fields.clone(), body) else {
                return;
            };

            assert_eq!(
                usize::try_from(segment_count).ok(),
                Some(root.segments().len()),
                "an accepted root disagrees with its own declared segment count"
            );

            for entry in root.segments() {
                let prefix = entry.prefix();
                assert!(
                    aad::check_prefix(prefix.bit_len(), prefix.bits()).is_ok(),
                    "a non-canonical prefix survived into a RootEntry"
                );
            }

            if root.check_tiles().is_ok() {
                for probe in PROBES {
                    assert!(
                        root.segment_for(probe).is_some(),
                        "check_tiles accepted a root with no segment for a hash"
                    );
                }
            }

            let encoded = root.encode_body().expect("an accepted root re-encodes");
            let again = ManifestRoot::decode(fields, &encoded).expect("a re-encoded root decodes");
            assert_eq!(again, root, "a round trip changed the root");
            assert_eq!(
                again.encode_body().expect("encodes"),
                encoded,
                "encode is not idempotent, so a digest over it is not stable"
            );
        }
        AadFields::ManifestSegment { .. } => {
            let Ok(segment) = ManifestSegment::decode(fields.clone(), body) else {
                return;
            };

            segment
                .prefix()
                .expect("a decoded 0x04 AAD carries a canonical prefix");

            let encoded = segment.encode_body().expect("an accepted segment re-encodes");
            let again =
                ManifestSegment::decode(fields, &encoded).expect("a re-encoded segment decodes");
            assert_eq!(again, segment, "a round trip changed the segment");
            assert_eq!(
                again.encode_body().expect("encodes"),
                encoded,
                "encode is not idempotent, so the root's digest over it is not stable"
            );
        }
        _ => {}
    }
});
