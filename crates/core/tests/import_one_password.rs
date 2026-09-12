#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Cursor;
use std::path::PathBuf;

use chiavora_core::attachment::MAX_ATTACHMENT_BYTES;
use chiavora_core::import::{
    ImportError, MoveKind, Outcome, PreserveReason, RefusalReason, FIELD_NOTES, FIELD_PASSWORD,
    FIELD_TOTP,
};
use chiavora_core::model::{Item, FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use chiavora_core::onepif;
use chiavora_core::onepux;
use chiavora_core::wrap::ItemKind;
use chiavora_core::zip::{self, Limits, ZipError, ONE_PUX_LIMITS};
use miniz_oxide::deflate::compress_to_vec;

const STORED: u16 = 0;
const DEFLATE: u16 = 8;
const MADE_BY_UNIX: u16 = 3 << 8;
const UNIX_SYMLINK: u32 = 0o120_777 << 16;

#[derive(Clone, Default)]
struct Opts {
    method: u16,
    flags: u16,
    made_by: u16,
    external: u32,
    crc: Option<u32>,
    uncompressed: Option<u32>,
    compressed: Option<u32>,
    raw: Option<Vec<u8>>,
}

fn deflated() -> Opts {
    Opts {
        method: DEFLATE,
        ..Opts::default()
    }
}

fn stored() -> Opts {
    Opts {
        method: STORED,
        ..Opts::default()
    }
}

struct ZipWriter {
    data: Vec<u8>,
    central: Vec<u8>,
    count: u16,
}

fn le16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn le32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn len32(len: usize) -> u32 {
    u32::try_from(len).unwrap()
}

fn len16(len: usize) -> u16 {
    u16::try_from(len).unwrap()
}

/// CRC-32 (IEEE), bitwise.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

impl ZipWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            central: Vec::new(),
            count: 0,
        }
    }

    fn add(&mut self, name: &str, content: &[u8], opts: &Opts) -> &mut Self {
        let compressed = match &opts.raw {
            Some(raw) => raw.clone(),
            None if opts.method == DEFLATE => compress_to_vec(content, 6),
            None => content.to_vec(),
        };
        let crc = opts.crc.unwrap_or_else(|| crc32(content));
        let uncompressed = opts.uncompressed.unwrap_or_else(|| len32(content.len()));
        let compressed_len = opts.compressed.unwrap_or_else(|| len32(compressed.len()));
        let offset = len32(self.data.len());

        let d = &mut self.data;
        d.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        le16(d, 20);
        le16(d, opts.flags);
        le16(d, opts.method);
        le16(d, 0);
        le16(d, 0);
        le32(d, crc);
        le32(d, compressed_len);
        le32(d, uncompressed);
        le16(d, len16(name.len()));
        le16(d, 0);
        d.extend_from_slice(name.as_bytes());
        d.extend_from_slice(&compressed);

        let c = &mut self.central;
        c.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        le16(c, opts.made_by);
        le16(c, 20);
        le16(c, opts.flags);
        le16(c, opts.method);
        le16(c, 0);
        le16(c, 0);
        le32(c, crc);
        le32(c, compressed_len);
        le32(c, uncompressed);
        le16(c, len16(name.len()));
        le16(c, 0);
        le16(c, 0);
        le16(c, 0);
        le16(c, 0);
        le32(c, opts.external);
        le32(c, offset);
        c.extend_from_slice(name.as_bytes());
        self.count += 1;
        self
    }

    fn finish(self) -> Vec<u8> {
        let mut out = self.data;
        let cd_offset = len32(out.len());
        out.extend_from_slice(&self.central);
        out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        le16(&mut out, 0);
        le16(&mut out, 0);
        le16(&mut out, self.count);
        le16(&mut out, self.count);
        le32(&mut out, len32(self.central.len()));
        le32(&mut out, cd_offset);
        le16(&mut out, 0);
        out
    }
}

const EXPORT_DATA: &str = r#"{"accounts":[{"attrs":{"accountName":"Test","name":"Test","uuid":"acct-1"},"vaults":[{"attrs":{"uuid":"vault-1","name":"Personal","type":"P"},"items":[
{"uuid":"item-0001","favIndex":0,"createdAt":1700000000,"updatedAt":1700000100,"state":"active","categoryUuid":"001",
 "details":{"loginFields":[{"value":"alice@example.test","id":"u","name":"username","fieldType":"E","designation":"username"},{"value":"correct-horse-battery","id":"p","name":"password","fieldType":"P","designation":"password"},{"value":"remember","id":"r","name":"remember_me","fieldType":"C"}],
  "notesPlain":"a note about the login",
  "sections":[{"title":"Security","name":"sec","fields":[{"title":"one-time password","id":"totp","value":{"totp":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"}},{"title":"recovery code","id":"rc","value":{"concealed":"RECOV-1234"}}]}],
  "passwordHistory":[{"value":"old-password-1","time":1690000000}]},
 "overview":{"title":"Example Login","url":"https://example.test/login","urls":[{"label":"main","url":"https://example.test/login"},{"label":"alt","url":"https://alt.example.test"}],"tags":["work","imported"],"subtitle":"alice@example.test","ps":80}},
{"uuid":"item-0002","state":"active","categoryUuid":"002",
 "details":{"sections":[{"title":"","name":"","fields":[{"title":"cardholder name","id":"cardholder","value":{"string":"Alice Example"}},{"title":"number","id":"ccnum","value":{"creditCardNumber":"4111111111111111"}},{"title":"verification number","id":"cvv","value":{"concealed":"123"}},{"title":"expiry date","id":"expiry","value":{"monthYear":202812}},{"title":"type","id":"type","value":{"creditCardType":"visa"}}]}]},
 "overview":{"title":"Example Card"}},
{"uuid":"item-0003","state":"active","categoryUuid":"003",
 "details":{"notesPlain":"the body of the note","sections":[{"title":"Extra","fields":[{"title":"riddle","id":"r","value":{"mystery":"value-x"}}]}]},
 "overview":{"title":"Example Note"}},
{"uuid":"item-0004","state":"active","categoryUuid":"004",
 "details":{"sections":[{"title":"Identification","fields":[{"title":"first name","id":"firstname","value":{"string":"Alice"}},{"title":"last name","id":"lastname","value":{"string":"Example"}}]},{"title":"Address","fields":[{"title":"address","id":"address","value":{"address":{"street":"1 Test Street","city":"Testville","zip":"9000","country":"ch"}}}]}]},
 "overview":{"title":"Example Identity"}},
{"uuid":"item-0005","state":"active","categoryUuid":"114",
 "details":{"sections":[{"title":"","fields":[{"title":"private key","id":"private_key","value":{"sshKey":{"privateKey":"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----","metadata":{"publicKey":"ssh-ed25519 AAAAfake","fingerprint":"SHA256:fake","keyType":"ed25519"}}}}]}]},
 "overview":{"title":"Example SSH Key"}},
{"uuid":"item-0006","state":"active","categoryUuid":"101",
 "details":{"sections":[{"title":"","fields":[{"title":"account number","id":"accountNo","value":{"string":"12345678"}},{"title":"routing number","id":"routingNo","value":{"string":"87654321"}},{"title":"PIN","id":"telephonePin","value":{"concealed":"0000"}}]}]},
 "overview":{"title":"Example Bank Account"}},
{"uuid":"item-0007","state":"active","categoryUuid":"999",
 "details":{"loginFields":[{"value":"bob@example.test","designation":"username"},{"value":"unknown-category-password","designation":"password"}],"weird":{"deep":[1,2,3]}},
 "overview":{"title":"Unknown Category"}},
{"uuid":"item-0008","state":"active","categoryUuid":"006",
 "details":{"documentAttributes":{"fileName":"scan.pdf","documentId":"doc-1","decryptedSize":6}},
 "overview":{"title":"Example Document"}},
{"uuid":"item-0009","state":"archived","trashed":true,"favIndex":1,"categoryUuid":"001",
 "details":{"loginFields":[{"value":"archived-user","designation":"username"},{"value":"archived-password","designation":"password"}]},
 "overview":{"title":"Archived Login","url":"https://old.example.test"}},
{"uuid":"item-0010","state":"active","categoryUuid":"001",
 "details":{"loginFields":[{"value":"carol","designation":"username"},{"value":"carol-password","designation":"password"}],"sections":[{"title":"Files","fields":[{"title":"backup","id":"f","value":{"file":{"documentId":"doc-2","fileName":"big.bin"}}}]}]},
 "overview":{"title":"Login With Big Attachment"}},
"just a string where an item should be",
{"uuid":"item-0012","state":"active","categoryUuid":"001",
 "details":{"loginFields":[{"value":"dave","designation":"username"},{"value":"dave-password","designation":"password"}],"sections":[{"title":"Files","fields":[{"title":"corrupt","id":"f","value":{"file":{"documentId":"doc-3","fileName":"crc.bin"}}}]}]},
 "overview":{"title":"Login With Corrupt Attachment"}}
]}]}]}"#;

const SCAN_PDF: &[u8] = b"%PDF-x";
const CRC_BIN: &[u8] = b"these bytes do not match their crc";

fn fixture() -> Vec<u8> {
    let mut z = ZipWriter::new();
    z.add(
        "export.attributes",
        br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#,
        &deflated(),
    );
    z.add("export.data", EXPORT_DATA.as_bytes(), &deflated());
    z.add("files/", b"", &stored());
    z.add("files/doc-1__scan.pdf", SCAN_PDF, &deflated());
    // Declared at 101 MiB so that the attachment policy, not the zip bounds, refuses it.
    let big = len32((MAX_ATTACHMENT_BYTES + (1 << 20)).try_into().unwrap());
    z.add(
        "files/doc-2__big.bin",
        b"tiny",
        &Opts {
            uncompressed: Some(big),
            compressed: Some(big),
            ..stored()
        },
    );
    z.add(
        "files/doc-3__crc.bin",
        CRC_BIN,
        &Opts {
            crc: Some(0xDEAD_BEEF),
            ..deflated()
        },
    );
    z.add("../escape.txt", b"outside", &stored());
    z.add("files/inner.zip", b"PK\x03\x04not really", &stored());
    z.add(
        "files/link",
        b"/etc/passwd",
        &Opts {
            made_by: MADE_BY_UNIX,
            external: UNIX_SYMLINK,
            ..stored()
        },
    );
    z.add(
        "bomb.bin",
        b"x",
        &Opts {
            uncompressed: Some(200 << 20),
            compressed: Some(100),
            ..deflated()
        },
    );
    z.finish()
}

/// Bytes that do not compress, so a fixture member does not trip the ratio refusal.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xFF).unwrap()
        })
        .collect()
}

fn field<'a>(item: &'a Item, name: &str) -> &'a [u8] {
    item.field(name)
        .unwrap_or_else(|| {
            panic!(
                "no field {name:?}; has {:?}",
                item.fields()
                    .map(|f| f.name().as_str().to_owned())
                    .collect::<Vec<_>>()
            )
        })
        .value()
}

fn tags(item: &Item) -> Vec<&str> {
    item.tags()
        .map(chiavora_core::model::Name::as_str)
        .collect()
}

#[test]
fn a_synthetic_1pux_imports_with_one_report_line_per_item() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    assert_eq!(
        imported.items.len(),
        12,
        "twelve items in the fixture, including the non-object"
    );
    assert_eq!(imported.report.records().len(), imported.items.len());
    assert_eq!(imported.report.records()[0].title(), "Example Login");
    assert_eq!(imported.report.records()[0].source_type(), "Login (001)");
    assert_eq!(imported.report.mapped(), 9);
    assert_eq!(imported.report.preserved(), 3);
}

#[test]
fn categories_land_on_the_kinds_the_table_says() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let outcomes: Vec<(ItemKind, Outcome)> = imported
        .items
        .iter()
        .zip(imported.report.records())
        .map(|(i, r)| (i.item.kind(), r.outcome()))
        .collect();
    let mapped = |k| (k, Outcome::Mapped(k));
    let preserved = |why| (ItemKind::Note, Outcome::PreservedAsNote(why));
    assert_eq!(
        outcomes,
        [
            mapped(ItemKind::Login),
            mapped(ItemKind::Card),
            mapped(ItemKind::Note),
            mapped(ItemKind::Identity),
            mapped(ItemKind::SshKey),
            preserved(PreserveReason::UnknownType), // Bank Account: no clean fit
            preserved(PreserveReason::UnknownType), // category 999
            mapped(ItemKind::Note),                 // Document
            mapped(ItemKind::Login),                // archived
            mapped(ItemKind::Login),                // big attachment
            preserved(PreserveReason::Malformed),   // the bare string
            mapped(ItemKind::Login),                // corrupt attachment
        ]
    );
}

#[test]
fn login_fields_move_where_the_report_says() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let login = &imported.items[0].item;
    assert_eq!(field(login, FIELD_TITLE), b"Example Login");
    assert_eq!(field(login, FIELD_USERNAME), b"alice@example.test");
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert_eq!(field(login, FIELD_URL), b"https://example.test/login");
    assert_eq!(field(login, "url 2"), b"https://alt.example.test");
    assert_eq!(field(login, "url 2 label"), b"alt");
    assert_eq!(
        field(login, "url label"),
        b"main",
        "the repeated primary URL keeps its label against the field that has it"
    );
    assert_eq!(field(login, FIELD_NOTES), b"a note about the login");
    assert_eq!(field(login, "remember_me"), b"remember");
    assert_eq!(field(login, "Security/recovery code"), b"RECOV-1234");
    assert_eq!(field(login, "password history 1"), b"old-password-1");
    assert_eq!(field(login, "password history 1 time"), b"1690000000");
    assert_eq!(
        field(login, "subtitle"),
        b"alice@example.test",
        "a derived field is still kept"
    );
    assert_eq!(
        field(login, "ps"),
        b"80",
        "an unknown overview key is kept under its own name"
    );
    assert_eq!(tags(login), ["work", "imported"]);

    let moves = imported.report.records()[0].moves();
    let password = moves
        .iter()
        .find(|m| m.to() == FIELD_PASSWORD)
        .expect("the password's move is reported");
    assert_eq!(password.from(), "details.loginFields[1]");
    assert_eq!(password.kind(), MoveKind::Mapped);
    let kept = moves.iter().find(|m| m.to() == "ps").unwrap();
    assert_eq!(kept.kind(), MoveKind::Preserved);
}

#[test]
fn a_totp_on_a_login_stays_a_field_on_the_login() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let login = &imported.items[0].item;
    assert_eq!(login.kind(), ItemKind::Login);
    assert!(field(login, FIELD_TOTP).starts_with(b"otpauth://totp/"));
    assert!(
        imported
            .items
            .iter()
            .all(|i| i.item.kind() != ItemKind::Totp),
        "1Password has no standalone TOTP category, so none should appear"
    );
}

#[test]
fn every_value_kind_in_a_section_is_kept_by_name() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let card = &imported.items[1].item;
    assert_eq!(field(card, "cardholder name"), b"Alice Example");
    assert_eq!(field(card, "number"), b"4111111111111111");
    assert_eq!(field(card, "verification number"), b"123");
    assert_eq!(field(card, "expiry date"), b"202812");
    assert_eq!(field(card, "type"), b"visa");

    let note = &imported.items[2].item;
    assert_eq!(field(note, FIELD_NOTES), b"the body of the note");
    assert_eq!(
        field(note, "Extra/riddle"),
        b"value-x",
        "an unknown value kind is kept, not dropped"
    );
    let riddle = imported.report.records()[2]
        .moves()
        .iter()
        .find(|m| m.to() == "Extra/riddle")
        .unwrap();
    assert_eq!(riddle.kind(), MoveKind::Preserved);

    let identity = &imported.items[3].item;
    assert_eq!(field(identity, "Identification/first name"), b"Alice");
    assert_eq!(field(identity, "Address/address/street"), b"1 Test Street");
    assert_eq!(field(identity, "Address/address/country"), b"ch");

    let ssh = &imported.items[4].item;
    assert!(field(ssh, "privateKey").starts_with(b"-----BEGIN OPENSSH"));
    assert_eq!(field(ssh, "publicKey"), b"ssh-ed25519 AAAAfake");
    assert_eq!(field(ssh, "keyType"), b"ed25519");
}

#[test]
fn what_has_no_clean_mapping_is_a_note_carrying_every_raw_field() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();

    let bank = &imported.items[5].item;
    assert_eq!(bank.kind(), ItemKind::Note);
    assert_eq!(field(bank, "account number"), b"12345678");
    assert_eq!(field(bank, "PIN"), b"0000");
    assert_eq!(
        imported.report.records()[5].source_type(),
        "Bank Account (101)"
    );

    let unknown = &imported.items[6].item;
    assert_eq!(unknown.kind(), ItemKind::Note);
    assert_eq!(field(unknown, FIELD_USERNAME), b"bob@example.test");
    assert_eq!(
        field(unknown, FIELD_PASSWORD),
        b"unknown-category-password",
        "the password of an unknown category is the case the rule exists for"
    );
    assert_eq!(
        field(unknown, "weird"),
        br#"{"deep":[1,2,3]}"#,
        "an unknown subtree is kept as compact JSON"
    );
    assert_eq!(
        imported.report.records()[6].source_type(),
        "unknown category (999)"
    );

    let junk = &imported.items[10].item;
    assert_eq!(junk.kind(), ItemKind::Note);
    assert_eq!(
        field(junk, "raw"),
        br#""just a string where an item should be""#
    );
    assert_eq!(
        imported.report.records()[10].outcome(),
        Outcome::PreservedAsNote(PreserveReason::Malformed)
    );

    let archived = &imported.items[8].item;
    assert_eq!(
        tags(archived),
        ["archived", "trashed", "favourite"],
        "state, trashed and favourite are tags, not skips"
    );
}

#[test]
fn attachments_stream_under_the_policy_and_refusals_are_named_on_the_record() {
    let (mut archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();

    let document = &imported.items[7];
    assert_eq!(document.attachments.len(), 1);
    let handle = &document.attachments[0];
    assert_eq!(handle.file_name(), "scan.pdf");
    assert_eq!(handle.declared_len(), SCAN_PDF.len() as u64);
    let mut out = Vec::new();
    let n = onepux::read_attachment(&mut archive, handle, &mut out).unwrap();
    assert_eq!(n, SCAN_PDF.len() as u64);
    assert_eq!(out, SCAN_PDF);

    let big = &imported.items[9];
    assert!(
        big.attachments.is_empty(),
        "no handle for a refused attachment"
    );
    let refused = imported.report.records()[9]
        .moves()
        .iter()
        .find(|m| m.kind() == MoveKind::AttachmentRefused)
        .expect("the refusal is on the record's line");
    assert_eq!(refused.from(), "details.sections[0].fields[0]");
    let listed = imported
        .report
        .refusals()
        .iter()
        .find(|r| r.record() == Some(9))
        .expect("and in the refusals");
    assert_eq!(
        *listed.reason(),
        RefusalReason::AttachmentTooLarge {
            max: MAX_ATTACHMENT_BYTES
        }
    );

    let corrupt = &imported.items[11];
    assert_eq!(corrupt.attachments.len(), 1);
    let mut sink = Vec::new();
    let err =
        onepux::read_attachment(&mut archive, &corrupt.attachments[0], &mut sink).unwrap_err();
    assert!(
        matches!(err, ImportError::Zip(ZipError::CrcMismatch { .. })),
        "{err:?}"
    );
}

#[test]
fn archive_level_refusals_are_named_and_the_rest_imports() {
    let (archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let unowned: Vec<&ZipError> = imported
        .report
        .refusals()
        .iter()
        .filter(|r| r.record().is_none())
        .map(|r| match r.reason() {
            RefusalReason::Zip(e) => e,
            RefusalReason::AttachmentTooLarge { .. } => panic!("an unowned attachment refusal"),
        })
        .collect();
    assert!(
        unowned
            .iter()
            .any(|e| matches!(e, ZipError::PathTraversal { .. })),
        "{unowned:?}"
    );
    assert!(
        unowned
            .iter()
            .any(|e| matches!(e, ZipError::NestedArchive { .. })),
        "{unowned:?}"
    );
    assert!(
        unowned
            .iter()
            .any(|e| matches!(e, ZipError::Symlink { .. })),
        "{unowned:?}"
    );
    assert!(
        unowned
            .iter()
            .any(|e| matches!(e, ZipError::RatioTooHigh { max: 100, .. })),
        "{unowned:?}"
    );
    assert_eq!(
        unowned.len(),
        4,
        "exactly the four planted refusals: {unowned:?}"
    );
    assert_eq!(
        imported.items.len(),
        12,
        "the refusals did not cost an item"
    );
    let traversal = archive.find("../escape.txt").unwrap();
    assert!(matches!(
        archive.entries()[traversal].refusal(),
        Some(ZipError::PathTraversal { .. })
    ));
}

#[test]
fn an_archive_without_a_central_directory_is_the_one_whole_failure() {
    let err = onepux::parse(Cursor::new(b"this is not a zip archive at all".to_vec())).unwrap_err();
    assert!(
        matches!(err, ImportError::Zip(ZipError::NoEndOfCentralDirectory)),
        "{err:?}"
    );

    let mut z = ZipWriter::new();
    z.add("export.attributes", b"{}", &deflated());
    let err = onepux::parse(Cursor::new(z.finish())).unwrap_err();
    assert!(matches!(err, ImportError::MissingMember), "{err:?}");

    let mut z = ZipWriter::new();
    z.add("export.data", b"{\"accounts\": 7}", &deflated());
    let err = onepux::parse(Cursor::new(z.finish())).unwrap_err();
    assert!(matches!(err, ImportError::NotTheExpectedShape), "{err:?}");

    let mut z = ZipWriter::new();
    z.add("export.data", b"{\"accounts\": [", &deflated());
    let err = onepux::parse(Cursor::new(z.finish())).unwrap_err();
    assert!(matches!(err, ImportError::Json { .. }), "{err:?}");
}

fn one_entry(name: &str, content: &[u8], opts: &Opts) -> Vec<u8> {
    let mut z = ZipWriter::new();
    z.add(name, content, opts);
    z.finish()
}

fn read_first(bytes: Vec<u8>, limits: &Limits) -> Result<Vec<u8>, ZipError> {
    let mut archive = zip::parse(Cursor::new(bytes), limits)?;
    let mut out = Vec::new();
    archive.read_entry(0, &mut out)?;
    Ok(out)
}

#[test]
fn the_zip_reader_round_trips_stored_and_deflated_members() {
    let text = incompressible(8800);
    assert_eq!(
        read_first(one_entry("a.txt", &text, &deflated()), &ONE_PUX_LIMITS).unwrap(),
        text
    );
    assert_eq!(
        read_first(one_entry("a.txt", &text, &stored()), &ONE_PUX_LIMITS).unwrap(),
        text
    );
    assert_eq!(
        read_first(one_entry("empty", b"", &deflated()), &ONE_PUX_LIMITS).unwrap(),
        b""
    );
}

#[test]
fn the_zip_reader_enforces_while_inflating_not_only_on_the_declaration() {
    let text = incompressible(10_000);
    // Declared one byte short: the inflate produces more than declared.
    let short = Opts {
        uncompressed: Some(len32(text.len() - 1)),
        ..deflated()
    };
    assert!(matches!(
        read_first(one_entry("a", &text, &short), &ONE_PUX_LIMITS),
        Err(ZipError::SizeMismatch { entry: 0 })
    ));
    // Declared one byte long: the stream ends early.
    let long = Opts {
        uncompressed: Some(len32(text.len() + 1)),
        ..deflated()
    };
    assert!(matches!(
        read_first(one_entry("a", &text, &long), &ONE_PUX_LIMITS),
        Err(ZipError::SizeMismatch { entry: 0 })
    ));
    let lying = Opts {
        crc: Some(1),
        ..deflated()
    };
    assert!(matches!(
        read_first(one_entry("a", &text, &lying), &ONE_PUX_LIMITS),
        Err(ZipError::CrcMismatch { entry: 0 })
    ));
    // Not a deflate stream, and small enough that the ratio bound does not refuse it first.
    let small = incompressible(2000);
    let garbage = Opts {
        raw: Some(vec![0xFF; 40]),
        compressed: Some(40),
        ..deflated()
    };
    assert!(matches!(
        read_first(one_entry("a", &small, &garbage), &ONE_PUX_LIMITS),
        Err(ZipError::Inflate { entry: 0 } | ZipError::SizeMismatch { entry: 0 })
    ));
    // A member that is itself an archive, by its first bytes rather than its name.
    let nested = b"PK\x03\x04 and then whatever".to_vec();
    assert!(matches!(
        read_first(
            one_entry("innocent.bin", &nested, &stored()),
            &ONE_PUX_LIMITS
        ),
        Err(ZipError::NestedArchive { entry: 0 })
    ));
}

#[allow(clippy::too_many_lines)]
#[test]
fn every_bound_is_a_named_refusal_on_the_entry() {
    let tight = Limits {
        max_entries: 1,
        max_entry_bytes: 4,
        max_total_bytes: 6,
        max_ratio: 2,
    };
    let mut z = ZipWriter::new();
    z.add("ok", b"abcd", &stored());
    z.add("second", b"ab", &stored());
    let archive = zip::parse(Cursor::new(z.finish()), &tight).unwrap();
    assert!(archive.entries()[0].refusal().is_none());
    assert!(matches!(
        archive.entries()[1].refusal(),
        Some(ZipError::TooManyEntries { max: 1 })
    ));

    let archive = zip::parse(Cursor::new(one_entry("big", b"abcde", &stored())), &tight).unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::EntryTooLarge { entry: 0, max: 4 })
    ));

    let loose_count = Limits {
        max_entries: 10,
        ..tight
    };
    let mut z = ZipWriter::new();
    z.add("a", b"abcd", &stored());
    z.add("b", b"abcd", &stored());
    z.add("c", b"a", &stored());
    let archive = zip::parse(Cursor::new(z.finish()), &loose_count).unwrap();
    assert!(archive.entries()[0].refusal().is_none());
    assert!(matches!(
        archive.entries()[1].refusal(),
        Some(ZipError::TotalTooLarge { entry: 1, max: 6 })
    ));
    assert!(
        matches!(
            archive.entries()[2].refusal(),
            Some(ZipError::TotalTooLarge { entry: 2, max: 6 })
        ),
        "every entry after the one that crossed the bound is refused too"
    );

    let ratio = Opts {
        uncompressed: Some(4),
        compressed: Some(1),
        raw: Some(vec![0]),
        ..deflated()
    };
    let archive = zip::parse(Cursor::new(one_entry("r", b"aaaa", &ratio)), &tight).unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::RatioTooHigh { entry: 0, max: 2 })
    ));

    let encrypted = Opts {
        flags: 1,
        ..stored()
    };
    let archive = zip::parse(
        Cursor::new(one_entry("e", b"ab", &encrypted)),
        &ONE_PUX_LIMITS,
    )
    .unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::Encrypted { entry: 0 })
    ));

    let bzip = Opts {
        method: 12,
        ..stored()
    };
    let archive = zip::parse(Cursor::new(one_entry("m", b"ab", &bzip)), &ONE_PUX_LIMITS).unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::UnsupportedMethod {
            entry: 0,
            method: 12
        })
    ));

    let zip64 = Opts {
        compressed: Some(0xFFFF_FFFF),
        ..stored()
    };
    let archive = zip::parse(Cursor::new(one_entry("z", b"ab", &zip64)), &ONE_PUX_LIMITS).unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::Zip64Unsupported { .. })
    ));

    let mut archive = zip::parse(
        Cursor::new(one_entry("dir/", b"", &stored())),
        &ONE_PUX_LIMITS,
    )
    .unwrap();
    assert!(archive.entries()[0].is_directory());
    let mut sink = Vec::new();
    assert!(matches!(
        archive.read_entry(0, &mut sink),
        Err(ZipError::IsDirectory { entry: 0 })
    ));
    assert!(matches!(
        archive.read_entry(7, &mut sink),
        Err(ZipError::NoSuchEntry { entry: 7 })
    ));

    let mut archive = zip::parse(
        Cursor::new(one_entry("../x", b"ab", &stored())),
        &ONE_PUX_LIMITS,
    )
    .unwrap();
    assert!(matches!(
        archive.read_entry(0, &mut sink),
        Err(ZipError::Refused { entry: 0 })
    ));
}

#[test]
fn a_declared_size_over_the_limit_is_refused_before_anything_is_reserved() {
    let lying = Opts {
        uncompressed: Some(0xFFFF_FFF0),
        compressed: Some(0xFFFF_FFF0),
        ..stored()
    };
    let mut archive = zip::parse(
        Cursor::new(one_entry("export.data", b"tiny", &lying)),
        &ONE_PUX_LIMITS,
    )
    .unwrap();
    assert!(matches!(
        archive.entries()[0].refusal(),
        Some(ZipError::EntryTooLarge { entry: 0, .. })
    ));
    assert!(matches!(
        archive.read_entry_to_vec(0),
        Err(ZipError::Refused { entry: 0 })
    ));
    let err = onepux::parse(Cursor::new(one_entry("export.data", b"tiny", &lying))).unwrap_err();
    assert!(
        matches!(err, ImportError::Zip(ZipError::Refused { entry: 0 })),
        "{err:?}"
    );
}

#[test]
fn zip_errors_render_positions_and_bounds_never_names() {
    let archive = zip::parse(
        Cursor::new(one_entry("../secret-canary-name.txt", b"ab", &stored())),
        &ONE_PUX_LIMITS,
    )
    .unwrap();
    let text = format!(
        "{} {:?}",
        archive.entries()[0].refusal().unwrap(),
        archive.entries()[0]
    );
    assert!(!text.contains("secret-canary-name"), "{text}");
}

const ONE_PIF: &str = concat!(
    "\u{FEFF}",
    r#"{"uuid":"pif-0001","typeName":"webforms.WebForm","title":"Example Login","location":"https://example.test/login","createdAt":1700000000,"secureContents":{"fields":[{"designation":"username","name":"username","value":"alice@example.test","type":"T"},{"designation":"password","name":"password","value":"correct-horse-battery","type":"P"}],"notesPlain":"a note","URLs":[{"label":"main","url":"https://example.test/login"},{"label":"alt","url":"https://alt.example.test"}],"sections":[{"title":"Security","name":"sec","fields":[{"k":"concealed","n":"TOTP_ABC","v":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP","t":"one-time password"}]}]},"openContents":{"tags":["work"],"faveIndex":1}}"#,
    "\r\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\r\n",
    r#"{"uuid":"pif-0002","typeName":"securenotes.SecureNote","title":"Example Note","secureContents":{"notesPlain":"the body"}}"#,
    "\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n",
    r#"{"uuid":"pif-0003","typeName":"wallet.financial.CreditCard","title":"Example Card","secureContents":{"ccnum":"4111111111111111","cvv":"123","expiry_mm":"12","expiry_yy":"2028","cardholder":"Alice Example"}}"#,
    "\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n",
    "this line is not JSON but it contains password=hunter2-ish and must not vanish\n",
    "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n",
    r#"{"uuid":"pif-0005","typeName":"wallet.membership.Membership","title":"Gym","trashed":true,"secureContents":{"membership_no":"M-1234","pin":"4321"}}"#,
    "\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n",
    r#"{"uuid":"pif-0006","typeName":"passwords.Password","title":"Just A Password","secureContents":{"password":"only-a-password"}}"#,
    "\n\n",
);

#[test]
fn a_1pif_file_imports_line_by_line_with_its_quirks() {
    let imported = onepif::parse(Cursor::new(ONE_PIF.as_bytes())).unwrap();
    assert_eq!(
        imported.items.len(),
        6,
        "five records and one non-JSON line"
    );
    assert_eq!(imported.report.records().len(), 6);

    let login = &imported.items[0].item;
    assert_eq!(login.kind(), ItemKind::Login);
    assert_eq!(
        field(login, FIELD_TITLE),
        b"Example Login",
        "the byte-order mark did not reach the first record"
    );
    assert_eq!(field(login, FIELD_USERNAME), b"alice@example.test");
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert_eq!(field(login, FIELD_URL), b"https://example.test/login");
    assert_eq!(
        field(login, "url 2"),
        b"https://alt.example.test",
        "location took `url`; the URL list continues"
    );
    assert!(
        field(login, FIELD_TOTP).starts_with(b"otpauth://"),
        "a TOTP_ field is the totp field"
    );
    assert_eq!(tags(login), ["work", "favourite"]);

    assert_eq!(imported.items[1].item.kind(), ItemKind::Note);
    assert_eq!(field(&imported.items[1].item, FIELD_NOTES), b"the body");

    let card = &imported.items[2].item;
    assert_eq!(card.kind(), ItemKind::Card);
    assert_eq!(
        field(card, "ccnum"),
        b"4111111111111111",
        "an unmodelled secureContents key is kept under its own name"
    );

    let garbage = &imported.items[3].item;
    assert_eq!(garbage.kind(), ItemKind::Note);
    assert_eq!(
        imported.report.records()[3].outcome(),
        Outcome::PreservedAsNote(PreserveReason::Malformed)
    );
    assert!(field(garbage, "raw").starts_with(b"this line is not JSON"));

    let membership = &imported.items[4].item;
    assert_eq!(
        imported.report.records()[4].outcome(),
        Outcome::PreservedAsNote(PreserveReason::UnknownType)
    );
    assert_eq!(field(membership, "pin"), b"4321");
    assert_eq!(
        tags(membership),
        ["trashed"],
        "trashed is a tag, not a skip"
    );

    assert_eq!(
        field(&imported.items[5].item, FIELD_PASSWORD),
        b"only-a-password"
    );
}

#[test]
fn a_1pif_line_over_the_record_bound_is_refused_by_position() {
    let long = format!(
        "{{\"typeName\":\"securenotes.SecureNote\",\"title\":\"{}\"}}\n",
        "x".repeat(chiavora_core::import::MAX_RECORD_BYTES)
    );
    let err = onepif::parse(Cursor::new(long.into_bytes())).unwrap_err();
    assert!(
        matches!(err, ImportError::RecordTooLong { at: 0, .. }),
        "{err:?}"
    );
}

#[test]
fn no_import_module_touches_the_filesystem() {
    for module in ["zip.rs", "import.rs", "onepux.rs", "onepif.rs"] {
        let source = std::fs::read_to_string(root().join("crates/core/src").join(module)).unwrap();
        for forbidden in [
            "std::fs",
            "fs::",
            "File::",
            "tempfile",
            "temp_dir",
            "OpenOptions",
        ] {
            assert!(
                !source.contains(forbidden),
                "{module} mentions {forbidden:?}: an import module must not touch the filesystem"
            );
        }
    }
}

#[test]
fn the_report_and_the_items_debug_without_content() {
    let (_archive, imported) = onepux::parse(Cursor::new(fixture())).unwrap();
    let rendered = format!("{:?} {:?}", imported.report, imported.items);
    for canary in [
        "correct-horse-battery",
        "alice@example.test",
        "Example Login",
        "RECOV-1234",
        "4111111111111111",
        "scan.pdf",
    ] {
        assert!(!rendered.contains(canary), "{canary} in a Debug rendering");
    }
}

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn write_seed(dir: &std::path::Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
}

#[allow(clippy::too_many_lines)]
#[test]
#[ignore = "writes fuzz/corpus/{zip_parse,onepux_parse,onepif_parse}; run explicitly"]
fn regenerate_import_corpora() {
    let corpus = root().join("fuzz").join("corpus");
    let zips = corpus.join("zip_parse");
    let pux = corpus.join("onepux_parse");
    let pif = corpus.join("onepif_parse");
    for d in [&zips, &pux, &pif] {
        std::fs::create_dir_all(d).unwrap();
    }

    let text = incompressible(2200);
    let mut variants: Vec<(&str, Vec<u8>)> = vec![
        ("fixture", fixture()),
        ("stored", one_entry("a.txt", &text, &stored())),
        ("deflated", one_entry("a.txt", &text, &deflated())),
        ("empty-member", one_entry("empty", b"", &deflated())),
        ("directory", one_entry("dir/", b"", &stored())),
        ("traversal", one_entry("../x", b"ab", &stored())),
        ("nested-by-name", one_entry("inner.zip", b"ab", &stored())),
        (
            "nested-by-bytes",
            one_entry("innocent", b"PK\x03\x04zz", &stored()),
        ),
        (
            "symlink",
            one_entry(
                "link",
                b"/etc/passwd",
                &Opts {
                    made_by: MADE_BY_UNIX,
                    external: UNIX_SYMLINK,
                    ..stored()
                },
            ),
        ),
        (
            "ratio",
            one_entry(
                "bomb",
                b"x",
                &Opts {
                    uncompressed: Some(200 << 20),
                    compressed: Some(100),
                    ..deflated()
                },
            ),
        ),
        (
            "encrypted",
            one_entry(
                "e",
                b"ab",
                &Opts {
                    flags: 1,
                    ..stored()
                },
            ),
        ),
        (
            "method-12",
            one_entry(
                "m",
                b"ab",
                &Opts {
                    method: 12,
                    ..stored()
                },
            ),
        ),
        (
            "zip64-marker",
            one_entry(
                "z",
                b"ab",
                &Opts {
                    compressed: Some(0xFFFF_FFFF),
                    ..stored()
                },
            ),
        ),
        (
            "crc-lies",
            one_entry(
                "c",
                &text,
                &Opts {
                    crc: Some(1),
                    ..deflated()
                },
            ),
        ),
        (
            "declared-short",
            one_entry(
                "s",
                &text,
                &Opts {
                    uncompressed: Some(len32(text.len() - 1)),
                    ..deflated()
                },
            ),
        ),
        (
            "garbage-stream",
            one_entry(
                "g",
                &text,
                &Opts {
                    raw: Some(vec![0xFF; 40]),
                    compressed: Some(40),
                    ..deflated()
                },
            ),
        ),
        ("eocd-only", ZipWriter::new().finish()),
    ];
    let mut truncated = fixture();
    truncated.truncate(truncated.len() / 2);
    variants.push(("truncated", truncated));
    for (name, bytes) in &variants {
        write_seed(&zips, &format!("seed-{name}.zip"), bytes);
    }

    let mut export_variants: Vec<(&str, Vec<u8>)> = vec![("fixture", fixture())];
    let single = |body: &str| -> Vec<u8> {
        let doc = format!(r#"{{"accounts":[{{"vaults":[{{"items":[{body}]}}]}}]}}"#);
        let mut z = ZipWriter::new();
        z.add("export.data", doc.as_bytes(), &deflated());
        z.finish()
    };
    for (name, body) in [
        (
            "login",
            r#"{"categoryUuid":"001","details":{"loginFields":[{"value":"u","designation":"username"},{"value":"p","designation":"password"}]},"overview":{"title":"t","url":"https://x.test"}}"#,
        ),
        (
            "card",
            r#"{"categoryUuid":"002","details":{"sections":[{"fields":[{"title":"number","value":{"creditCardNumber":"4111111111111111"}}]}]},"overview":{"title":"c"}}"#,
        ),
        (
            "note",
            r#"{"categoryUuid":"003","details":{"notesPlain":"n"},"overview":{"title":"n"}}"#,
        ),
        (
            "identity",
            r#"{"categoryUuid":"004","details":{"sections":[{"title":"A","fields":[{"title":"address","value":{"address":{"street":"s","city":"c"}}}]}]},"overview":{"title":"i"}}"#,
        ),
        (
            "ssh",
            r#"{"categoryUuid":"114","details":{"sections":[{"fields":[{"title":"k","value":{"sshKey":{"privateKey":"pk","metadata":{"publicKey":"pub"}}}}]}]},"overview":{"title":"s"}}"#,
        ),
        (
            "unknown",
            r#"{"categoryUuid":"999","details":{"x":[1,2]},"overview":{"title":"?"}}"#,
        ),
        (
            "totp",
            r#"{"categoryUuid":"001","details":{"sections":[{"fields":[{"title":"otp","value":{"totp":"otpauth://totp/a?secret=JBSWY3DP"}}]}]},"overview":{"title":"t"}}"#,
        ),
        (
            "file",
            r#"{"categoryUuid":"006","details":{"documentAttributes":{"documentId":"nope","fileName":"f.bin"}},"overview":{"title":"d"}}"#,
        ),
        ("not-object", "42"),
        ("empty-items", ""),
    ] {
        export_variants.push((name, single(body)));
    }
    let mut z = ZipWriter::new();
    z.add("export.data", b"{\"accounts\": 7}", &deflated());
    export_variants.push(("wrong-shape", z.finish()));
    let mut z = ZipWriter::new();
    z.add("export.data", b"{\"accounts\": [", &deflated());
    export_variants.push(("bad-json", z.finish()));
    let mut z = ZipWriter::new();
    z.add("export.attributes", b"{}", &deflated());
    export_variants.push(("no-export-data", z.finish()));
    for (name, bytes) in &export_variants {
        write_seed(&pux, &format!("seed-{name}.1pux"), bytes);
    }

    let pif_variants: Vec<(&str, Vec<u8>)> = vec![
        ("fixture", ONE_PIF.as_bytes().to_vec()),
        ("login", br#"{"typeName":"webforms.WebForm","title":"t","secureContents":{"fields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}]}}"#.to_vec()),
        ("note", br#"{"typeName":"securenotes.SecureNote","title":"n","secureContents":{"notesPlain":"body"}}"#.to_vec()),
        ("card", br#"{"typeName":"wallet.financial.CreditCard","title":"c","secureContents":{"ccnum":"4111111111111111"}}"#.to_vec()),
        ("identity", br#"{"typeName":"identities.Identity","title":"i","secureContents":{"firstname":"a","sections":[{"title":"A","fields":[{"k":"address","n":"address","v":{"street":"s"}}]}]}}"#.to_vec()),
        ("password", br#"{"typeName":"passwords.Password","title":"p","secureContents":{"password":"only"}}"#.to_vec()),
        ("unknown", br#"{"typeName":"wallet.membership.Membership","title":"m","secureContents":{"membership_no":"1"}}"#.to_vec()),
        ("totp", br#"{"typeName":"webforms.WebForm","title":"t","secureContents":{"sections":[{"fields":[{"k":"concealed","n":"TOTP_X","v":"otpauth://totp/a?secret=JBSWY3DP"}]}]}}"#.to_vec()),
        ("trashed", br#"{"typeName":"webforms.WebForm","title":"t","trashed":true,"secureContents":{"password":"p"}}"#.to_vec()),
        ("bom-crlf", b"\xEF\xBB\xBF{\"typeName\":\"securenotes.SecureNote\",\"title\":\"n\"}\r\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\r\n".to_vec()),
        ("garbage-line", b"not json at all\n".to_vec()),
        ("separators-only", b"***5642bee8-a5ff-11dc-8314-0800200c9a66***\n\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n".to_vec()),
        ("empty", Vec::new()),
        ("not-object", b"[1,2,3]\n".to_vec()),
    ];
    for (name, bytes) in &pif_variants {
        write_seed(&pif, &format!("seed-{name}.1pif"), bytes);
    }
}
