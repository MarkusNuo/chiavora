#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Cursor;
use std::path::PathBuf;

use chiavora_core::bitwarden;
use chiavora_core::chrome;
use chiavora_core::import::{
    ImportError, MoveKind, Outcome, PreserveReason, FIELD_NOTES, FIELD_PASSWORD, FIELD_TOTP,
};
use chiavora_core::lastpass;
use chiavora_core::model::{Item, FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use chiavora_core::wrap::ItemKind;

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

const BITWARDEN: &str = r#"{"encrypted":false,"folders":[{"id":"f1","name":"Work"}],"collections":[{"id":"c1","organizationId":"o1","name":"Shared","externalId":null}],"items":[
{"id":"i1","organizationId":null,"folderId":"f1","type":1,"reprompt":0,"name":"Example Login","notes":"a note","favorite":true,
 "login":{"uris":[{"match":null,"uri":"https://example.test"},{"match":0,"uri":"https://alt.example.test"}],"username":"alice@example.test","password":"correct-horse-battery","totp":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP"},
 "fields":[{"name":"pin","value":"1234","type":1},{"name":"linked","value":null,"type":3,"linkedId":100}],
 "passwordHistory":[{"lastUsedDate":"2024-01-01T00:00:00.000Z","password":"old-password-1"}],
 "creationDate":"2024-01-01T00:00:00.000Z","revisionDate":"2025-01-01T00:00:00.000Z","collectionIds":["c1"]},
{"id":"i2","type":2,"name":"Example Note","notes":"the body","secureNote":{"type":0}},
{"id":"i3","type":3,"name":"Example Card","card":{"cardholderName":"Alice Example","brand":"Visa","number":"4111111111111111","expMonth":"12","expYear":"2028","code":"123"}},
{"id":"i4","type":4,"name":"Example Identity","identity":{"title":"Dr","firstName":"Alice","lastName":"Example","address1":"1 Test Street","city":"Testville","email":"alice@example.test"}},
{"id":"i5","type":5,"name":"Example SSH","sshKey":{"privateKey":"-----BEGIN OPENSSH PRIVATE KEY-----\nfake","publicKey":"ssh-ed25519 AAAAfake","keyFingerprint":"SHA256:fake"}},
{"id":"i6","type":9,"name":"Mystery","weird":{"deep":[1,2]},"login":{"password":"kept-anyway"}},
{"id":"i7","type":1,"name":"Old","deletedDate":"2025-02-01T00:00:00.000Z","login":{"username":"u","password":"p"}},
"not an object"
]}"#;

const BITWARDEN_ENCRYPTED: &str = r#"{"encrypted":true,"passwordProtected":true,"salt":"abc","kdfType":0,"kdfIterations":600000,"encKeyValidation_DO_NOT_EDIT":"2.x","data":"2.y"}"#;

#[test]
fn a_bitwarden_export_imports_with_one_report_line_per_item() {
    let imported = bitwarden::parse(Cursor::new(BITWARDEN.as_bytes())).unwrap();
    assert_eq!(imported.items.len(), 8);
    assert_eq!(imported.report.records().len(), 8);
    let kinds: Vec<(ItemKind, Outcome)> = imported
        .items
        .iter()
        .zip(imported.report.records())
        .map(|(i, r)| (i.item.kind(), r.outcome()))
        .collect();
    let mapped = |k| (k, Outcome::Mapped(k));
    assert_eq!(
        kinds,
        [
            mapped(ItemKind::Login),
            mapped(ItemKind::Note),
            mapped(ItemKind::Card),
            mapped(ItemKind::Identity),
            mapped(ItemKind::SshKey),
            (
                ItemKind::Note,
                Outcome::PreservedAsNote(PreserveReason::UnknownType)
            ),
            mapped(ItemKind::Login),
            (
                ItemKind::Note,
                Outcome::PreservedAsNote(PreserveReason::Malformed)
            ),
        ]
    );
}

#[test]
fn bitwarden_login_totp_stays_a_field_on_the_login_and_fields_land_by_name() {
    let imported = bitwarden::parse(Cursor::new(BITWARDEN.as_bytes())).unwrap();
    let login = &imported.items[0].item;
    assert_eq!(field(login, FIELD_TITLE), b"Example Login");
    assert_eq!(field(login, FIELD_USERNAME), b"alice@example.test");
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert!(
        field(login, FIELD_TOTP).starts_with(b"otpauth://totp/"),
        "ADR-0003 rev 2: a field on the login"
    );
    assert!(
        imported
            .items
            .iter()
            .all(|i| i.item.kind() != ItemKind::Totp),
        "no standalone TOTP item is manufactured"
    );
    assert_eq!(field(login, FIELD_URL), b"https://example.test");
    assert_eq!(field(login, "url 2"), b"https://alt.example.test");
    assert_eq!(field(login, "url 2 match"), b"0");
    assert_eq!(field(login, FIELD_NOTES), b"a note");
    assert_eq!(
        field(login, "pin"),
        b"1234",
        "a hidden custom field is a field"
    );
    assert_eq!(
        field(login, "linked (linked)"),
        b"100",
        "a linked field keeps its link"
    );
    assert_eq!(field(login, "password history 1"), b"old-password-1");
    assert_eq!(
        tags(login),
        ["Work", "favourite", "Shared"],
        "folder, favourite and collection are tags, in the document's own order"
    );

    let card = &imported.items[2].item;
    assert_eq!(field(card, "cardholder"), b"Alice Example");
    assert_eq!(field(card, "number"), b"4111111111111111");
    assert_eq!(field(card, "cvv"), b"123");
    assert_eq!(field(card, "brand"), b"Visa");

    let identity = &imported.items[3].item;
    assert_eq!(field(identity, "firstName"), b"Alice");
    assert_eq!(field(identity, "address1"), b"1 Test Street");

    let ssh = &imported.items[4].item;
    assert!(field(ssh, "privateKey").starts_with(b"-----BEGIN"));
    assert_eq!(field(ssh, "keyFingerprint"), b"SHA256:fake");

    let unknown = &imported.items[5].item;
    assert_eq!(
        field(unknown, FIELD_PASSWORD),
        b"kept-anyway",
        "the password of an unknown type is the case the rule exists for"
    );
    assert_eq!(field(unknown, "weird"), br#"{"deep":[1,2]}"#);

    let old = &imported.items[6].item;
    assert_eq!(tags(old), ["trashed"]);
    assert_eq!(field(&imported.items[7].item, "raw"), br#""not an object""#);
}

#[test]
fn an_encrypted_bitwarden_export_is_refused_whole_by_name() {
    let err = bitwarden::parse(Cursor::new(BITWARDEN_ENCRYPTED.as_bytes())).unwrap_err();
    assert!(matches!(err, ImportError::EncryptedExport), "{err:?}");
    let err = bitwarden::parse(Cursor::new(b"{\"items\": 5}".to_vec())).unwrap_err();
    assert!(matches!(err, ImportError::NotTheExpectedShape), "{err:?}");
    let err = bitwarden::parse(Cursor::new(b"{\"items\": [".to_vec())).unwrap_err();
    assert!(matches!(err, ImportError::Json { .. }), "{err:?}");
}

/// The newer column set, with `totp`, plus a column nobody expected. The
/// first row's `extra` has an embedded newline, a comma and doubled quotes.
const LASTPASS_WITH_TOTP: &str = concat!(
    "url,username,password,totp,extra,name,grouping,fav,mfa_backup\r\n",
    "https://example.test/login,alice@example.test,correct-horse-battery,JBSWY3DPEHPK3PXP,\"multi\nline note, with comma and \"\"quote\"\"\",Example Login,Work\\Sub,1,backup-1234\r\n",
    "http://sn,,,,just a note,Free Note,Notes,0,\r\n",
    "http://sn,,,,\"NoteType:Credit Card\nName on Card:Alice Example\nType:Visa\nNumber:4111111111111111\nSecurity Code:123\nExpiration Date:\"\"December,2028\"\"\nNotes:my card\nmore notes\",Example Card,,0,\r\n",
    "http://sn,,,,\"NoteType:Server\nHostname:db.example.test\nUsername:root\nPassword:server-pass\nNotes:\",DB Server,,0,\r\n",
    "http://sn,,,,\"NoteType:Membership\nOrganization:Gym\nMembership Number:M-1\",Gym,,0,\r\n",
    "https://short.test,u,p\r\n",
    ",,,,,,,,\r\n",
);

const LASTPASS_WITHOUT_TOTP: &str = concat!(
    "\u{FEFF}url,username,password,extra,name,grouping,fav\r\n",
    "https://example.test/login,alice@example.test,correct-horse-battery,a note,Example Login,,0\r\n",
);

#[test]
fn a_lastpass_export_with_the_totp_column_imports_with_one_report_line_per_row() {
    let imported = lastpass::parse(Cursor::new(LASTPASS_WITH_TOTP.as_bytes())).unwrap();
    assert_eq!(
        imported.items.len(),
        6,
        "six data rows; the header and the empty row are not records"
    );
    assert_eq!(imported.report.records().len(), 6);

    let login = &imported.items[0].item;
    assert_eq!(login.kind(), ItemKind::Login);
    assert_eq!(field(login, FIELD_TITLE), b"Example Login");
    assert_eq!(field(login, FIELD_URL), b"https://example.test/login");
    assert_eq!(field(login, FIELD_USERNAME), b"alice@example.test");
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert_eq!(
        field(login, FIELD_TOTP),
        b"JBSWY3DPEHPK3PXP",
        "the column exists, so the TOTP is a field on the login"
    );
    assert_eq!(
        field(login, FIELD_NOTES),
        b"multi\nline note, with comma and \"quote\"",
        "the embedded newline, comma and doubled quotes survive"
    );
    assert_eq!(
        field(login, "mfa_backup"),
        b"backup-1234",
        "an unexpected column is kept under its header"
    );
    assert_eq!(tags(login), ["Work\\Sub", "favourite"]);
    let kept = imported.report.records()[0]
        .moves()
        .iter()
        .find(|m| m.to() == "mfa_backup")
        .unwrap();
    assert_eq!(kept.kind(), MoveKind::Preserved);

    let free = &imported.items[1].item;
    assert_eq!(free.kind(), ItemKind::Note);
    assert_eq!(field(free, FIELD_NOTES), b"just a note");
    assert_eq!(imported.report.records()[1].source_type(), "Secure Note");

    let card = &imported.items[2].item;
    assert_eq!(card.kind(), ItemKind::Card);
    assert_eq!(field(card, "Name on Card"), b"Alice Example");
    assert_eq!(field(card, "Number"), b"4111111111111111");
    assert_eq!(
        field(card, "Expiration Date"),
        b"\"December,2028\"",
        "the template line is kept as written"
    );
    assert_eq!(
        field(card, FIELD_NOTES),
        b"my card\nmore notes",
        "Notes: runs to the end of the template"
    );
    assert_eq!(
        imported.report.records()[2].source_type(),
        "Secure Note (Credit Card)"
    );

    let server = &imported.items[3].item;
    assert_eq!(server.kind(), ItemKind::Login);
    assert_eq!(field(server, FIELD_URL), b"db.example.test");
    assert_eq!(field(server, FIELD_USERNAME), b"root");
    assert_eq!(field(server, FIELD_PASSWORD), b"server-pass");
    assert!(
        server.field(FIELD_NOTES).is_none(),
        "an empty Notes: carries nothing"
    );

    let gym = &imported.items[4].item;
    assert_eq!(gym.kind(), ItemKind::Note);
    assert_eq!(
        imported.report.records()[4].outcome(),
        Outcome::PreservedAsNote(PreserveReason::UnknownType)
    );
    assert_eq!(field(gym, "Membership Number"), b"M-1");

    let short = &imported.items[5].item;
    assert_eq!(
        field(short, FIELD_URL),
        b"https://short.test",
        "a ragged row reads its columns by position"
    );
    assert_eq!(field(short, FIELD_PASSWORD), b"p");
    assert!(
        short.field(FIELD_TOTP).is_none(),
        "a missing field is empty, not invented"
    );
}

#[test]
fn a_lastpass_export_without_the_totp_column_imports_too() {
    let imported = lastpass::parse(Cursor::new(LASTPASS_WITHOUT_TOTP.as_bytes())).unwrap();
    assert_eq!(imported.items.len(), 1);
    let login = &imported.items[0].item;
    assert_eq!(
        field(login, FIELD_TITLE),
        b"Example Login",
        "the byte-order mark did not reach the header"
    );
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert!(
        login.field(FIELD_TOTP).is_none(),
        "no column, no field -- and no error"
    );
    assert_eq!(field(login, FIELD_NOTES), b"a note");
}

#[test]
fn a_csv_without_a_header_loses_nothing() {
    let imported = lastpass::parse(Cursor::new(
        b"https://x.test,u,hunter2-fake\nhttps://y.test,v,w\n".to_vec(),
    ))
    .unwrap();
    assert_eq!(
        imported.items.len(),
        2,
        "both rows are records when the first is not a header"
    );
    for (item, record) in imported.items.iter().zip(imported.report.records()) {
        assert_eq!(item.item.kind(), ItemKind::Note);
        assert_eq!(
            record.outcome(),
            Outcome::PreservedAsNote(PreserveReason::Malformed)
        );
        assert_eq!(record.source_type(), "row without a header");
    }
    assert_eq!(
        field(&imported.items[0].item, "column 3"),
        b"hunter2-fake",
        "the password is there, under a positional name"
    );
}

const CHROME: &str = concat!(
    "name,url,username,password,note\r\n",
    "Example,https://example.test,alice,correct-horse-battery,\"a note, quoted\"\r\n",
    "NoNote,https://other.test,bob,other-password,\r\n",
);

#[test]
fn a_chrome_export_maps_four_columns_and_preserves_the_rest_verbatim() {
    let imported = chrome::parse(Cursor::new(CHROME.as_bytes())).unwrap();
    assert_eq!(imported.items.len(), 2);
    assert_eq!(imported.report.records().len(), 2);
    let login = &imported.items[0].item;
    assert_eq!(login.kind(), ItemKind::Login);
    assert_eq!(field(login, FIELD_TITLE), b"Example");
    assert_eq!(field(login, FIELD_URL), b"https://example.test");
    assert_eq!(field(login, FIELD_USERNAME), b"alice");
    assert_eq!(field(login, FIELD_PASSWORD), b"correct-horse-battery");
    assert_eq!(
        field(login, "note"),
        b"a note, quoted",
        "not a URL, username or password: preserved under its header"
    );
    let note_move = imported.report.records()[0]
        .moves()
        .iter()
        .find(|m| m.to() == "note")
        .unwrap();
    assert_eq!(note_move.kind(), MoveKind::Preserved);
    assert!(
        imported.items[1].item.field("note").is_none(),
        "an empty cell carries nothing"
    );
    assert!(login.field(FIELD_TOTP).is_none(), "Chrome has no TOTP");
}

#[test]
fn no_new_import_module_touches_the_filesystem() {
    for module in ["csv.rs", "bitwarden.rs", "lastpass.rs", "chrome.rs"] {
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
fn the_reports_debug_without_content() {
    let imported = lastpass::parse(Cursor::new(LASTPASS_WITH_TOTP.as_bytes())).unwrap();
    let rendered = format!("{:?} {:?}", imported.report, imported.items);
    for canary in [
        "correct-horse-battery",
        "alice@example.test",
        "Example Login",
        "4111111111111111",
        "JBSWY3DPEHPK3PXP",
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

#[test]
#[ignore = "writes fuzz/corpus/{csv,bitwarden,lastpass,chrome}_parse; run explicitly"]
#[allow(clippy::too_many_lines)]
fn regenerate_import_corpora() {
    let corpus = root().join("fuzz").join("corpus");
    let dirs = [
        "csv_parse",
        "bitwarden_parse",
        "lastpass_parse",
        "chrome_parse",
    ]
    .map(|d| corpus.join(d));
    for d in &dirs {
        std::fs::create_dir_all(d).unwrap();
    }

    let csv_seeds: Vec<(&str, Vec<u8>)> = vec![
        ("lastpass-with-totp", LASTPASS_WITH_TOTP.as_bytes().to_vec()),
        (
            "lastpass-without-totp",
            LASTPASS_WITHOUT_TOTP.as_bytes().to_vec(),
        ),
        ("chrome", CHROME.as_bytes().to_vec()),
        ("quoted-newline", b"a,\"line1\nline2\",c\n".to_vec()),
        ("doubled-quotes", b"a,\"say \"\"hi\"\"\",c\n".to_vec()),
        ("bom-crlf", b"\xEF\xBB\xBFname,url\r\nx,y\r\n".to_vec()),
        ("ragged", b"a,b,c\n1\n1,2,3,4,5\n".to_vec()),
        ("unterminated-quote", b"a,\"never closed\nmore".to_vec()),
        ("no-final-newline", b"a,b\nc,d".to_vec()),
        ("blank-lines", b"\n\na,b\n\n".to_vec()),
        ("empty", Vec::new()),
        ("quote-mid-field", b"ab\"c,d\n".to_vec()),
        ("comma-only", b",,,\n".to_vec()),
    ];
    for (name, bytes) in &csv_seeds {
        write_seed(&dirs[0], &format!("seed-{name}.csv"), bytes);
    }

    let single = |item: &str| -> Vec<u8> {
        format!(r#"{{"encrypted":false,"folders":[],"items":[{item}]}}"#).into_bytes()
    };
    let bitwarden_seeds: Vec<(&str, Vec<u8>)> = vec![
        ("fixture", BITWARDEN.as_bytes().to_vec()),
        ("encrypted", BITWARDEN_ENCRYPTED.as_bytes().to_vec()),
        (
            "login",
            single(
                r#"{"type":1,"name":"t","login":{"username":"u","password":"p","uris":[{"uri":"https://x.test"}]}}"#,
            ),
        ),
        (
            "totp",
            single(r#"{"type":1,"name":"t","login":{"totp":"otpauth://totp/a?secret=JBSWY3DP"}}"#),
        ),
        (
            "note",
            single(r#"{"type":2,"name":"n","notes":"body","secureNote":{"type":0}}"#),
        ),
        (
            "card",
            single(r#"{"type":3,"name":"c","card":{"number":"4111111111111111","code":"123"}}"#),
        ),
        (
            "identity",
            single(r#"{"type":4,"name":"i","identity":{"firstName":"a"}}"#),
        ),
        (
            "ssh",
            single(r#"{"type":5,"name":"s","sshKey":{"privateKey":"pk","publicKey":"pub"}}"#),
        ),
        ("unknown-type", single(r#"{"type":42,"name":"?","x":[1]}"#)),
        (
            "fields",
            single(
                r#"{"type":1,"name":"f","fields":[{"name":"a","value":"1","type":0},{"name":"b","value":null,"type":3,"linkedId":101}]}"#,
            ),
        ),
        ("not-object", single("7")),
        ("empty-items", single("")),
        ("wrong-shape", b"{\"items\": 5}".to_vec()),
        ("bad-json", b"{\"items\": [".to_vec()),
        ("empty", Vec::new()),
    ];
    for (name, bytes) in &bitwarden_seeds {
        write_seed(&dirs[1], &format!("seed-{name}.json"), bytes);
    }

    let lastpass_seeds: Vec<(&str, Vec<u8>)> = vec![
        ("with-totp", LASTPASS_WITH_TOTP.as_bytes().to_vec()),
        ("without-totp", LASTPASS_WITHOUT_TOTP.as_bytes().to_vec()),
        ("header-only", b"url,username,password,extra,name,grouping,fav\n".to_vec()),
        ("no-header", b"https://x.test,u,p\n".to_vec()),
        ("secure-note-free", b"url,username,password,extra,name,grouping,fav\nhttp://sn,,,\"free\nnote\",N,,0\n".to_vec()),
        ("secure-note-card", b"url,username,password,extra,name,grouping,fav\nhttp://sn,,,\"NoteType:Credit Card\nNumber:4111\nNotes:x\",C,,0\n".to_vec()),
        ("secure-note-server", b"url,username,password,extra,name,grouping,fav\nhttp://sn,,,\"NoteType:Server\nHostname:h\nUsername:u\nPassword:p\",S,,0\n".to_vec()),
        ("secure-note-unknown-template", b"url,username,password,extra,name,grouping,fav\nhttp://sn,,,\"NoteType:Whatever\nKey:Value\",W,,0\n".to_vec()),
        ("reordered-columns", b"name,password,username,url\nT,p,u,https://x.test\n".to_vec()),
        ("ragged", b"url,username,password,extra,name,grouping,fav\nhttps://x.test\n".to_vec()),
        ("bom-crlf", b"\xEF\xBB\xBFurl,username,password\r\nhttps://x.test,u,p\r\n".to_vec()),
        ("blank-rows", b"url,username,password\n,,\nhttps://x.test,u,p\n".to_vec()),
        ("empty", Vec::new()),
    ];
    for (name, bytes) in &lastpass_seeds {
        write_seed(&dirs[2], &format!("seed-{name}.csv"), bytes);
    }

    let chrome_seeds: Vec<(&str, Vec<u8>)> = vec![
        ("fixture", CHROME.as_bytes().to_vec()),
        (
            "four-columns",
            b"name,url,username,password\nT,https://x.test,u,p\n".to_vec(),
        ),
        ("no-header", b"T,https://x.test,u,p\n".to_vec()),
        ("header-only", b"name,url,username,password\n".to_vec()),
        (
            "extra-columns",
            b"name,url,username,password,note,extra\nT,https://x.test,u,p,n,e\n".to_vec(),
        ),
        (
            "quoted",
            b"name,url,username,password\n\"T, quoted\",https://x.test,\"u\"\"q\",\"p\nq\"\n"
                .to_vec(),
        ),
        (
            "bom-crlf",
            b"\xEF\xBB\xBFname,url,username,password\r\nT,https://x.test,u,p\r\n".to_vec(),
        ),
        (
            "ragged",
            b"name,url,username,password\nT\nT,https://x.test,u,p,1,2\n".to_vec(),
        ),
        (
            "reordered",
            b"password,username,url,name\np,u,https://x.test,T\n".to_vec(),
        ),
        (
            "blank-rows",
            b"name,url,username,password\n,,,\nT,https://x.test,u,p\n".to_vec(),
        ),
        ("empty", Vec::new()),
    ];
    for (name, bytes) in &chrome_seeds {
        write_seed(&dirs[3], &format!("seed-{name}.csv"), bytes);
    }
}
