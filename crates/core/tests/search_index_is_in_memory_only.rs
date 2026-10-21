#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use chiavora_core::model::{Item, ItemField, SEARCHED_FIELDS};
use chiavora_core::search::{Hit, MatchedField, SearchIndex};
use chiavora_core::wrap::ItemKind;

fn login(title: &str, username: &str, url: &str) -> Item {
    Item::new(
        ItemKind::Login,
        vec![
            ItemField::new("title", title.as_bytes().to_vec()).unwrap(),
            ItemField::new("username", username.as_bytes().to_vec()).unwrap(),
            ItemField::new("url", url.as_bytes().to_vec()).unwrap(),
            ItemField::new("password", b"correct-horse-battery-staple".to_vec()).unwrap(),
        ],
        &["work"],
    )
    .unwrap()
}

fn fixture() -> SearchIndex {
    let a = login(
        "Example Bank",
        "ada-lovelace-1815",
        "https://bank.example.test",
    );
    let b = login("Mail", "grace.hopper", "https://mail.example.test/login");
    let c = Item::new(
        ItemKind::Note,
        vec![ItemField::new("title", b"Passport numbers".to_vec()).unwrap()],
        &[],
    )
    .unwrap();
    SearchIndex::build([(&b"a"[..], &a), (&b"b"[..], &b), (&b"c"[..], &c)])
}

fn ids(hits: &[Hit]) -> Vec<&[u8]> {
    hits.iter().map(|h| h.item_id.as_slice()).collect()
}

#[test]
fn the_query_is_case_insensitive_substring_over_the_three_fields() {
    let index = fixture();
    assert_eq!(ids(&index.search("ample b")), [&b"a"[..]]);
    assert_eq!(ids(&index.search("AMPLE B")), [&b"a"[..]]);
    assert_eq!(ids(&index.search("lovelace")), [&b"a"[..]]);
    assert_eq!(ids(&index.search("mail.example")), [&b"b"[..]]);
    assert_eq!(ids(&index.search("example.test")), [&b"a"[..], &b"b"[..]]);
    assert_eq!(ids(&index.search("passport")), [&b"c"[..]]);
    assert!(
        index.search("zzz").is_empty(),
        "a term that is a substring of nothing must match nothing"
    );
}

#[test]
fn the_matched_field_is_the_first_of_the_three_in_search_order() {
    let index = fixture();
    let hits = index.search("example bank");
    let hit = hits.first().expect("the bank title matches");
    assert_eq!(hit.matched, MatchedField::Title);
    let hits = index.search("grace");
    let hit = hits.first().expect("the username matches");
    assert_eq!(hit.matched, MatchedField::Username);
    let hits = index.search("/login");
    let hit = hits.first().expect("the url matches");
    assert_eq!(hit.matched, MatchedField::Url);
    assert_eq!(SEARCHED_FIELDS, ["title", "username", "url"]);
}

#[test]
fn an_empty_query_matches_nothing() {
    // Listing everything is `Store::list`'s job, not the index's.
    assert!(
        fixture().search("").is_empty(),
        "the empty query matched something"
    );
}

#[test]
fn only_the_three_searched_fields_are_searched() {
    let index = fixture();
    assert!(
        index.search("correct-horse").is_empty(),
        "a password was reachable through the index"
    );
    assert!(
        index.search("work").is_empty(),
        "tags are not searched either"
    );
}

#[test]
fn a_hit_carries_an_identifier_and_a_kind_and_no_text() {
    let index = fixture();
    let hits = index.search("bank");
    assert_eq!(hits.len(), 1);
    let hit = hits.first().expect("one hit");
    assert_eq!(hit.item_id, b"a");
    assert_eq!(hit.kind, ItemKind::Login);
    let rendered = format!("{hit:?}");
    assert!(!rendered.contains("Example Bank"), "{rendered}");
    assert!(!rendered.contains("lovelace"), "{rendered}");
    assert!(!rendered.contains("example.test"), "{rendered}");
}

#[test]
fn the_index_debug_prints_a_count_and_no_entry() {
    let index = fixture();
    let rendered = format!("{index:?}");
    assert_eq!(rendered, "SearchIndex(3 entries, redacted)");
}

#[test]
fn insert_replaces_by_identifier_and_remove_is_honest() {
    let mut index = fixture();
    assert_eq!(index.len(), 3);
    index.insert(
        b"a",
        &login("Renamed", "ada-lovelace-1815", "https://bank.example.test"),
    );
    assert_eq!(
        index.len(),
        3,
        "insert by an existing id replaces, not appends"
    );
    assert!(
        index.search("example bank").is_empty(),
        "the replaced title is still searchable"
    );
    assert_eq!(ids(&index.search("renamed")), [&b"a"[..]]);
    assert!(index.remove(b"a"));
    assert!(!index.remove(b"a"));
    assert_eq!(index.len(), 2);
    assert!(
        index.search("renamed").is_empty(),
        "a removed item is still searchable"
    );
}

#[test]
#[ignore = "prints a two-number cost report for this machine; run explicitly"]
fn report_index_costs_on_this_machine() {
    const ITEMS: usize = 10_000;
    const QUERIES: usize = 1_000;

    let items: Vec<(Vec<u8>, Item)> = (0..ITEMS)
        .map(|n| {
            (
                format!("item-{n:05}").into_bytes(),
                login(
                    &format!(
                        "Site {n} — {}",
                        ["Bank", "Mail", "Shop", "Forum"]
                            .get(n % 4)
                            .copied()
                            .unwrap_or("Bank")
                    ),
                    &format!("user{n}@example.test"),
                    &format!("https://site{n}.example.test/login"),
                ),
            )
        })
        .collect();

    let mut builds: Vec<Duration> = (0..10)
        .map(|_| {
            let t = Instant::now();
            let idx = SearchIndex::build(items.iter().map(|(id, it)| (id.as_slice(), it)));
            assert_eq!(idx.len(), ITEMS);
            t.elapsed()
        })
        .collect();
    builds.sort();
    let rebuild_median = *builds.get(builds.len() / 2).expect("ten samples");

    let index = SearchIndex::build(items.iter().map(|(id, it)| (id.as_slice(), it)));
    let needles = [
        "bank",
        "SITE 42",
        "user9",
        "example.test/login",
        "forum",
        "zzz",
    ];
    let mut samples: Vec<Duration> = Vec::with_capacity(QUERIES);
    for i in 0..QUERIES {
        let q = needles.get(i % needles.len()).copied().unwrap_or("bank");
        let t = Instant::now();
        let hits = index.search(q);
        samples.push(t.elapsed());
        assert!(hits.len() <= ITEMS);
    }
    samples.sort();
    let p95 = *samples
        .get((samples.len() * 95) / 100)
        .expect("a thousand samples");

    println!();
    println!(
        "index costs on this machine -- the latency target applies to the reference-handset run"
    );
    println!("  rebuild at unlock, {ITEMS} items, median of 10:   {rebuild_median:?}");
    println!("  query latency, p95 over {QUERIES} queries:        {p95:?}");
    println!("  these are two different numbers and neither licenses the other");
}
