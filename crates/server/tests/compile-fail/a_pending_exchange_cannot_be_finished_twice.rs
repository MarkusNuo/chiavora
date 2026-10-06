//! One `b`, one attempt: `finish` moves `self`, so a second call does not compile (E0382).

fn main() {
    let record = chiavora_server::auth::AuthRecord::new(&[0; 16], &[0; 32], &[1; 512]).unwrap();
    let exchange = chiavora_server::auth::PendingExchange::begin(&record, &[2; 512]).unwrap();
    let _first = exchange.finish(&[0; 32]);
    let _second = exchange.finish(&[0; 32]);
}
