//! Run with `cargo test -p chiavora-core --test srp_exchange_cost -- --ignored --nocapture`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;

use chiavora_core::secret::{
    kind::{SrpEphemeralSecret, SrpExponent},
    Secret,
};
use chiavora_core::srp::{
    client_premaster, client_public, server_premaster, server_public, Group, Sha256Hash,
};

#[test]
#[ignore = "a measurement, not an assertion; run explicitly with --nocapture"]
fn the_4096_bit_exchange_costs_what_it_costs() {
    let group = Group::RFC5054_4096;

    let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(vec![0x5A_u8; 32]);
    let b = Secret::<SrpEphemeralSecret>::from_derived_bytes(vec![0xA5_u8; 32]);
    let x = Secret::<SrpExponent>::from_derived_bytes(vec![0x3C_u8; 32]);

    // The verifier stands in for `g^x`; its value does not affect the cost.
    let verifier = client_public(group, &x_as_ephemeral(&x)).unwrap();

    let started = Instant::now();
    let public_a = client_public(group, &a).unwrap();
    let a_cost = started.elapsed();

    let started = Instant::now();
    let public_b = server_public::<Sha256Hash>(group, &b, &verifier).unwrap();
    let b_cost = started.elapsed();

    let started = Instant::now();
    let client = client_premaster::<Sha256Hash>(group, &a, &x, &public_b).unwrap();
    let client_cost = started.elapsed();

    let started = Instant::now();
    let server = server_premaster::<Sha256Hash>(group, &b, &verifier, &public_a).unwrap();
    let server_cost = started.elapsed();

    assert_eq!(
        client.expose(),
        server.expose(),
        "the measurement is worthless if the exchange did not actually agree"
    );

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    println!("SRP-6a exchange cost — RFC 5054 4096-bit group, SHA-256, {profile} build");
    println!("  A = g^a            {a_cost:?}");
    println!("  B = k*v + g^b      {b_cost:?}");
    println!("  client premaster   {client_cost:?}");
    println!("  server premaster   {server_cost:?}");
    println!(
        "  client total       {:?}  (A + premaster: what a login pays)",
        a_cost + client_cost
    );
    println!("  Measured on this machine, not on a low-end phone.");
}

/// `x` under the ephemeral brand, so the verifier can be computed like `A`.
fn x_as_ephemeral(x: &Secret<SrpExponent>) -> Secret<SrpEphemeralSecret> {
    Secret::from_derived_bytes(x.expose().to_vec())
}
