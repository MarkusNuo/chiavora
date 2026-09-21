//! A branded SRP secret cannot leave `core::srp` as an integer: the conversion is private (E0603).

fn main() {
    let secret = chiavora_core::secret::Secret::<
        chiavora_core::secret::kind::SrpExponent,
    >::from_derived_bytes(vec![1_u8; 32]);
    let _leaked = chiavora_core::srp::secret_to_uint(secret.expose());
}
