//! Device-side memory-pressure generator for the measurement harness; never shipped.
//! Usage: `memhog <MiB to take> <hold seconds>`

use std::io::Write;

const CHUNK_MIB: usize = 64;
const PAGE: usize = 4096;
/// The most this takes, as a percentage of `MemTotal`, whatever was asked for.
const MAX_FRACTION_OF_TOTAL: u64 = 55;
const SAFETY_FLOOR_MIB: u64 = 600;

fn main() {
    let mut args = std::env::args().skip(1);
    let asked_mib: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(4096);
    let hold_secs: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(30);

    let total_mib = mem_total_kib().unwrap_or(0) / 1024;
    let ceiling_mib = total_mib * MAX_FRACTION_OF_TOTAL / 100;
    let take_mib = asked_mib.min(ceiling_mib);
    if take_mib < asked_mib {
        println!("memhog: asked for {asked_mib} MiB, capped to {take_mib} MiB ({MAX_FRACTION_OF_TOTAL}% of {total_mib} MiB total)");
    }

    let start = mem_available_kib().unwrap_or(0) / 1024;
    println!("memhog: MemTotal {total_mib} MiB, MemAvailable {start} MiB, taking {take_mib} MiB");

    let mut held: Vec<Vec<u8>> = Vec::new();
    while ((held.len() * CHUNK_MIB) as u64) < take_mib {
        let available = mem_available_kib().unwrap_or(0) / 1024;
        if available < SAFETY_FLOOR_MIB {
            println!("memhog: SAFETY STOP at {available} MiB available, {} MiB taken", held.len() * CHUNK_MIB);
            break;
        }
        let mut chunk = vec![0_u8; CHUNK_MIB * 1024 * 1024];
        // Touch every page, or the kernel never commits them.
        let mut offset = 0;
        while offset < chunk.len() {
            chunk[offset] = 1;
            offset += PAGE;
        }
        held.push(chunk);
        if held.len() % 8 == 0 {
            println!("memhog: {} MiB taken, {available} MiB available", held.len() * CHUNK_MIB);
            let _ = std::io::stdout().flush();
        }
    }

    println!(
        "memhog: holding {} MiB for {hold_secs}s, MemAvailable {} MiB",
        held.len() * CHUNK_MIB,
        mem_available_kib().unwrap_or(0) / 1024
    );
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_secs(hold_secs));
    println!(
        "memhog: releasing {} MiB, MemAvailable {} MiB",
        held.len() * CHUNK_MIB,
        mem_available_kib().unwrap_or(0) / 1024
    );
}

fn mem_total_kib() -> Option<u64> {
    field("MemTotal:")
}

fn mem_available_kib() -> Option<u64> {
    field("MemAvailable:")
}

fn field(name: &str) -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix(name))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
