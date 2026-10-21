#!/usr/bin/env python3
"""Independent SRP-6a reference that generates Chiavora's SRP test vectors.

Written from the specifications with hashlib and pow(), sharing no code with
crates/core. It extracts RFC 5054's groups and Appendix B vectors from the RFC
text, checks them by recomputation, and writes crates/core/tests/vectors/.
Not constant-time: it produces values only.

Usage:
    python tools/srp_reference.py --rfc path/to/rfc5054.txt [--check-only]
    (fetch: https://www.rfc-editor.org/rfc/rfc5054.txt)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import pathlib
import re
import sys

HEX_LINE = re.compile(r"^\s*(?:[0-9A-Fa-f]{8}\s*)+$")


def strip_page_furniture(text: str) -> str:
    """Drop page headers, footers and form feeds, which sit inside hex blocks."""
    keep = [
        line
        for line in text.split("\n")
        if "Taylor, et al." not in line
        and not line.startswith("RFC 5054")
        and "[Page" not in line
        and "\f" not in line
    ]
    return "\n".join(keep)


def appendix(doc: str, start: str, end: str) -> str:
    """The body of one appendix; `rindex` skips the table of contents."""
    return doc[doc.rindex(start) : doc.rindex(end)]


def hex_value(block: str, name: str) -> str:
    """The value of `name =`, from contiguous pure-hex lines only.

    Stopping at the first non-hex line keeps the prose after Appendix B's salt
    out of the value.
    """
    lines = block.split("\n")
    assignment = re.compile(r"^\s*%s\s*=\s*(.*)$" % re.escape(name))
    for index, line in enumerate(lines):
        match = assignment.match(line)
        if not match:
            continue
        chunks: list[str] = []
        first = match.group(1).strip()
        if first and HEX_LINE.match(first):
            chunks.append(first)
        for following in lines[index + 1 :]:
            if not following.strip():
                if chunks:
                    break
                continue
            if HEX_LINE.match(following):
                chunks.append(following.strip())
            else:
                break
        if chunks:
            return re.sub(r"\s", "", "".join(chunks)).upper()
    raise KeyError(f"no hex value for {name!r}")


def group(doc: str, heading: str, next_heading: str) -> tuple[str, int]:
    """One group's `N` and `g` from Appendix A."""
    block = doc[doc.rindex(heading) : doc.rindex(next_heading)]
    match = re.search(
        r"hexadecimal value (?:for the prime )?is:?\s*\n(.*?)\n\s*The generator is:?\s*(\d+)",
        block,
        re.S,
    )
    if match is None:
        raise KeyError(f"could not parse {heading!r}")
    modulus = re.sub(r"[^0-9A-Fa-f]", "", match.group(1)).upper()
    return modulus, int(match.group(2))


class Srp:
    """RFC 5054 §2.4 and §2.6, with the hash and group as parameters."""

    def __init__(self, modulus: int, generator: int, hash_name: str) -> None:
        self.N = modulus
        self.g = generator
        self.hash_name = hash_name
        self.n_bytes = (modulus.bit_length() + 7) // 8

    def _h(self, *parts: bytes) -> int:
        digest = hashlib.new(self.hash_name)
        for part in parts:
            digest.update(part)
        return int.from_bytes(digest.digest(), "big")

    def pad(self, value: int) -> bytes:
        """Left-pad to the byte length of N (RFC 5054 §2.6)."""
        return value.to_bytes(self.n_bytes, "big")

    def k(self) -> int:
        return self._h(self.pad(self.N), self.pad(self.g))

    def x_rfc(self, salt: bytes, identity: bytes, password: bytes) -> int:
        """The RFC's `x = H(s | H(I | ":" | p))`, for the published vectors only.

        Chiavora's own derivation is `chiavora_x`.
        """
        inner = hashlib.new(self.hash_name, identity + b":" + password).digest()
        return self._h(salt, inner)

    def verifier(self, x: int) -> int:
        return pow(self.g, x, self.N)

    def public_a(self, a: int) -> int:
        return pow(self.g, a, self.N)

    def public_b(self, b: int, verifier: int) -> int:
        return (self.k() * verifier + pow(self.g, b, self.N)) % self.N

    def u(self, public_a: int, public_b: int) -> int:
        return self._h(self.pad(public_a), self.pad(public_b))

    def client_secret(self, a: int, x: int, public_b: int) -> int:
        u = self.u(self.public_a(a), public_b)
        base = (public_b - self.k() * pow(self.g, x, self.N)) % self.N
        return pow(base, a + u * x, self.N)

    def server_secret(self, b: int, verifier: int, public_a: int) -> int:
        u = self.u(public_a, self.public_b(b, verifier))
        return pow(public_a * pow(verifier, u, self.N), b, self.N)


def chiavora_x(srp_salt: bytes, srp_x: bytes) -> bytes:
    """`x = SHA-256(srpSalt ‖ srpX)` (ADR-0008 §3.3), written from the ADR."""
    return hashlib.sha256(srp_salt + srp_x).digest()


def chiavora_verifier(modulus: int, generator: int, x: bytes) -> int:
    """`v = g^x mod N`, the value the server stores."""
    return pow(generator, int.from_bytes(x, "big"), modulus)


def derivation_vectors(modulus_hex: str, generator: int) -> list[dict]:
    """The derivation cases: all-zero srpX, all-ones srpSalt, an ordinary one,
    and a searched-for x with a leading zero byte."""
    modulus = int(modulus_hex, 16)
    cases: list[tuple[str, bytes, bytes]] = [
        ("all_zero_srp_x", bytes(32), bytes(32)),
        ("all_ones_srp_salt", b"\xff" * 32, bytes(range(32))),
        ("ordinary", bytes(range(32)), bytes(range(32, 64))),
    ]

    for counter in range(4096):
        salt = b"leading-zero-probe".ljust(32, b"\x00")
        srp_x = counter.to_bytes(32, "big")
        if chiavora_x(salt, srp_x)[0] == 0:
            cases.append(("x_has_a_leading_zero_byte", salt, srp_x))
            break
    else:  # pragma: no cover - 4096 tries at p=1/256 will not all miss
        raise RuntimeError("no leading-zero x found; widen the search")

    out = []
    for name, salt, srp_x in cases:
        x = chiavora_x(salt, srp_x)
        out.append({
            "name": name,
            "srp_salt": salt.hex().upper(),
            "srp_x": srp_x.hex().upper(),
            "x": x.hex().upper(),
            "verifier": f"{chiavora_verifier(modulus, generator, x):0{len(modulus_hex)}X}",
        })
    return out


def hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 with no salt (HashLen zero bytes), written out."""
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def chiavora_session_keys(premaster: bytes) -> dict[str, bytes]:
    """`K`, `macC2S` and `macS2C`, each derived directly from the padded `S`."""
    return {
        "K": hkdf_sha256(premaster, b"chiavora-srp-k", 32),
        "mac_c2s": hkdf_sha256(premaster, b"chiavora-mac-c2s", 32),
        "mac_s2c": hkdf_sha256(premaster, b"chiavora-mac-s2c", 32),
    }


def chiavora_m1(srp: "Srp", identity: bytes, srp_salt: bytes,
                public_a: int, public_b: int, session_key: bytes) -> bytes:
    """`M1 = H(H(N) XOR H(g) | H(I) | s | PAD(A) | PAD(B) | K)`.

    Every field is fixed-width, and `I` is the accountId.
    """
    h_n = hashlib.sha256(srp.pad(srp.N)).digest()
    h_g = hashlib.sha256(srp.pad(srp.g)).digest()
    group_xor = bytes(left ^ right for left, right in zip(h_n, h_g))
    return hashlib.sha256(
        group_xor
        + hashlib.sha256(identity).digest()
        + srp_salt
        + srp.pad(public_a)
        + srp.pad(public_b)
        + session_key
    ).digest()


def chiavora_m2(srp: "Srp", public_a: int, m1: bytes,
                session_key: bytes) -> bytes:
    """`M2 = H(PAD(A) | M1 | K)` (RFC 5054 section 2.6)."""
    return hashlib.sha256(srp.pad(public_a) + m1 + session_key).digest()


def proof_vectors(modulus_hex: str, generator: int) -> list[dict]:
    """Full exchanges at 4096-bit SHA-256 through `M1` and `M2`: an ordinary
    case and searched-for short `A` and `B`, where padding matters."""
    modulus = int(modulus_hex, 16)
    srp = Srp(modulus, generator, "sha256")
    width = len(modulus_hex)

    identity = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # accountId
    srp_salt = bytes(range(0x20, 0x40))
    srp_x = bytes(range(0x40, 0x60))
    x_bytes = chiavora_x(srp_salt, srp_x)
    x = int.from_bytes(x_bytes, "big")
    verifier = srp.verifier(x)

    def exchange(name: str, a_bytes: bytes, b_bytes: bytes) -> dict:
        a = int.from_bytes(a_bytes, "big")
        b = int.from_bytes(b_bytes, "big")
        public_a = srp.public_a(a)
        public_b = srp.public_b(b, verifier)

        client_s = srp.client_secret(a, x, public_b)
        server_s = srp.server_secret(b, verifier, public_a)
        if client_s != server_s:
            raise RuntimeError(f"{name}: the two sides disagree on S")

        # S is padded before HKDF, as `client_premaster` returns it.
        premaster = srp.pad(client_s)
        keys = chiavora_session_keys(premaster)
        m1 = chiavora_m1(srp, identity, srp_salt, public_a, public_b,
                         keys["K"])
        m2 = chiavora_m2(srp, public_a, m1, keys["K"])

        if len({keys["K"], keys["mac_c2s"], keys["mac_s2c"]}) != 3:
            raise RuntimeError(f"{name}: two of the three keys are equal")
        if premaster in (keys["K"], keys["mac_c2s"], keys["mac_s2c"]):
            raise RuntimeError(f"{name}: a derived key equals S itself")

        return {
            "name": name,
            "account_id": identity.hex().upper(),
            "srp_salt": srp_salt.hex().upper(),
            "srp_x": srp_x.hex().upper(),
            "x": x_bytes.hex().upper(),
            "verifier": f"{verifier:0{width}X}",
            "a": a_bytes.hex().upper(),
            "b": b_bytes.hex().upper(),
            "A": f"{public_a:0{width}X}",
            "B": f"{public_b:0{width}X}",
            "S": premaster.hex().upper(),
            "K": keys["K"].hex().upper(),
            "mac_c2s": keys["mac_c2s"].hex().upper(),
            "mac_s2c": keys["mac_s2c"].hex().upper(),
            "M1": m1.hex().upper(),
            "M2": m2.hex().upper(),
        }

    ordinary_a = bytes(range(0x60, 0x80))
    ordinary_b = bytes(range(0x80, 0xA0))
    out = [exchange("ordinary", ordinary_a, ordinary_b)]

    def search(predicate) -> bytes:
        for counter in range(1 << 16):
            candidate = (counter + 1).to_bytes(32, "big")
            if predicate(candidate):
                return candidate
        raise RuntimeError("no short public value found; widen the search")

    short_a = search(lambda c: srp.public_a(int.from_bytes(c, "big"))
                     .bit_length() <= 4096 - 8)
    out.append(exchange("a_has_a_leading_zero_byte", short_a, ordinary_b))

    short_b = search(lambda c: srp.public_b(int.from_bytes(c, "big"), verifier)
                     .bit_length() <= 4096 - 8)
    out.append(exchange("b_has_a_leading_zero_byte", ordinary_a, short_b))

    return out


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin with 12 small bases plus `rounds` witnesses; not a proof."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small + list(range(41, 41 + 2 * rounds, 2)):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def check_group(modulus_hex: str, generator: int) -> dict:
    """Is `N` a safe prime, and does `g` generate the full group of order 2q?"""
    n = int(modulus_hex, 16)
    q = (n - 1) // 2
    n_prime = is_probable_prime(n)
    q_prime = is_probable_prime(q)
    return {
        "bits": n.bit_length(),
        "N_is_probable_prime": n_prime,
        "q_is_probable_prime": q_prime,
        "is_safe_prime": n_prime and q_prime,
        "g_generates_full_group": pow(generator, q, n) == n - 1,
        "method": (
            "Miller-Rabin, 12 small bases plus 24 further witnesses, on N and on "
            "q = (N-1)/2; then g^q mod N == N-1. Probable-prime, not a proof."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rfc", required=True, type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path,
                        default=pathlib.Path("crates/core/tests/vectors"))
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    doc = strip_page_furniture(args.rfc.read_text(encoding="utf-8", errors="replace"))

    n1024, g1024 = group(doc, "1.  1024-bit Group", "2.  1536-bit Group")
    n4096, g4096 = group(doc, "5.  4096-bit Group", "6.  6144-bit Group")
    for label, modulus, expected in (("1024", n1024, 1024), ("4096", n4096, 4096)):
        actual = int(modulus, 16).bit_length()
        if actual != expected or len(modulus) * 4 != expected:
            print(f"FAIL: {label}-bit group is {actual} bits", file=sys.stderr)
            return 1

    block = appendix(doc, "Appendix B.  SRP Test Vectors", "Appendix C.")
    published = {name: hex_value(block, name)
                 for name in ("s", "k", "x", "v", "a", "b", "A", "B", "u")}
    published["S"] = hex_value(block, "<premaster secret>")

    srp = Srp(int(n1024, 16), g1024, "sha1")
    salt = bytes.fromhex(published["s"])
    a = int(published["a"], 16)
    b = int(published["b"], 16)

    x = srp.x_rfc(salt, b"alice", b"password123")
    v = srp.verifier(x)
    public_a = srp.public_a(a)
    public_b = srp.public_b(b, v)

    recomputed = {
        "k": srp.k(),
        "x": x,
        "v": v,
        "A": public_a,
        "B": public_b,
        "u": srp.u(public_a, public_b),
        "S": srp.client_secret(a, x, public_b),
    }
    server_s = srp.server_secret(b, v, public_a)

    failures = [name for name, value in recomputed.items()
                if value != int(published[name], 16)]
    if server_s != recomputed["S"]:
        failures.append("S(server) != S(client)")
    if failures:
        print(f"FAIL: recomputation does not match the RFC: {failures}", file=sys.stderr)
        return 1
    print(f"OK: {len(recomputed)} Appendix B values recomputed and matched, "
          f"and both sides agree on the premaster secret")

    if args.check_only:
        return 0

    provenance = (
        "Extracted from RFC 5054's own text and recomputed from the specification by "
        "tools/srp_reference.py (Python: hashlib and pow(), sharing no code with "
        "crates/core), so the Rust implementation is checked against something that "
        "is not itself."
    )

    properties = {}
    for label, modulus, generator in (("1024", n1024, g1024), ("4096", n4096, g4096)):
        result = check_group(modulus, generator)
        properties[label] = result
        if not (result["is_safe_prime"] and result["g_generates_full_group"]):
            print(f"FAIL: {label}-bit group: {result}", file=sys.stderr)
            return 1
        print(f"OK: {label}-bit group is a safe prime and g = {generator} "
              f"generates the full group")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "srp_groups.json").write_text(json.dumps({
        "source": "RFC 5054 Appendix A",
        "note": provenance,
        "warning": (
            "Matching these bytes shows the group is the right one and says "
            "nothing about the exchange, whose only published vectors "
            "(Appendix B) use the 1024-bit group with SHA-1."
        ),
        "groups": {
            "1024": {"bits": 1024, "g": g1024, "N": n1024,
                     "use": "Test only: the instantiation RFC 5054 Appendix B uses."},
            "4096": {"bits": 4096, "g": g4096, "N": n4096,
                     "use": "Shipping (docs/security-design.md 2.3)."},
        },
        "properties": properties,
    }, indent=1) + "\n", encoding="utf-8")

    (args.out / "rfc5054_appendix_b.json").write_text(json.dumps({
        "source": "RFC 5054 Appendix B",
        "note": provenance,
        "scope": (
            "The 1024-bit group with SHA-1, which Chiavora does not ship: these "
            "vectors check the exchange algebra given x and are no evidence for "
            "the shipping configuration."
        ),
        "group": "1024",
        "hash": "sha1",
        "identity": "alice",
        "password": "password123",
        "vectors": published,
    }, indent=1) + "\n", encoding="utf-8")

    derivation = derivation_vectors(n4096, g4096)
    leading_zero = [v for v in derivation if v["x"].startswith("00")]
    if not leading_zero:
        print("FAIL: no vector has an x with a leading zero byte", file=sys.stderr)
        return 1
    print(f"OK: {len(derivation)} derivation vectors, "
          f"{len(leading_zero)} with a leading-zero x")

    (args.out / "srp_derivation.json").write_text(json.dumps({
        "source": "docs/adr/0008 section 3.3 — x = SHA-256(srpSalt || srpX), v = g^x mod N",
        "note": provenance,
        "checked_against": (
            "NOTHING EXTERNAL: no other implementation of x = SHA-256(srpSalt || "
            "srpX) exists, so the only evidence is that tools/srp_reference.py, "
            "written from the ADR and sharing no code with crates/core, agrees "
            "with the Rust."
        ),
        "scope": "The SHIPPING configuration: RFC 5054's 4096-bit group with SHA-256.",
        "group": "4096",
        "hash": "sha256",
        "vectors": derivation,
    }, indent=1) + "\n", encoding="utf-8")

    proofs = proof_vectors(n4096, g4096)
    short = [v for v in proofs
             if v["A"].startswith("00") or v["B"].startswith("00")]
    if len(short) < 2:
        print("FAIL: the proof suite needs a short A and a short B; "
              f"found {len(short)}", file=sys.stderr)
        return 1
    print(f"OK: {len(proofs)} proof vectors, {len(short)} with a public value "
          f"short enough for PAD to matter")

    (args.out / "srp_proofs.json").write_text(json.dumps({
        "source": (
            "RFC 5054 section 2.6's M1/M2 formula, with the flat session-key "
            "schedule and the fixed-width transcript encoding of docs/crypto.md."
        ),
        "note": provenance,
        "checked_against": (
            "NOTHING EXTERNAL: RFC 5054 publishes no M1 or M2, so the only "
            "evidence is that tools/srp_reference.py, written from docs/crypto.md "
            "with HKDF written out from RFC 5869 and sharing no code with "
            "crates/core, agrees with the Rust."
        ),
        "scope": (
            "The SHIPPING configuration: RFC 5054's 4096-bit group with SHA-256, "
            "Chiavora's x, the flat key schedule and the fixed-width transcript."
        ),
        "group": "4096",
        "hash": "sha256",
        "labels": {
            "K": "chiavora-srp-k",
            "mac_c2s": "chiavora-mac-c2s",
            "mac_s2c": "chiavora-mac-s2c",
        },
        "vectors": proofs,
    }, indent=1) + "\n", encoding="utf-8")

    print(f"wrote {args.out / 'srp_groups.json'}")
    print(f"wrote {args.out / 'rfc5054_appendix_b.json'}")
    print(f"wrote {args.out / 'srp_derivation.json'}")
    print(f"wrote {args.out / 'srp_proofs.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
