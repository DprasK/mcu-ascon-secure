# Experimental-AEAD-384-v0 — design note

> **Do not use this algorithm to protect real data.** It is a new research
> construction with no independent cryptanalysis, security proof, published
> analysis, interoperability ecosystem, or side-channel assessment.

## Purpose

Experimental-AEAD-384-v0 is an educational deterministic-nonce experiment
to be implementable in small C99 firmware. It exists to demonstrate what must
be specified and tested when designing an authenticated cipher. The production
module in this repository continues to use NIST Ascon-AEAD128.

## Parameters

| Parameter | Value |
|---|---:|
| Key | 128 bits |
| Nonce | 128 bits; unique for every message under a key |
| Tag | 128 bits |
| State | 384 bits (`12 x uint32_t`) |
| Rate | 128 bits |
| Capacity | 256 bits |
| Permutation | 12 rounds, ARX |

The implementation uses only fixed rotations, addition, and XOR. It contains
no lookup table or data-dependent branch in the permutation. This is useful
for portability and timing behaviour, but does **not** establish security.

## Permutation

Each round injects a public 32-bit round constant and performs three layers of
six reversible ARX pair mixes. The three matchings connect adjacent lanes and
two progressively wider lane distances. Constants are derived transparently
as the first four bytes of
`SHA-256("Experimental-AEAD-384-v0 round N")` in little-endian form for
`N = 0..11`; they are not secret parameters.

The pair transform is:

```text
a = a + b mod 2^32
b = ROTL32(b, r) XOR a
a = ROTL32(a, q)
```

## AEAD mode

The state is initialized with the key, nonce, and fixed algorithm identifier,
permuted, then has the key injected into the capacity. Associated data is
absorbed at 16 bytes per permutation with `0x01 ... 0x80` padding. A domain
constant separates associated data from plaintext.

Plaintext is duplexed through the 16-byte rate. Finalization injects a separate
domain constant and the key before and after the last permutation. The final
128 capacity bits are emitted as the tag. Decryption compares the whole tag
without early exit and wipes unauthenticated plaintext on failure.

Input/output buffers must not overlap. Nonce reuse is forbidden.

## What the included tests mean

Tests cover message boundary lengths, round-trip behaviour, mutation failure,
and plaintext wiping. They are functional tests only. They do not measure:

- differential or linear cryptanalysis;
- forgery bounds or multi-user security;
- weak keys, related keys, state collisions, or nonce misuse;
- statistical distinguishers;
- power/EM analysis, fault injection, or compiler-introduced leakage.

Before any real use, the design would need a stable specification, extensive
automated analysis, public test vectors, third-party review, and multiple years
of open cryptanalysis. Until then, use the Ascon implementation in `src/`.
