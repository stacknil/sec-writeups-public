---

platform: TryHackMe
room: Learn Rust
slug: learn-rust
path: notes/tryhackme/00-foundations/learn-rust.md
topic: 00-foundations
status: done
date: 2026-02-13
---

## 0) Summary

* Goal: reverse a simple ciphertext pipeline and print the plaintext in Rust.
* Pipeline (reverse): `rot13 -> base64 decode -> rot13`.
* Result (plaintext): `thm{rust}`.
* Rust angle: keep each intermediate as an *owned* value (`Vec<u8>` / `String`) to reduce lifetime/borrow-checker friction.

## 1) Key Concepts (plain language)

* Ownership (所有权): a value has one owner; when the owner goes out of scope, memory is freed.
* Borrowing (借用): pass `&T` (shared reference) so a function can read without taking ownership.
* `Vec<u8>` vs `&[u8]`:

  * `Vec<u8>` is an owned, growable byte buffer.
  * `&[u8]` is a borrowed view (slice) into bytes.
* `String` vs `&str`:

  * `String` is owned UTF‑8 text.
  * `&str` is a borrowed view into UTF‑8 text.
* `Result<T, E>` + `?`: propagate errors without manual match boilerplate.

## 2) Reverse pipeline

Ciphertext: `M3I6r2IbMzq9`

Steps:

1. `rot13(ciphertext)` → `Z3V6e2VoZmd9`
2. `base64_decode(step1)` → bytes representing `guz{ehfg}`
3. `rot13(step2_bytes)` → bytes representing `thm{rust}`
4. `utf8(step3_bytes)` → `String`

## 3) Implementation (Rust)

Design rule: **one transformation per line**, store intermediates as owned values.

```rust
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::error::Error;

fn rot13_bytes(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
            _ => b,
        })
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let cipher = "M3I6r2IbMzq9";

    // rot13 -> base64 decode -> rot13
    let step1 = rot13_bytes(cipher.as_bytes());
    let step2 = STANDARD.decode(&step1)?; // Vec<u8>
    let step3 = rot13_bytes(&step2);

    let plaintext = String::from_utf8(step3)?;
    println!("{plaintext}"); // thm{rust}
    Ok(())
}
```

### Cargo.toml

```toml
[dependencies]
base64 = "0.22.1"
```

## 4) Why this avoids borrow-checker pain

Common beginner trap: creating references (`&[u8]`, `&str`) to *temporary* values that get dropped too early.

This pattern avoids it:

* Each intermediate is stored in a named variable (`step1`, `step2`, `step3`).
* The next call borrows it briefly (`&step1`, `&step2`) and returns a new owned value.
* Net effect: minimal lifetimes to reason about; no dangling references.

## 5) Pitfalls

* Base64 decoding returns raw bytes; not everything is valid UTF‑8. Here it is, but in general `String::from_utf8(...)` can fail.
* ROT13 is defined over ASCII letters; for non-ASCII text you’d need different logic.
* Prefer explicit engines (`STANDARD`) instead of deprecated helper functions.

## 6) Takeaways

* Treat low-level transforms as `bytes -> bytes` until the final `bytes -> String` conversion.
* When in doubt in Rust: **own the intermediate**, borrow only for the next function call.

## CN–EN Glossary

* Ownership — 所有权
* Borrowing — 借用
* Lifetime — 生命周期
* Slice — 切片
* Heap allocation — 堆分配
* Trait — 特征
* Error propagation — 错误传播
* Crate — 包/库

## References

```text
Rust Book (References & Borrowing):
https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html

base64 crate docs (v0.22.1):
https://docs.rs/base64/latest/base64/
```
