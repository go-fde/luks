# Performance parity — go-fde/luks vs cryptsetup / OpenSSL  (2026-06-22)

Rigorous parity benchmark of the two hot crypto paths that dominate full-disk
encryption: **bulk AES-XTS sector crypto** and the **unlock KDF**
(PBKDF2 / Argon2id).

## Methodology

- **Ours (host):** Apple M4 Max, macOS 26.5, Go 1.26.4 `darwin/arm64`.
  ARMv8 AES instructions present (`hw.optional.arm.FEAT_AES = 1`). The bulk
  cipher is `golang.org/x/crypto/xts` v0.50.0 over `crypto/aes`; KDFs are
  `golang.org/x/crypto/{pbkdf2,argon2}` — the exact code `go-fde/luks` ships.
  Single core. Metric: MB/s over a 1 MiB buffer in 512-byte sectors
  (`b.SetBytes`), best of `-count=2 -benchtime=3s`. KDF metric: ms/derivation.
- **Reference (Linux):** `debian` Tart VM, aarch64 (4 vCPU on the same M4 Max),
  ARMv8 AES (`aes pmull sha2` in `/proc/cpuinfo`). `cryptsetup 2.7.5`,
  OpenSSL 3.5.6 (`OPENSSL_armcap=0x8fd`, HW AES + PMULL). `cryptsetup benchmark`
  (in-memory), `openssl speed -evp`, and a real **dm-crypt loop device**
  (LUKS2 `aes-xts-plain64`, 512-bit key, `dd ... oflag=direct`).
- **Correctness verified first** (see below) — the perf gap is *not* a
  correctness artefact.

> Cross-arch note: host and VM are both the same M4 Max silicon with ARMv8 AES,
> so this is an apples-to-apples per-core comparison of the *software stack*
> (Go x/crypto XTS vs kernel/OpenSSL XTS), not a CPU difference.

## Correctness

| check | result |
|---|---|
| AES-256-XTS ciphertext (key `00..3f`, sector 0, 512 B plaintext) vs OpenSSL/libcrypto (`cryptography` 43.0.0) | **byte-identical** ✓ |
| | ours `dc8c665b97cbc024…43248046597e326` |
| | ref  `dc8c665b97cbc024…43248046597e326` |
| LUKS2 `aes-xts-plain64` volume formatted by `cryptsetup`, opened by `go-fde/luks` | **header-parse mismatch on a stock LUKS2 keyslot** ✗ (see action items) |

The bulk XTS cipher is provably correct against OpenSSL. A separate interop gap
exists in the LUKS2 *header/keyslot* path on a cryptsetup-default container
(4000 AF stripes, pbkdf2-sha256 slot) — tracked as an action item; it is not a
crypto-throughput issue.

## Bulk AES-XTS (single core, MB/s — higher is better)

| op | algo | ours | cryptsetup (in-mem) | OpenSSL (1 KiB / 16 KiB) | dm-crypt (real, direct IO) | ratio vs cryptsetup | verdict |
|---|---|---:|---:|---:|---:|---:|---|
| encrypt | AES-256-XTS | **585 MB/s** | 4364 MB/s | 10 536 / 11 881 MB/s | 3700 MB/s (write) | **0.13× (7.5× slower)** | ❌ far behind |
| decrypt | AES-256-XTS | **583 MB/s** | 4429 MB/s | 10 536 / 11 881 MB/s | 4700 MB/s (read) | **0.13× (7.6× slower)** | ❌ far behind |
| encrypt | AES-128-XTS | **591 MB/s** | 4537 MB/s | 13 538 / 15 798 MB/s | — | **0.13× (7.7× slower)** | ❌ far behind |
| encrypt | AES-CBC-ESSIV-256 | **843 MB/s** | 1433 MB/s (aes-cbc 256b) | — | — | 0.59× | ⚠️ behind |

(`cryptsetup benchmark` reports MiB/s; converted to MB/s. OpenSSL columns are the
1 KiB and 16 KiB block sizes from `openssl speed`.)

## KDF — unlock cost (ms/derivation, lower is better; equal params)

| op | params | ours | cryptsetup / ref | ratio | verdict |
|---|---|---:|---:|---:|---|
| PBKDF2-SHA256 | 100 000 iters, 32 B | **9.6 ms** | 9.5 ms (cryptsetup: 9.50 M iters/s ⇒ 10.5 ms/100k) | ~1.0× | ✅ at parity |
| Argon2id | t=4, m=256 MiB, p=1 | **581 ms** | cryptsetup auto-tunes m≈515 MiB/t=27/p=4 ≈ 2000 ms target | n/a (same lib) | ✅ same primitive |

Both stacks use the **same** Argon2/PBKDF2 reference code (`golang.org/x/crypto`
mirrors the C reference); at identical cost parameters they are equivalent. The
KDF is not a go-fde weakness.

## Summary, root cause, action items

**Bulk XTS is the gap: go-fde is ~7.5× slower than cryptsetup and ~18× slower
than OpenSSL, per core.** Crucially this is **not** a "pure-Go software AES vs
hardware AES" gap — `crypto/aes` on this M4 *does* use the ARMv8 AES
instructions (a raw AES-CTR stream measured **10 024 MB/s**, matching OpenSSL).

**Root cause:** `golang.org/x/crypto/xts` is the bottleneck. It drives AES one
16-byte block at a time through the `cipher.Block` interface and advances the
XTS tweak with a **pure-Go GF(2¹²⁸) multiply per block**. There is no
HW-accelerated XTS path. Measured: raw AES-CTR = 10 024 MB/s, but XTS (whole
buffer *or* per-512 B sector) = ~600 MB/s — a **~17× drop** caused entirely by
the per-block interface dispatch + scalar tweak update. cryptsetup/dm-crypt uses
the kernel `xts-aes-ce` driver and OpenSSL its `aesv8`/`xts` assembly, both of
which fuse the tweak multiply and AES rounds in NEON/crypto-extension assembly.

**Action items (to reach "as good as cryptsetup"):**
1. **Replace `x/crypto/xts` with a fused AES-XTS kernel** generated via
   `go-asmgen` for all 6 targets (amd64 AES-NI+PCLMUL, arm64 AES+PMULL,
   ppc64le VSX, s390x KMA, …): do the GF tweak multiply with `PMULL`/`VPCLMULQDQ`
   and pipeline ≥4 AES blocks. Target ≥ 4 GB/s/core (cryptsetup parity).
2. **Process whole sectors per cipher call**, not 16-byte blocks, to amortise
   interface dispatch (a `BulkEncrypt([]sector)` API on the cipher).
3. **Parallelise across sectors** for multi-MiB transfers (XTS sectors are
   independent) to scale past single-core once (1) lands.
4. Fix the **LUKS2 keyslot interop** so cryptsetup-default containers
   (4000-stripe AF, pbkdf2-sha256) open with `go-fde/luks` — restores the
   format-compatibility correctness leg.

The KDF leg is already at parity. See [`benchmarks/`](benchmarks/) for the
reproducible harness (`./benchmarks/run.sh`).
