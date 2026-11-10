# Performance — go-fde/luks vs cryptsetup / OpenSSL

## 2026-11-10: whole-span I/O, batched sector ciphers

`Device.ReadAt` and `WriteAt` used to work one sector at a time. Each
sector cost one `ReadAt` on the underlying device, one 512-byte buffer,
and, for CBC, a new `aes.NewCipher`. Now:

- **I/O:** the whole sector span is read with one `ReadAt` and written with
  one `WriteAt`. Only a partial first or last sector is read back for
  read-modify-write.
- **XTS:** goes through go-encryptions/xts v0.2.0 `DecryptSectors` /
  `EncryptSectors`, which encrypt the tweaks of 8 sectors at a time.
- **CBC-ESSIV decryption:** go-encryptions/cbc v0.1.0 computes the ESSIV
  IVs 8 at a time (`EncryptECB`) and decrypts 8 blocks at a time
  (`DecryptSectors`).
- **CBC encryption** is serial within a sector and still goes through
  `crypto/cipher`.
- **Aligned reads** decrypt in the caller's buffer.

Measured on one Apple M4 Max core: 1 MiB per call, 512-byte sectors.
`abbench --max-load 8` ran 6 rounds interleaved with a clean clone of
v0.2.0 (`BenchmarkReadAt`, `BenchmarkWriteAt`); every row is p=0.002.

| | v0.2.0 | 2026-11-10 | allocations per call |
|---|---|---|---|
| ReadAt AES-128-XTS | 2.21 GB/s | **8.17 GB/s** | 4 096 → 1 (then 0, see below) |
| ReadAt AES-256-XTS | 2.18 GB/s | **7.12 GB/s** | 4 096 → 1 |
| ReadAt AES-128-CBC-ESSIV | 1.21 GB/s | **8.64 GB/s** | 8 192 → 2 |
| ReadAt AES-256-CBC-ESSIV | 1.16 GB/s | **7.82 GB/s** | 8 192 → 2 |
| WriteAt AES-128-XTS | 1.21 GB/s | **8.05 GB/s** | 6 144 → 1 |
| WriteAt AES-256-XTS | 1.19 GB/s | **7.15 GB/s** | 6 144 → 1 |
| WriteAt AES-128-CBC-ESSIV | 0.55 GB/s | **1.24 GB/s** | 14 336 → 2 050 |
| WriteAt AES-256-CBC-ESSIV | 0.49 GB/s | **1.01 GB/s** | 14 336 → 2 050 |

After the A/B run, sector-aligned reads were changed to decrypt in the
caller's buffer, which removes the 1 MiB buffer allocation.

The figures include copying the megabyte out of the in-memory test
device. For reference, `openssl speed -bytes 512` on the same core gives
12.8 GB/s for AES-128-XTS encryption and 17.6 GB/s for AES-128-CBC
decryption, with no device copy. The xts and cbc kernels alone are ahead
of OpenSSL (go-encryptions/xts v0.2.0, go-encryptions/cbc v0.1.0).

CBC writes remain the slow path, for two reasons. Each sector's chain is
serial, and `crypto/cipher` allocates one encrypter per sector. Encrypting
8 sectors' chains interleaved is filed on go-encryptions/cbc.

## 2026-06-22: the fused XTS kernel

Rigorous parity benchmark of the two hot crypto paths that dominate full-disk
encryption: **bulk AES-XTS sector crypto** and the **unlock KDF**
(PBKDF2 / Argon2id).

## What changed (2026-06-22)

The AES-XTS gap is **closed**. `go-fde/luks` no longer drives
`golang.org/x/crypto/xts`; the `sectorCipher` now uses a **fused
hardware-accelerated AES-XTS kernel** (the shared `github.com/go-encryptions/xts`
package) that pipelines four AES
blocks at a time and folds the tweak XOR into the round pipeline — ARMv8
`AESE`/`AESMC` on arm64, AES-NI on amd64, and a portable fallback (byte-identical
to `x/crypto/xts`) on riscv64/loong64/ppc64le/s390x. Ciphertext stays
byte-for-byte identical to OpenSSL and the IEEE P1619 / NIST XTS-AES KAT vectors,
and the LUKS2 interop (opening stock cryptsetup containers) is preserved.

## Methodology

- **Ours (host):** Apple M4 Max, macOS 26.5, Go 1.26.4 `darwin/arm64`.
  ARMv8 AES instructions present (`hw.optional.arm.FEAT_AES = 1`). The bulk
  cipher is the fused `github.com/go-encryptions/xts` kernel over `crypto/aes`; KDFs are
  `golang.org/x/crypto/{pbkdf2,argon2}` — the exact code `go-fde/luks` ships.
  Single core. Metric: MB/s over a 1 MiB buffer in 512-byte sectors
  (`b.SetBytes`), best of `-count=2 -benchtime=3s`. KDF metric: ms/derivation.
- **Apples-to-apples (same VM):** `cb-tpm-ubuntu` Tart VM, aarch64 (6 vCPU on
  the same M4 Max), ARMv8 AES (`aes pmull` in `/proc/cpuinfo`). `cryptsetup`
  benchmark and `openssl speed -evp` *and* the cross-compiled `go-fde/luks`
  benchmark binary were all run on this one VM, so the comparison reflects the
  software stack (Go fused XTS vs kernel/OpenSSL XTS), not a CPU difference.

## Correctness

| check | result |
|---|---|
| AES-256-XTS / AES-128-XTS ciphertext vs OpenSSL + IEEE P1619 / NIST XTS-AES KAT vectors | **byte-identical** ✓ (all 6 arches, incl. big-endian s390x) |
| LUKS2 `aes-xts-plain64` volume formatted by `cryptsetup`, opened by `go-fde/luks` | **opens** ✓ (interop test `TestInterop_CryptsetupDefault_LUKS2` passes) |

The fused XTS kernel is validated byte-for-byte against `golang.org/x/crypto/xts`
(previously confirmed byte-identical to OpenSSL) and against the published IEEE
P1619 / NIST known-answer vectors, on both little- and big-endian.

## Bulk AES-XTS — BEFORE → AFTER (single core, MB/s — higher is better)

Host (`darwin/arm64`), via the production `sectorCipher` path:

| op | algo | before (`x/crypto/xts`) | **after (fused kernel)** | speedup |
|---|---|---:|---:|---:|
| encrypt | AES-256-XTS | 585 MB/s | **3400 MB/s** | **5.8×** |
| decrypt | AES-256-XTS | 583 MB/s | **3413 MB/s** | **5.9×** |
| encrypt | AES-128-XTS | 591 MB/s | **3514 MB/s** | **5.9×** |
| encrypt | AES-CBC-ESSIV-256 | 843 MB/s | 827 MB/s | n/a (CBC unchanged) |

Apples-to-apples on `cb-tpm-ubuntu` (ours vs cryptsetup on the same VM):

| op | algo | **ours** | cryptsetup (in-mem) | OpenSSL (1 KiB / 8 KiB) | ratio vs cryptsetup | verdict |
|---|---|---:|---:|---:|---:|---|
| encrypt | AES-256-XTS | **~3010 MB/s** | 3539 MB/s | 9401 / 11 035 MB/s | **0.85×** | ✅ near parity |
| decrypt | AES-256-XTS | **~3277 MB/s** | 3554 MB/s | 9401 / 11 035 MB/s | **0.92×** | ✅ near parity |
| encrypt | AES-128-XTS | **~3433 MB/s** | 3357 MB/s | 11 601 / 13 485 MB/s | **1.02×** | ✅ at/above cryptsetup |

(`cryptsetup benchmark` reports MiB/s; converted to MB/s. OpenSSL columns are the
1 KiB and 8 KiB block sizes from `openssl speed`.)

## KDF — unlock cost (ms/derivation, lower is better; equal params)

| op | params | ours | cryptsetup / ref | ratio | verdict |
|---|---|---:|---:|---:|---|
| PBKDF2-SHA256 | 100 000 iters, 32 B | **9.6 ms** | 9.5 ms (cryptsetup: 9.50 M iters/s ⇒ 10.5 ms/100k) | ~1.0× | ✅ at parity |
| Argon2id | t=4, m=256 MiB, p=1 | **581 ms** | same `x/crypto` reference primitive | n/a | ✅ same primitive |

Both stacks use the **same** Argon2/PBKDF2 reference code (`golang.org/x/crypto`
mirrors the C reference); at identical cost parameters they are equivalent.

## Summary

**Bulk AES-XTS is now at parity with cryptsetup** (0.85–1.02× per core, up from
0.13×), a **~5.8× speedup** over the previous `x/crypto/xts` path. This was never
a software-AES-vs-hardware-AES gap — `crypto/aes` already uses ARMv8 AES (raw
AES-CTR streams at ~10 GB/s). The old bottleneck was `x/crypto/xts` driving AES
one 16-byte block at a time through the `cipher.Block` interface plus a scalar
GF(2¹²⁸) tweak multiply per block, which defeated the pipelined multi-block AES
path. The fused kernel pipelines four blocks and keeps the AES units busy.

Remaining headroom to OpenSSL (~3× faster at large block sizes) comes from
OpenSSL's deeper 8-block interleave and `PMULL`-based tweak doubling; for
512-byte sectors the 4-block pipeline already saturates the AES units on this
silicon. An 8-wide / `PMULL`-tweak kernel plus multi-core sector parallelism is
the path to OpenSSL-class numbers and is tracked as future work — cryptsetup
parity, the stated bar, is met. The KDF leg was already at parity.

See [`benchmarks/`](benchmarks/) for the reproducible harness
(`./benchmarks/run.sh`).
