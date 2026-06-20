<p align="center"><img src="https://raw.githubusercontent.com/go-fde/brand/main/social/go-fde-luks.png" alt="go-fde/luks" width="720"></p>

# luks

Pure-Go read/write support for LUKS1 and LUKS2 full-disk encryption containers.

## Features

### LUKS version 1

| Feature | Status |
|---------|--------|
| Header parsing (592-byte phdr, 8 key slots) | ✅ |
| Key derivation: PBKDF2 | ✅ |
| Hash specs: `sha1`, `sha256`, `sha512`, `ripemd160` | ✅ |
| Anti-forensic split/merge (AF) | ✅ |
| Cipher: `aes-xts-plain64` | ✅ |
| Cipher: `aes-cbc-essiv:sha256` | ✅ |
| Cipher: `twofish-*`, `serpent-*` | ❌ (extremely rare; out of scope) |
| Hash specs: `sha3-*`, `blake2b` | ❌ (very rare; out of scope) |

### LUKS version 2

| Feature | Status |
|---------|--------|
| Binary superblock + JSON metadata parsing | ✅ |
| Key derivation: PBKDF2 | ✅ |
| Key derivation: Argon2i | ✅ |
| Key derivation: Argon2id | ✅ |
| Cipher: `aes-xts-plain64` | ✅ |
| Cipher: `aes-cbc-essiv:sha256` | ✅ |
| Segment `iv_tweak` (non-zero starting sector number) | ✅ |
| Integrity (AEAD per-sector tags, `--integrity` flag) | ❌ (complex; out of scope) |
| Hardware tokens (FIDO2, TPM, smart cards) | ❌ (out of scope for passphrase library) |
| Detached headers | ❌ (out of scope) |
| Backup header fallback (secondary copy at `hdrSize/2`) | ❌ (valid devices always have a readable primary header) |

## Usage

```go
import "github.com/go-fde/luks"

// Open and unlock a LUKS container.
dev, err := luks.Open("/dev/sdb", []byte("my passphrase"))
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

// Read decrypted payload (offset is relative to the payload start).
buf := make([]byte, 4096)
n, err := dev.ReadAt(buf, 0)

// Write to the payload (encrypt-on-write).
_, err = dev.WriteAt([]byte("hello"), 0)

// Check whether a file looks like a LUKS container.
ok, err := luks.Detect("/path/to/disk.img")
```

### Create a new LUKS1 container

`Format` and `FormatOn` initialise a fresh LUKS1 header on an existing file or
block device, derive an encryption key from the passphrase, and return an open
`*Device` ready for payload I/O. Container parameters:

| Parameter | Value |
|-----------|-------|
| LUKS version | 1 |
| Master key size | 32 bytes (AES-256) |
| Cipher | `aes-xts-plain64` |
| Key derivation | PBKDF2-SHA256, 1000 iterations |
| AF stripes | 4000 |
| Key material offset | sector 8 |
| Payload offset | sector 258 (132 096 bytes from start) |

```go
// The file must exist before calling Format.
f, _ := os.Create("disk.luks")
f.Close()

dev, err := luks.Format("disk.luks", []byte("passphrase"))
if err != nil { log.Fatal(err) }
defer dev.Close()

// WriteAt offset is relative to payload start (sector 0 of plaintext).
dev.WriteAt(myData, 0)
```

`FormatOn` accepts the same `blockRW` interface as `OpenFrom`, allowing LUKS to
be initialised directly inside a QCOW2 virtual disk or any other RW backend.

## IV sector number semantics

Sector numbers used for IV computation start at `0` (or the LUKS2 `iv_tweak`
value) for the first payload sector and increment by one per sector,
independently of where the payload sits in the file. This matches the behaviour
of `cryptsetup`, making containers created by this library interoperable with
the standard Linux tooling.

## Compatibility

Containers created or opened by this library are fully interoperable with
`cryptsetup` for the supported feature set above. The supported feature set
covers the vast majority of LUKS containers found in practice:

- LUKS1 with `aes-xts-plain64` and `sha256` (the `cryptsetup` default)
- LUKS1 with `aes-cbc-essiv:sha256` and `sha1`/`ripemd160` (legacy containers)
- LUKS2 with PBKDF2 or Argon2id (the `cryptsetup` LUKS2 default)

## Layering on top of other block devices (raw, QCOW2, …)

`OpenFrom` allows layering LUKS on top of any read-write-closable block device
instead of a plain file. This is useful when the LUKS container lives inside a
virtual disk image format such as QCOW2.

The caller passes any value that satisfies:

```go
interface {
    io.ReaderAt
    WriteAt([]byte, int64) (int, error)
    io.Closer
}
```

LUKS will use it as the underlying storage. When the returned `*Device` is
closed it also closes the underlying block device.

### Example: LUKS over QCOW2

```go
import (
    luks      "github.com/go-fde/luks"
    image_qcow2 "github.com/go-diskimages/qcow2"
)

// 1. Open the QCOW2 container.
qdev, err := image_qcow2.OpenDevice("disk.qcow2")
if err != nil { log.Fatal(err) }

// 2. Unlock the LUKS container embedded in the QCOW2 virtual disk.
//    ldev.Close() will also close qdev.
ldev, err := luks.OpenFrom(qdev, []byte("passphrase"))
if err != nil {
    qdev.Close()
    log.Fatal(err)
}
defer ldev.Close()

// 3. Read/write the plaintext payload.
buf := make([]byte, 512)
_, err = ldev.ReadAt(buf, 0)
```

### Creating a LUKS container inside a QCOW2 image

LUKS operates at the raw block level. To embed a LUKS container inside QCOW2:

1. Create a raw file of the desired size: `truncate -s 2G disk.raw`
2. Format with LUKS: `cryptsetup luksFormat disk.raw`
3. Convert to QCOW2: `qemu-img convert -f raw -O qcow2 disk.raw disk.qcow2`

Alternatively, create the QCOW2 image first, write the LUKS header directly
into the virtual disk using `OpenDevice` + `WriteAt`, then use `OpenFrom` to
unlock it — as the `diskimage` package does for testing.

