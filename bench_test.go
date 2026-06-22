package luks

import (
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Benchmarks for the hot crypto paths of the LUKS backend.
//
// These exercise the exact code that go-fde/luks uses in production:
//   - sectorCipher (AES-XTS / AES-CBC-ESSIV over golang.org/x/crypto/xts +
//     crypto/aes, which uses the ARMv8 AES instructions on arm64 and AES-NI
//     on amd64),
//   - the PBKDF2 and Argon2 KDFs used to unlock LUKS1/LUKS2 key slots.
//
// They are excluded from the coverage gate: `go test` without -bench skips
// Benchmark* functions, and benchmark bodies do not contribute to coverage.

const benchSectorSize = 512

func benchData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func benchXTS(b *testing.B, keyLen, bufBytes int) {
	key := benchData(keyLen)
	sc, err := newSectorCipher("aes-xts-plain64", key, benchSectorSize)
	if err != nil {
		b.Fatal(err)
	}
	buf := benchData(bufBytes)
	nSectors := bufBytes / benchSectorSize
	b.SetBytes(int64(bufBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < nSectors; s++ {
			off := s * benchSectorSize
			_ = sc.encryptSector(buf[off:off+benchSectorSize], uint64(s))
		}
	}
}

func benchXTSDecrypt(b *testing.B, keyLen, bufBytes int) {
	key := benchData(keyLen)
	sc, err := newSectorCipher("aes-xts-plain64", key, benchSectorSize)
	if err != nil {
		b.Fatal(err)
	}
	buf := benchData(bufBytes)
	nSectors := bufBytes / benchSectorSize
	b.SetBytes(int64(bufBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < nSectors; s++ {
			off := s * benchSectorSize
			_ = sc.decryptSector(buf[off:off+benchSectorSize], uint64(s))
		}
	}
}

// AES-256-XTS: 64-byte key (two 32-byte AES-256 keys).
func BenchmarkXTSEncryptAES256(b *testing.B) { benchXTS(b, 64, 1<<20) }
func BenchmarkXTSDecryptAES256(b *testing.B) { benchXTSDecrypt(b, 64, 1<<20) }

// AES-128-XTS: 32-byte key (two 16-byte AES-128 keys).
func BenchmarkXTSEncryptAES128(b *testing.B) { benchXTS(b, 32, 1<<20) }

func benchCBCESSIV(b *testing.B, bufBytes int) {
	key := benchData(32)
	sc, err := newSectorCipher("aes-cbc-essiv:sha256", key, benchSectorSize)
	if err != nil {
		b.Fatal(err)
	}
	buf := benchData(bufBytes)
	nSectors := bufBytes / benchSectorSize
	b.SetBytes(int64(bufBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < nSectors; s++ {
			off := s * benchSectorSize
			_ = sc.encryptSector(buf[off:off+benchSectorSize], uint64(s))
		}
	}
}

func BenchmarkCBCESSIVEncrypt(b *testing.B) { benchCBCESSIV(b, 1<<20) }

// --- KDF benchmarks (key-slot unlock cost) ---

func BenchmarkPBKDF2_SHA256_100k(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := benchData(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2.Key(pass, salt, 100000, 32, sha256.New)
	}
}

// Argon2id at a typical cryptsetup LUKS2 default-ish working point.
func BenchmarkArgon2id_t4_m256MiB_p1(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := benchData(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, salt, 4, 256*1024, 1, 32)
	}
}

func BenchmarkArgon2id_t4_m1GiB_p4(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := benchData(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, salt, 4, 1024*1024, 4, 32)
	}
}
