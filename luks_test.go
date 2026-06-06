package luks

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// -----------------------------------------------------------------------
// Helpers to build minimal synthetic LUKS1 images for testing.
// -----------------------------------------------------------------------

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// buildLUKS1Image creates a minimal but cryptographically valid LUKS1 image
// in memory. It returns the image bytes, volume key, and passphrase used.
func buildLUKS1Image(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	passphrase := []byte("correct horse battery staple")
	volumeKey := mustRand(32) // 256-bit AES-XTS key
	cipherName := "aes"
	cipherMode := "xts-plain64"
	hashSpec := "sha256"
	stripes := 4000
	sectorSize := 512

	// Key slot PBKDF2 parameters.
	slotSalt := mustRand(32)
	slotIter := 1000
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, 32, sha256.New)

	// AF-split the volume key.
	afData := afSplit(t, volumeKey, stripes)

	// Encrypt AF data with the slot key.
	enc, err := newSectorCipher(cipherName+"-"+cipherMode, slotKey, sectorSize)
	if err != nil {
		t.Fatalf("buildLUKS1Image: cipher: %v", err)
	}
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		end := (i + 1) * sectorSize
		if end > len(encAF) {
			end = len(encAF)
		}
		if err := enc.encryptSector(encAF[i*sectorSize:end], uint64(i)); err != nil {
			t.Fatalf("buildLUKS1Image: encrypt AF: %v", err)
		}
	}

	// MK digest.
	mkSalt := mustRand(32)
	mkIter := 1000
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, mkIter, 20, sha256.New)

	// Place key material at sector 8 (first available area after phdr).
	kmOffset := uint32(8) // sector
	payloadOffset := uint32(8 + uint32(stripes*32)/512 + 8)

	return buildLUKS1Bytes(t, buildLUKS1Params{
		cipherName: cipherName, cipherMode: cipherMode, hashSpec: hashSpec,
		payloadOffset: payloadOffset, keyBytes: 32,
		mkDigest: mkDigest, mkSalt: mkSalt, mkIter: mkIter,
		slotSalt: slotSalt, slotIter: slotIter,
		kmOffset: kmOffset, stripes: uint32(stripes),
		encAF: encAF,
	}), volumeKey, passphrase
}

type buildLUKS1Params struct {
	cipherName, cipherMode, hashSpec string
	payloadOffset, keyBytes          uint32
	mkDigest, mkSalt                 []byte
	mkIter                           int
	slotSalt                         []byte
	slotIter                         int
	kmOffset, stripes                uint32
	encAF                            []byte
}

// buildLUKS1Bytes serialises the LUKS1 phdr + key-material area.
func buildLUKS1Bytes(t *testing.T, p buildLUKS1Params) []byte {
	t.Helper()
	img := make([]byte, int(p.payloadOffset)*512+512)
	// Magic + version
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	writePaddedStr(img[8:40], p.cipherName)
	writePaddedStr(img[40:72], p.cipherMode)
	writePaddedStr(img[72:104], p.hashSpec)
	binary.BigEndian.PutUint32(img[104:108], p.payloadOffset)
	binary.BigEndian.PutUint32(img[108:112], p.keyBytes)
	copy(img[112:132], p.mkDigest)
	copy(img[132:164], p.mkSalt)
	binary.BigEndian.PutUint32(img[164:168], uint32(p.mkIter))
	copy(img[168:208], []byte("test-uuid-000000000000000000000000000000"))
	// Slot 0 (active)
	base := 208
	binary.BigEndian.PutUint32(img[base:], luks1KeySlotActive)
	binary.BigEndian.PutUint32(img[base+4:], uint32(p.slotIter))
	copy(img[base+8:base+40], p.slotSalt)
	binary.BigEndian.PutUint32(img[base+40:], p.kmOffset)
	binary.BigEndian.PutUint32(img[base+44:], p.stripes)
	// Slots 1-7 inactive (0xDEAD0000)
	for i := 1; i < 8; i++ {
		b := 208 + i*48
		binary.BigEndian.PutUint32(img[b:], 0xDEAD0000)
	}
	// Key material area
	copy(img[int(p.kmOffset)*512:], p.encAF)
	return img
}

// afSplit produces a synthetic AF split of key for testing (inverse of afMerge).
// It uses random stripes and sets the last stripe so that afMerge recovers key.
func afSplit(t *testing.T, key []byte, stripes int) []byte {
	t.Helper()
	return afSplitWithHash(t, key, stripes, "sha256")
}

// afSplitWithHash is like afSplit but uses the specified hash for diffusion.
func afSplitWithHash(t *testing.T, key []byte, stripes int, hashName string) []byte {
	t.Helper()
	keyBytes := len(key)
	afData := make([]byte, keyBytes*stripes)
	d := make([]byte, keyBytes)
	for i := 0; i < stripes-1; i++ {
		stripe := mustRand(keyBytes)
		copy(afData[i*keyBytes:], stripe)
		xorBytes(d, stripe)
		if err := hashDiffuse(d, hashName); err != nil {
			t.Fatalf("afSplitWithHash: diffuse: %v", err)
		}
	}
	last := afData[(stripes-1)*keyBytes : stripes*keyBytes]
	copy(last, d)
	xorBytes(last, key)
	return afData
}

// writePaddedStr writes s as a null-terminated string into buf (zero-padded).
func writePaddedStr(buf []byte, s string) {
	copy(buf, s)
	for i := len(s); i < len(buf); i++ {
		buf[i] = 0
	}
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func TestDetect_LUKS(t *testing.T) {
	imgData, _, _ := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !ok {
		t.Fatal("Detect returned false for LUKS image")
	}
}

func TestDetect_NonLUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if ok {
		t.Fatal("Detect returned true for non-LUKS file")
	}
}

func TestDetect_NotExist(t *testing.T) {
	_, err := Detect(filepath.Join(t.TempDir(), "nofile"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestOpen_LUKS1_CorrectPassphrase(t *testing.T) {
	imgData, volumeKey, passphrase := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()
	if !bytes.Equal(dev.h.volumeKey, volumeKey) {
		t.Errorf("volume key mismatch")
	}
}

func TestOpen_LUKS1_WrongPassphrase(t *testing.T) {
	imgData, _, _ := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("wrong passphrase")); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestOpen_BadMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestOpen_NotExist(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nofile"), []byte("pass")); err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestOpen_UnsupportedVersion(t *testing.T) {
	img := make([]byte, 4096)
	copy(img, luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 99) // version 99
	path := filepath.Join(t.TempDir(), "disk.luks99")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestLUKS1_ReadWriteRoundtrip(t *testing.T) {
	imgData, _, passphrase := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	want := []byte("hello LUKS world!")
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := dev.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadAt got %q, want %q", got, want)
	}
}

// -----------------------------------------------------------------------
// Unit tests for sub-components.
// -----------------------------------------------------------------------

func TestAFMerge_RoundTrip(t *testing.T) {
	key := mustRand(32)
	afData := afSplit(t, key, 4000)
	got, err := afMerge(afData, 32, 4000, "sha256")
	if err != nil {
		t.Fatalf("afMerge: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("afMerge did not recover original key")
	}
}

func TestAFMerge_ShortData(t *testing.T) {
	if _, err := afMerge(make([]byte, 1), 32, 4000, "sha256"); err == nil {
		t.Fatal("expected error for short AF data")
	}
}

func TestAFMerge_InvalidStripes(t *testing.T) {
	if _, err := afMerge(make([]byte, 32), 32, 0, "sha256"); err == nil {
		t.Fatal("expected error for stripes=0")
	}
}

func TestAFMerge_UnknownHash(t *testing.T) {
	afData := afSplit(t, mustRand(32), 4)
	if _, err := afMerge(afData, 32, 4, "md99"); err == nil {
		t.Fatal("expected error for unknown hash")
	}
}

func TestCipher_XTS_RoundTrip(t *testing.T) {
	key := mustRand(64) // 512-bit key for AES-XTS-256
	enc, err := newSectorCipher("aes-xts-plain64", key, 512)
	if err != nil {
		t.Fatalf("newSectorCipher: %v", err)
	}
	pt := mustRand(512)
	ct := make([]byte, 512)
	copy(ct, pt)
	if err := enc.encryptSector(ct, 0); err != nil {
		t.Fatalf("encryptSector: %v", err)
	}
	if bytes.Equal(ct, pt) {
		t.Error("ciphertext equals plaintext")
	}
	if err := enc.decryptSector(ct, 0); err != nil {
		t.Fatalf("decryptSector: %v", err)
	}
	if !bytes.Equal(ct, pt) {
		t.Error("decrypted sector does not match original")
	}
}

func TestCipher_CBCESSIV_RoundTrip(t *testing.T) {
	key := mustRand(32) // 256-bit AES key (CBC takes first half: 128-bit)
	enc, err := newSectorCipher("aes-cbc-essiv:sha256", key, 512)
	if err != nil {
		t.Fatalf("newSectorCipher cbc: %v", err)
	}
	pt := mustRand(512)
	ct := make([]byte, 512)
	copy(ct, pt)
	if err := enc.encryptSector(ct, 3); err != nil {
		t.Fatalf("encryptSector: %v", err)
	}
	if err := enc.decryptSector(ct, 3); err != nil {
		t.Fatalf("decryptSector: %v", err)
	}
	if !bytes.Equal(ct, pt) {
		t.Error("decrypted sector does not match original")
	}
}

func TestCipher_UnknownCipher(t *testing.T) {
	if _, err := newSectorCipher("blowfish-cbc", mustRand(16), 512); err == nil {
		t.Fatal("expected error for unsupported cipher")
	}
}

func TestCipher_UnknownMode(t *testing.T) {
	if _, err := newSectorCipher("aes-ofb", mustRand(16), 512); err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}

func TestNullStr(t *testing.T) {
	buf := []byte{'a', 'e', 's', 0, 0, 0}
	if got := nullStr(buf); got != "aes" {
		t.Errorf("nullStr = %q, want %q", got, "aes")
	}
}

func TestHashFactory_Unsupported(t *testing.T) {
	if _, err := hashFactory("md5"); err == nil {
		t.Fatal("expected error for unsupported hash")
	}
}

func TestHashFactory_SHA1(t *testing.T) {
	hf, err := hashFactory("sha1")
	if err != nil {
		t.Fatalf("hashFactory sha1: %v", err)
	}
	h := hf()
	h.Write([]byte("test"))
	if len(h.Sum(nil)) != 20 {
		t.Error("sha1 digest length mismatch")
	}
}

func TestHashFactory_SHA512(t *testing.T) {
	hf, err := hashFactory("sha512")
	if err != nil {
		t.Fatalf("hashFactory sha512: %v", err)
	}
	if hf().Size() != 64 {
		t.Error("sha512 size mismatch")
	}
}

// TestLUKS1_CBCESSIVImage tests unlocking with aes-cbc-essiv:sha256.
func TestLUKS1_CBCESSIVImage(t *testing.T) {
	passphrase := []byte("cbc test passphrase")
	volumeKey := mustRand(16) // 128-bit key for AES-128-CBC
	slotSalt := mustRand(32)
	slotIter := 500
	// slot key size matches keyBytes (16 for AES-128)
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, 16, sha256.New)
	stripes := 100

	afData := afSplit(t, volumeKey, stripes)
	enc, err := newSectorCipher("aes-cbc-essiv:sha256", slotKey, 512)
	if err != nil {
		t.Fatalf("cipher setup: %v", err)
	}
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	// Pad to sector boundary (CBC-ESSIV encrypts full sectors only).
	sectorAligned := ((len(encAF) + 511) / 512) * 512
	paddedAF := make([]byte, sectorAligned)
	copy(paddedAF, encAF)
	for i := 0; i*512 < len(paddedAF); i++ {
		if err := enc.encryptSector(paddedAF[i*512:(i+1)*512], uint64(i)); err != nil {
			t.Fatalf("encrypt AF sector %d: %v", i, err)
		}
	}

	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 500, 20, sha256.New)
	kmOffset := uint32(8)
	payloadOffset := uint32(kmOffset + uint32(sectorAligned)/512 + 2)

	imgData := buildLUKS1Bytes(t, buildLUKS1Params{
		cipherName: "aes", cipherMode: "cbc-essiv:sha256", hashSpec: "sha256",
		payloadOffset: payloadOffset, keyBytes: 16,
		mkDigest: mkDigest, mkSalt: mkSalt, mkIter: 500,
		slotSalt: slotSalt, slotIter: slotIter,
		kmOffset: kmOffset, stripes: uint32(stripes),
		encAF: paddedAF,
	})
	path := filepath.Join(t.TempDir(), "cbc.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open CBC image: %v", err)
	}
	defer dev.Close()
	if !strings.Contains(dev.h.cipher, "cbc") {
		t.Errorf("expected cbc cipher, got %q", dev.h.cipher)
	}
}

// TestLUKS2_UnsupportedKDF exercises the Argon2 path via a synthetic LUKS2
// image. A full LUKS2 image is complex to construct; we test only the error
// path for an unsupported KDF type.
func TestLUKS2_UnknownKDF(t *testing.T) {
	slot := &luks2Keyslot{
		Type:    "luks2",
		KeySize: 64,
		KDF:     luks2KDF{Type: "bcrypt", Salt: mustRand(32)},
		AF:      luks2AF{Type: "luks1", Stripes: 4000, Hash: "sha256"},
		Area:    luks2KeyArea{Encryption: "aes-xts-plain64", KeySize: 64},
	}
	if _, err := tryLUKS2Slot(nil, slot, []byte("pass")); err == nil {
		t.Fatal("expected error for unsupported KDF")
	}
}

// TestXorBytes ensures XOR is applied correctly.
func TestXorBytes(t *testing.T) {
	dst := []byte{0xFF, 0x00, 0xAA}
	src := []byte{0x0F, 0xFF, 0x55}
	xorBytes(dst, src)
	want := []byte{0xF0, 0xFF, 0xFF}
	if !bytes.Equal(dst, want) {
		t.Errorf("xorBytes = %v, want %v", dst, want)
	}
}

// TestDeviceSize checks that Size() returns the payload length set in header.
func TestDeviceSize(t *testing.T) {
	imgData, _, passphrase := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()
	// payloadLen is 0 for LUKS1 (dynamic).
	if dev.Size() != 0 {
		t.Errorf("Size() = %d, want 0 for dynamic payload", dev.Size())
	}
}

// TestCipher_BadKey checks that an invalid key length is rejected.
func TestCipher_BadKey(t *testing.T) {
	// AES-XTS requires 32 or 64 bytes; 15 bytes is invalid.
	if _, err := newSectorCipher("aes-xts-plain64", mustRand(15), 512); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

// TestCipherMissingMode ensures a bare cipher name without mode is rejected.
func TestCipherMissingMode(t *testing.T) {
	if _, err := newSectorCipher("aes", mustRand(32), 512); err == nil {
		t.Fatal("expected error for cipher string without mode")
	}
}

// TestParseOffset ensures parseOffset handles valid and invalid inputs.
func TestParseOffset(t *testing.T) {
	if v, err := parseOffset("16777216"); err != nil || v != 16777216 {
		t.Errorf("parseOffset valid: got %d %v", v, err)
	}
	if _, err := parseOffset("notanumber"); err == nil {
		t.Fatal("expected error for non-numeric offset")
	}
}

// TestDecryptRaw_PartialSector verifies decryptRaw pads and handles a partial
// last sector (using CBC-ESSIV which supports non-sector-multiple inputs).
func TestDecryptRaw_PartialSector(t *testing.T) {
	key := mustRand(32)
	enc, err := newSectorCipher("aes-cbc-essiv:sha256", key, 512)
	if err != nil {
		t.Fatalf("newSectorCipher: %v", err)
	}
	// 600 bytes: one full 512-byte sector + 88-byte partial (padded to 512).
	ct := mustRand(600)
	if _, err := enc.decryptRaw(ct); err != nil {
		t.Fatalf("decryptRaw partial: %v", err)
	}
}

// TestLUKS1_AllSlotsInactive verifies an error when no slot is active.
func TestLUKS1_AllSlotsInactive(t *testing.T) {
	imgData, _, _ := buildLUKS1Image(t)
	// Mark slot 0 as inactive.
	binary.BigEndian.PutUint32(imgData[208:], 0xDEAD0000)
	path := filepath.Join(t.TempDir(), "inactive.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("any")); err == nil {
		t.Fatal("expected error when no key slot is active")
	}
}

// TestVerifyMasterKey_Mismatch checks that digest verification rejects bad keys.
func TestVerifyMasterKey_Mismatch(t *testing.T) {
	hf, _ := hashFactory("sha256")
	salt := mustRand(32)
	digest := pbkdf2.Key([]byte("correct"), salt, 1000, 20, hf)
	if err := verifyMasterKey([]byte("wrong"), digest, salt, 1000, hf); err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

// TestAES128XTS ensures we can create an AES-128-XTS cipher (32-byte key).
func TestAES128XTS(t *testing.T) {
	enc, err := newSectorCipher("aes-xts-plain64", mustRand(32), 512)
	if err != nil {
		t.Fatalf("AES-128-XTS: %v", err)
	}
	pt := mustRand(512)
	ct := make([]byte, 512)
	copy(ct, pt)
	if err := enc.encryptSector(ct, 1); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := enc.decryptSector(ct, 1); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(ct, pt) {
		t.Error("roundtrip failed for AES-128-XTS")
	}
}

// Compile-time check: buildLUKS1Image uses aes internally via crypto/aes.
var _ = aes.NewCipher

// -----------------------------------------------------------------------
// LUKS2 synthetic image builder and tests
// -----------------------------------------------------------------------

// buildLUKS2Image builds a minimal valid LUKS2 image with a PBKDF2 key slot.
func buildLUKS2Image(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	passphrase := []byte("luks2 passphrase")
	volumeKey := mustRand(64) // 512-bit AES-XTS key

	stripes := 4
	keySize := 64
	areaKeySize := 64 // same as volume key for PBKDF2 slot
	sectorSize := 512

	slotSalt := mustRand(32)
	slotIter := 200
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, areaKeySize, sha256.New)

	afData := afSplit(t, volumeKey, stripes)
	enc, err := newSectorCipher("aes-xts-plain64", slotKey, sectorSize)
	if err != nil {
		t.Fatalf("buildLUKS2: cipher: %v", err)
	}
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		end := (i + 1) * sectorSize
		if end > len(encAF) {
			end = len(encAF)
		}
		if err := enc.encryptSector(encAF[i*sectorSize:end], uint64(i)); err != nil {
			t.Fatalf("buildLUKS2: encrypt af sector %d: %v", i, err)
		}
	}

	mkSalt := mustRand(32)
	mkIter := 200
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, mkIter, 32, sha256.New)

	// Layout:
	//   0    - 4095:  binary superblock (primary)
	//   4096 - 8191:  JSON area (12288-4096 = 8192 bytes → hdrSize/2 = 8192+4096 = 12288)
	//   12288 - 24575: secondary superblock (copy, we leave it empty)
	//   32768+:        key area and payload
	hdrSize := uint64(16384 * 2)   // 32768 total for both header copies
	areaOffset := int64(65536)     // key area starts after the header
	payloadOffset := int64(131072) // payload starts 64KiB after key area

	jsonStr := buildLUKS2JSON(slotSalt, slotIter, keySize, areaKeySize, stripes,
		areaOffset, mkSalt, mkIter, mkDigest, payloadOffset, sectorSize)

	totalSize := payloadOffset + 512
	img := make([]byte, totalSize)

	// Binary superblock.
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], hdrSize)
	binary.BigEndian.PutUint64(img[16:24], 1) // seqID
	writePaddedStr(img[72:104], "sha256")     // checkAlg
	copy(img[104:168], mustRand(64))          // salt (random, not verified)
	writePaddedStr(img[168:208], "test-luks2-uuid-000000000000000000000")

	// JSON area immediately after binary superblock.
	copy(img[luks2BinHdrSize:], jsonStr)

	// Key material area.
	copy(img[areaOffset:], encAF)

	return img, volumeKey, passphrase
}

// buildLUKS2JSON produces the JSON config string for the synthetic LUKS2 image.
func buildLUKS2JSON(slotSalt []byte, slotIter, keySize, areaKeySize, stripes int,
	areaOffset int64, mkSalt []byte, mkIter int, mkDigest []byte,
	payloadOffset int64, sectorSize int) []byte {
	type m = map[string]interface{}
	cfg := m{
		"keyslots": m{
			"0": m{
				"type": "luks2", "key_size": keySize,
				"kdf": m{
					"type": "pbkdf2", "hash": "sha256",
					"iterations": slotIter, "salt": slotSalt,
				},
				"af": m{"type": "luks1", "stripes": stripes, "hash": "sha256"},
				"area": m{"type": "raw", "offset": fmt.Sprintf("%d", areaOffset),
					"size":       fmt.Sprintf("%d", areaKeySize*stripes),
					"encryption": "aes-xts-plain64", "key_size": areaKeySize},
			},
		},
		"segments": m{
			"0": m{
				"type": "crypt", "offset": fmt.Sprintf("%d", payloadOffset),
				"size": "dynamic", "encryption": "aes-xts-plain64",
				"sector_size": sectorSize, "iv_tweak": "0",
			},
		},
		"digests": m{
			"0": m{
				"type": "pbkdf2", "keyslots": []string{"0"}, "segments": []string{"0"},
				"hash": "sha256", "iterations": mkIter,
				"salt": mkSalt, "digest": mkDigest,
			},
		},
		"config": m{"json_size": "12288", "keyslots_size": fmt.Sprintf("%d", areaOffset)},
	}
	b, _ := json.Marshal(cfg)
	return b
}

func TestOpen_LUKS2_CorrectPassphrase(t *testing.T) {
	imgData, volumeKey, passphrase := buildLUKS2Image(t)
	path := filepath.Join(t.TempDir(), "disk2.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open LUKS2: %v", err)
	}
	defer dev.Close()
	if !bytes.Equal(dev.h.volumeKey, volumeKey) {
		t.Error("LUKS2 volume key mismatch")
	}
}

func TestOpen_LUKS2_WrongPassphrase(t *testing.T) {
	imgData, _, _ := buildLUKS2Image(t)
	path := filepath.Join(t.TempDir(), "disk2.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("wrong")); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestLUKS2_ReadWriteRoundtrip(t *testing.T) {
	imgData, _, passphrase := buildLUKS2Image(t)
	path := filepath.Join(t.TempDir(), "disk2.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open LUKS2: %v", err)
	}
	defer dev.Close()
	want := []byte("hello LUKS2 world!")
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := dev.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadAt got %q, want %q", got, want)
	}
}

func TestLUKS2_BadJSON(t *testing.T) {
	img := make([]byte, 32768)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 32768) // hdrSize
	writePaddedStr(img[72:104], "sha256")
	copy(img[luks2BinHdrSize:], []byte("{invalid json"))
	path := filepath.Join(t.TempDir(), "bad.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLUKS2_NoCryptSegment(t *testing.T) {
	img := make([]byte, 32768)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 32768)
	writePaddedStr(img[72:104], "sha256")
	js, _ := json.Marshal(map[string]interface{}{
		"keyslots": map[string]interface{}{},
		"segments": map[string]interface{}{
			"0": map[string]interface{}{"type": "linear", "offset": "32768", "size": "dynamic"},
		},
		"digests": map[string]interface{}{},
		"config":  map[string]interface{}{"json_size": "12288"},
	})
	copy(img[luks2BinHdrSize:], js)
	path := filepath.Join(t.TempDir(), "noseg.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for missing crypt segment")
	}
}

func TestLUKS2_ArgonSlot(t *testing.T) {
	// Build a LUKS2 image with an Argon2id key slot (exercises deriveKeyLUKS2 argon2id path).
	passphrase := []byte("argon2 pass")
	volumeKey := mustRand(64)
	stripes := 4
	keySize := 64
	sectorSize := 512
	slotSalt := mustRand(32)

	slotKey := argon2IDKey(passphrase, slotSalt, 1, 8, 1, keySize)
	afData := afSplit(t, volumeKey, stripes)
	enc, _ := newSectorCipher("aes-xts-plain64", slotKey, sectorSize)
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		end := min512(i+1, len(encAF), sectorSize)
		if err := enc.encryptSector(encAF[i*sectorSize:end], uint64(i)); err != nil {
			t.Fatalf("encrypt: %v", err)
		}
	}

	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 100, 32, sha256.New)
	areaOffset := int64(65536)
	payloadOffset := int64(131072)
	hdrSize := uint64(32768)

	type m = map[string]interface{}
	cfg := m{
		"keyslots": m{"0": m{
			"type": "luks2", "key_size": keySize,
			"kdf": m{"type": "argon2id", "time": 1, "memory": 8, "cpus": 1, "salt": slotSalt},
			"af":  m{"type": "luks1", "stripes": stripes, "hash": "sha256"},
			"area": m{"type": "raw", "offset": fmt.Sprintf("%d", areaOffset),
				"size": "256", "encryption": "aes-xts-plain64", "key_size": keySize},
		}},
		"segments": m{"0": m{
			"type": "crypt", "offset": fmt.Sprintf("%d", payloadOffset),
			"size": "dynamic", "encryption": "aes-xts-plain64",
			"sector_size": sectorSize, "iv_tweak": "0",
		}},
		"digests": m{"0": m{
			"type": "pbkdf2", "keyslots": []string{"0"}, "segments": []string{"0"},
			"hash": "sha256", "iterations": 100,
			"salt": mkSalt, "digest": mkDigest,
		}},
		"config": m{"json_size": "12288", "keyslots_size": "65536"},
	}
	js, _ := json.Marshal(cfg)

	totalSize := payloadOffset + 512
	img := make([]byte, totalSize)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], hdrSize)
	binary.BigEndian.PutUint64(img[16:24], 1)
	writePaddedStr(img[72:104], "sha256")
	copy(img[104:168], mustRand(64))
	writePaddedStr(img[168:208], "argon2-uuid-test-00000000000000000000")
	copy(img[luks2BinHdrSize:], js)
	copy(img[areaOffset:], encAF)

	path := filepath.Join(t.TempDir(), "argon2.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open Argon2id LUKS2: %v", err)
	}
	defer dev.Close()
	if !bytes.Equal(dev.h.volumeKey, volumeKey) {
		t.Error("Argon2id LUKS2 volume key mismatch")
	}
}

// argon2IDKey is a thin test helper to produce an Argon2id-derived key.
func argon2IDKey(pass, salt []byte, time, mem uint32, threads uint8, keyLen int) []byte {
	return argon2.IDKey(pass, salt, time, mem, threads, uint32(keyLen))
}

// min512 returns the minimum of (i+1)*ss and maxLen.
func min512(nextI, maxLen, ss int) int {
	v := nextI * ss
	if v > maxLen {
		return maxLen
	}
	return v
}

func TestLUKS2_Argon2i(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF:  luks2KDF{Type: "argon2i", Time: 1, Memory: 8, CPUs: 1, Salt: mustRand(32)},
		AF:   luks2AF{Type: "luks1", Stripes: 4, Hash: "sha256"},
		Area: luks2KeyArea{Encryption: "aes-xts-plain64", KeySize: 32},
	}
	key, err := deriveKeyLUKS2(slot, []byte("pass"))
	if err != nil {
		t.Fatalf("Argon2i: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestNullStr_NoNull(t *testing.T) {
	buf := []byte{'a', 'e', 's'}
	if got := nullStr(buf); got != "aes" {
		t.Errorf("nullStr (no null) = %q, want %q", got, "aes")
	}
}

func TestLUKS2_BinHdrShortRead(t *testing.T) {
	img := make([]byte, 100) // too short for 4096-byte superblock
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 32768)
	path := filepath.Join(t.TempDir(), "short.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for short LUKS2 image")
	}
}

// -----------------------------------------------------------------------
// Additional tests for branch/error-path coverage
// -----------------------------------------------------------------------

// errReader is a minimal io.ReaderAt that always returns an error.
type errReader struct{ err error }

func (r errReader) ReadAt(_ []byte, _ int64) (int, error) { return 0, r.err }

// readOnlyAt implements io.ReaderAt but NOT WriteAt, to test the write fallback.
type readOnlyAt struct{ data []byte }

func (ro *readOnlyAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(ro.data)) {
		return 0, fmt.Errorf("read beyond end")
	}
	n := copy(p, ro.data[off:])
	return n, nil
}

// errWriterAt wraps a byte slice and fails on WriteAt.
type errWriterAt struct{ data []byte }

func (w *errWriterAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(w.data)) {
		return 0, fmt.Errorf("read beyond end")
	}
	n := copy(p, w.data[off:])
	return n, nil
}

func (w *errWriterAt) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("write error")
}

// TestCBC_DecryptBadKey exercises cbcDecryptSector with an invalid key size.
func TestCBC_DecryptBadKey(t *testing.T) {
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	if err := sc.cbcDecryptSector(make([]byte, 512), 0); err == nil {
		t.Fatal("expected error for bad cbcKey in decryptSector")
	}
}

// TestCBC_EncryptBadKey exercises cbcEncryptSector with an invalid key size.
func TestCBC_EncryptBadKey(t *testing.T) {
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	if err := sc.cbcEncryptSector(make([]byte, 512), 0); err == nil {
		t.Fatal("expected error for bad cbcKey in encryptSector")
	}
}

// TestDecryptRaw_PartialSectorCBCError exercises the error in decryptRaw's partial-sector path.
func TestDecryptRaw_PartialSectorCBCError(t *testing.T) {
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	if _, err := sc.decryptRaw(make([]byte, 600)); err == nil {
		t.Fatal("expected error for bad cbcKey in decryptRaw partial sector")
	}
}

// TestReadAt_IOError exercises the readAt error path when ReadAt fails.
func TestReadAt_IOError(t *testing.T) {
	enc, _ := newSectorCipher("aes-xts-plain64", mustRand(32), 512)
	r := errReader{err: fmt.Errorf("disk error")}
	if _, err := enc.readAt(r, make([]byte, 512), 0); err == nil {
		t.Fatal("expected error when underlying ReadAt fails")
	}
}

// TestWriteAt_NoWriterAt exercises the path where the underlying reader lacks WriteAt.
func TestWriteAt_NoWriterAt(t *testing.T) {
	enc, _ := newSectorCipher("aes-xts-plain64", mustRand(32), 512)
	ro := &readOnlyAt{data: make([]byte, 512)}
	if _, err := enc.writeAt(ro, []byte("hello"), 0); err == nil {
		t.Fatal("expected error when underlying reader lacks WriteAt")
	}
}

// TestWriteAt_ReadError exercises the read-modify-write read-failure path.
func TestWriteAt_ReadError(t *testing.T) {
	enc, _ := newSectorCipher("aes-xts-plain64", mustRand(32), 512)
	// Use errWriterAt (implements both ReadAt and WriteAt) with empty data
	// so ReadAt always returns an error.
	w := &errWriterAt{data: []byte{}} // ReadAt fails immediately
	if _, err := enc.writeAt(w, []byte("hello"), 0); err == nil {
		t.Fatal("expected error when read-for-RMW fails")
	}
}

// TestWriteAt_WriteError exercises the WriteAt failure path.
func TestWriteAt_WriteError(t *testing.T) {
	enc, _ := newSectorCipher("aes-xts-plain64", mustRand(32), 512)
	w := &errWriterAt{data: make([]byte, 512)}
	if _, err := enc.writeAt(w, []byte("hello"), 0); err == nil {
		t.Fatal("expected error when WriteAt fails")
	}
}

// TestDetect_ShortFile covers the io.ReadFull failure branch in Detect.
func TestDetect_ShortFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny")
	if err := os.WriteFile(path, []byte{1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect on short file: %v", err)
	}
	if ok {
		t.Fatal("Detect should be false for short file")
	}
}

// TestUnlock_ShortFile exercises the ReadAt error in unlock.
func TestUnlock_ShortFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.luks")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for file too short to read magic")
	}
}

// TestLUKS1_ShortHeader exercises the parseLUKS1Phdr ReadAt error path.
func TestLUKS1_ShortHeader(t *testing.T) {
	img := make([]byte, 200) // < 592 bytes needed for LUKS1 phdr
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	path := filepath.Join(t.TempDir(), "short1.luks")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for short LUKS1 header")
	}
}

// TestLUKS1_BadHashSpec exercises the hashFactory error in unlockLUKS1.
func TestLUKS1_BadHashSpec(t *testing.T) {
	img := make([]byte, 4096)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	writePaddedStr(img[8:40], "aes")
	writePaddedStr(img[40:72], "xts-plain64")
	writePaddedStr(img[72:104], "md5") // unsupported
	path := filepath.Join(t.TempDir(), "badhash.luks1")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for unsupported hash spec")
	}
}

// TestLUKS1_KeyMaterialReadFail tests the ReadAt error in readAndDecryptKeyMaterial.
func TestLUKS1_KeyMaterialReadFail(t *testing.T) {
	volumeKey := mustRand(32)
	slotSalt := mustRand(32)
	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 100, 20, sha256.New)
	p := buildLUKS1Params{
		cipherName: "aes", cipherMode: "xts-plain64", hashSpec: "sha256",
		payloadOffset: 4096, keyBytes: 32,
		mkDigest: mkDigest, mkSalt: mkSalt, mkIter: 100,
		slotSalt: slotSalt, slotIter: 100,
		kmOffset: 2000, // far beyond file end after truncation
		stripes:  4000, encAF: make([]byte, 512),
	}
	img := buildLUKS1Bytes(t, p)
	img = img[:592+512] // truncate so offset 2000*512 is unreachable
	path := filepath.Join(t.TempDir(), "kmfail.luks1")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error when key material read fails")
	}
}

// TestLUKS1_BadCipherMode exercises the newSectorCipher error in readAndDecryptKeyMaterial.
func TestLUKS1_BadCipherMode(t *testing.T) {
	passphrase := []byte("badcipher pass")
	volumeKey := mustRand(32)
	slotSalt := mustRand(32)
	slotIter := 100
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, 32, sha256.New)

	stripes := 4000
	afData := afSplit(t, volumeKey, stripes)
	enc, _ := newSectorCipher("aes-xts-plain64", slotKey, 512)
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*512 < len(encAF); i++ {
		enc.encryptSector(encAF[i*512:(i+1)*512], uint64(i))
	}

	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 100, 20, sha256.New)
	kmOffset := uint32(8)
	payloadOffset := uint32(kmOffset + uint32(len(encAF))/512 + 2)

	imgData := buildLUKS1Bytes(t, buildLUKS1Params{
		cipherName: "blowfish", cipherMode: "cbc-plain", hashSpec: "sha256",
		payloadOffset: payloadOffset, keyBytes: 32,
		mkDigest: mkDigest, mkSalt: mkSalt, mkIter: 100,
		slotSalt: slotSalt, slotIter: slotIter,
		kmOffset: kmOffset, stripes: uint32(stripes), encAF: encAF,
	})
	path := filepath.Join(t.TempDir(), "badcipher.luks1")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, passphrase); err == nil {
		t.Fatal("expected error for unsupported cipher in key slot")
	}
}

// TestLUKS2_SmallHdrSize exercises parseLUKS2JSON implausible JSON size path.
func TestLUKS2_SmallHdrSize(t *testing.T) {
	img := make([]byte, 4096)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	// hdrSize/2 = 4096 == luks2BinHdrSize → jsonEnd = 0
	binary.BigEndian.PutUint64(img[8:16], 8192)
	writePaddedStr(img[72:104], "sha256")
	path := filepath.Join(t.TempDir(), "smallhdr.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for implausibly small JSON area")
	}
}

// TestLUKS2_BadAreaOffset exercises parseOffset error in tryLUKS2Slot.
func TestLUKS2_BadAreaOffset(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF: luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:  luks2AF{Type: "luks1", Stripes: 4, Hash: "sha256"},
		Area: luks2KeyArea{Type: "raw", Offset: "notanumber", Size: "512",
			Encryption: "aes-xts-plain64", KeySize: 32},
	}
	ro := &readOnlyAt{data: make([]byte, 4096)}
	if _, err := tryLUKS2Slot(ro, slot, []byte("pass")); err == nil {
		t.Fatal("expected error for invalid area offset")
	}
}

// TestLUKS2_ZeroAFSize exercises the afSize <= 0 guard in tryLUKS2Slot.
func TestLUKS2_ZeroAFSize(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 0,
		KDF:  luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:   luks2AF{Type: "luks1", Stripes: 4, Hash: "sha256"},
		Area: luks2KeyArea{Offset: "0", Encryption: "aes-xts-plain64", KeySize: 32},
	}
	ro := &readOnlyAt{data: make([]byte, 4096)}
	if _, err := tryLUKS2Slot(ro, slot, []byte("pass")); err == nil {
		t.Fatal("expected error for zero afSize")
	}
}

// TestLUKS2_BadSlotCipher exercises the newSectorCipher error in tryLUKS2Slot.
func TestLUKS2_BadSlotCipher(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF:  luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:   luks2AF{Type: "luks1", Stripes: 4, Hash: "sha256"},
		Area: luks2KeyArea{Offset: "0", Encryption: "blowfish-cbc", KeySize: 32},
	}
	ro := &readOnlyAt{data: make([]byte, 32*4+512)}
	if _, err := tryLUKS2Slot(ro, slot, []byte("pass")); err == nil {
		t.Fatal("expected error for unsupported slot cipher")
	}
}

// TestLUKS2_BadSegmentOffset exercises parseOffset error in parseMainSegment.
func TestLUKS2_BadSegmentOffset(t *testing.T) {
	cfg := &luks2JSON{
		Segments: map[string]luks2Segment{
			"0": {Type: "crypt", Offset: "notanumber", Encryption: "aes-xts-plain64", SectorSize: 512},
		},
	}
	if _, _, _, _, err := parseMainSegment(cfg); err == nil {
		t.Fatal("expected error for invalid segment offset")
	}
}

// TestLUKS2_ZeroSectorSize exercises the default sector size path in parseMainSegment.
func TestLUKS2_ZeroSectorSize(t *testing.T) {
	cfg := &luks2JSON{
		Segments: map[string]luks2Segment{
			"0": {Type: "crypt", Offset: "131072", Encryption: "aes-xts-plain64", SectorSize: 0},
		},
	}
	_, _, ss, _, err := parseMainSegment(cfg)
	if err != nil {
		t.Fatalf("parseMainSegment: %v", err)
	}
	if ss != 512 {
		t.Errorf("sector size = %d, want 512", ss)
	}
}

// TestLUKS2_BadPBKDF2Hash exercises the hashFactory error in deriveKeyLUKS2.
func TestLUKS2_BadPBKDF2Hash(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF:  luks2KDF{Type: "pbkdf2", Hash: "md5", Salt: mustRand(32), Iterations: 1},
		Area: luks2KeyArea{KeySize: 32},
	}
	if _, err := deriveKeyLUKS2(slot, []byte("pass")); err == nil {
		t.Fatal("expected error for unsupported PBKDF2 hash")
	}
}

// TestLUKS2_NonPBKDF2Digest exercises the non-pbkdf2 continue in verifyLUKS2MasterKey.
func TestLUKS2_NonPBKDF2Digest(t *testing.T) {
	cfg := &luks2JSON{
		Digests: map[string]luks2Digest{
			"0": {Type: "argon2", Hash: "sha256"},
		},
	}
	if err := verifyLUKS2MasterKey(mustRand(64), cfg); err == nil {
		t.Fatal("expected error when no matching pbkdf2 digest")
	}
}

// TestLUKS2_BadDigestHash exercises the hashFactory continue in verifyLUKS2MasterKey.
func TestLUKS2_BadDigestHash(t *testing.T) {
	cfg := &luks2JSON{
		Digests: map[string]luks2Digest{
			"0": {Type: "pbkdf2", Hash: "md5", Salt: mustRand(32), Iterations: 1, Digest: mustRand(16)},
		},
	}
	if err := verifyLUKS2MasterKey(mustRand(16), cfg); err == nil {
		t.Fatal("expected error when digest hash is unsupported")
	}
}

// TestOpen_InvalidCipherAfterUnlock exercises the Open error path where the
// cipher setup fails after a successful LUKS2 unlock.
func TestOpen_InvalidCipherAfterUnlock(t *testing.T) {
	passphrase := []byte("test passphrase")
	volumeKey := mustRand(64)
	stripes := 8
	keySize := 64
	sectorSize := 512

	slotSalt := mustRand(32)
	slotIter := 100
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, keySize, sha256.New)

	afData := afSplit(t, volumeKey, stripes)
	enc, _ := newSectorCipher("aes-xts-plain64", slotKey, sectorSize)
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		enc.encryptSector(encAF[i*sectorSize:(i+1)*sectorSize], uint64(i))
	}

	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 100, 32, sha256.New)
	areaOffset := int64(65536)
	payloadOffset := int64(131072)
	hdrSize := uint64(32768)

	type m = map[string]interface{}
	cfg := m{
		"keyslots": m{"0": m{
			"type": "luks2", "key_size": keySize,
			"kdf": m{"type": "pbkdf2", "hash": "sha256", "iterations": slotIter, "salt": slotSalt},
			"af":  m{"type": "luks1", "stripes": stripes, "hash": "sha256"},
			"area": m{"type": "raw", "offset": fmt.Sprintf("%d", areaOffset),
				"size":       fmt.Sprintf("%d", keySize*stripes),
				"encryption": "aes-xts-plain64", "key_size": keySize},
		}},
		"segments": m{"0": m{
			"type": "crypt", "offset": fmt.Sprintf("%d", payloadOffset),
			"size": "dynamic", "encryption": "blowfish-cbc", // unsupported
			"sector_size": sectorSize, "iv_tweak": "0",
		}},
		"digests": m{"0": m{
			"type": "pbkdf2", "keyslots": []string{"0"}, "segments": []string{"0"},
			"hash": "sha256", "iterations": 100, "salt": mkSalt, "digest": mkDigest,
		}},
		"config": m{"json_size": "12288", "keyslots_size": "65536"},
	}
	js, _ := json.Marshal(cfg)

	totalSize := payloadOffset + 512
	img := make([]byte, totalSize)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], hdrSize)
	binary.BigEndian.PutUint64(img[16:24], 1)
	writePaddedStr(img[72:104], "sha256")
	copy(img[104:168], mustRand(64))
	writePaddedStr(img[168:208], "inv-cipher-uuid-000000000000000000000")
	copy(img[luks2BinHdrSize:], js)
	copy(img[areaOffset:], encAF)

	path := filepath.Join(t.TempDir(), "invcip.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, passphrase); err == nil {
		t.Fatal("expected error when segment cipher is unsupported")
	}
}

// TestLUKS2_JSONAreaReadFail exercises parseLUKS2JSON ReadAt failure.
func TestLUKS2_JSONAreaReadFail(t *testing.T) {
	// Binary superblock OK but file is too short for the JSON area.
	img := make([]byte, 4097) // just 1 byte past binary superblock
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 32768) // claims 32768-byte header
	writePaddedStr(img[72:104], "sha256")
	path := filepath.Join(t.TempDir(), "jsonshort.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error when JSON area read fails")
	}
}

// TestLUKS2_SlotReadFail exercises the ReadAt error in tryLUKS2Slot.
func TestLUKS2_SlotReadFail(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF:  luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:   luks2AF{Type: "luks1", Stripes: 4, Hash: "sha256"},
		Area: luks2KeyArea{Offset: "65536", Encryption: "aes-xts-plain64", KeySize: 32},
	}
	ro := &readOnlyAt{data: make([]byte, 100)} // no data at offset 65536
	if _, err := tryLUKS2Slot(ro, slot, []byte("pass")); err == nil {
		t.Fatal("expected error when key area ReadAt fails")
	}
}

// TestReadAt_DecryptError exercises the decryptSector error path inside readAt.
func TestReadAt_DecryptError(t *testing.T) {
	// Bad cbcKey (1 byte) → cbcDecryptSector fails after a successful ReadAt.
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	ro := &readOnlyAt{data: make([]byte, 512)}
	if _, err := sc.readAt(ro, make([]byte, 512), 0); err == nil {
		t.Fatal("expected error when decryptSector fails inside readAt")
	}
}

// TestWriteAt_DecryptError exercises the decryptSector error path inside writeAt.
func TestWriteAt_DecryptError(t *testing.T) {
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	w := &errWriterAt{data: make([]byte, 512)}
	if _, err := sc.writeAt(w, []byte("hello"), 0); err == nil {
		t.Fatal("expected error when decryptSector fails inside writeAt")
	}
}

// TestLUKS2_EmptyAFHash exercises the default AF hash path in tryLUKS2Slot.
func TestLUKS2_EmptyAFHash(t *testing.T) {
	// AF.Hash="" causes the hashName default to "sha256" branch to execute.
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 32,
		KDF:  luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:   luks2AF{Type: "luks1", Stripes: 1, Hash: ""}, // empty → defaults to sha256
		Area: luks2KeyArea{Offset: "0", Encryption: "aes-xts-plain64", KeySize: 32},
	}
	// Provide 32 bytes at offset 0 (afSize = 32*1 = 32 bytes).
	ro := &readOnlyAt{data: make([]byte, 512)}
	// tryLUKS2Slot should reach the hashName default branch and complete.
	_, _ = tryLUKS2Slot(ro, slot, []byte("pass"))
}

// TestDeriveKeyLUKS2_ZeroAreaKeySize exercises the keyLen fallback in deriveKeyLUKS2.
func TestDeriveKeyLUKS2_ZeroAreaKeySize(t *testing.T) {
	slot := &luks2Keyslot{
		Type:    "luks2",
		KeySize: 32, // fallback key length
		KDF:     luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		Area:    luks2KeyArea{KeySize: 0}, // triggers keyLen = slot.KeySize
	}
	key, err := deriveKeyLUKS2(slot, []byte("pass"))
	if err != nil {
		t.Fatalf("deriveKeyLUKS2 with zero area key size: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

// TestLUKS1_ZeroStripes exercises the afMerge error path in tryLUKS1Slot.
func TestLUKS1_ZeroStripes(t *testing.T) {
	img := make([]byte, 8192)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	writePaddedStr(img[8:40], "aes")
	writePaddedStr(img[40:72], "xts-plain64")
	writePaddedStr(img[72:104], "sha256")
	binary.BigEndian.PutUint32(img[104:108], 4096) // payloadOffset
	binary.BigEndian.PutUint32(img[108:112], 32)   // keyBytes
	// mk digest (20 bytes) and salt (32 bytes) and iterations
	binary.BigEndian.PutUint32(img[164:168], 100)
	// key slot 0: active, iterations=100, kmOffset=8, stripes=0
	base := 208
	binary.BigEndian.PutUint32(img[base:base+4], luks1KeySlotActive)
	binary.BigEndian.PutUint32(img[base+4:base+8], 100) // iterations
	binary.BigEndian.PutUint32(img[base+40:base+44], 8) // kmOffset
	binary.BigEndian.PutUint32(img[base+44:base+48], 0) // stripes = 0 → afMerge will fail
	path := filepath.Join(t.TempDir(), "zerostripes.luks1")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	// Should fail (no slot matches: stripes=0 causes afMerge error → slot skipped).
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for zero stripes in LUKS1 slot")
	}
}

// TestLUKS2_SlotBadAreaCipherViaOpen exercises the `if err != nil { continue }`
// branch in unlockLUKS2 when tryLUKS2Slot fails for a slot with an unsupported
// area cipher.
func TestLUKS2_SlotBadAreaCipherViaOpen(t *testing.T) {
	// Build a LUKS2 image where the key slot uses "blowfish-cbc" area encryption.
	// tryLUKS2Slot will fail → unlockLUKS2 continues → no matching slot.
	hdrSize := uint64(32768)
	areaOffset := int64(65536)
	payloadOffset := int64(131072)
	slotSalt := mustRand(32)

	type m = map[string]interface{}
	cfg := m{
		"keyslots": m{"0": m{
			"type": "luks2", "key_size": 32,
			"kdf": m{"type": "pbkdf2", "hash": "sha256", "iterations": 1, "salt": slotSalt},
			"af":  m{"type": "luks1", "stripes": 4, "hash": "sha256"},
			"area": m{"type": "raw", "offset": fmt.Sprintf("%d", areaOffset),
				"size": "128", "encryption": "blowfish-cbc", "key_size": 32},
		}},
		"segments": m{"0": m{
			"type": "crypt", "offset": fmt.Sprintf("%d", payloadOffset),
			"size": "dynamic", "encryption": "aes-xts-plain64",
			"sector_size": 512, "iv_tweak": "0",
		}},
		"digests": m{"0": m{
			"type": "pbkdf2", "hash": "sha256", "iterations": 1,
			"salt": mustRand(32), "digest": mustRand(32),
			"keyslots": []string{"0"}, "segments": []string{"0"},
		}},
		"config": m{"json_size": "12288", "keyslots_size": "65536"},
	}
	js, _ := json.Marshal(cfg)

	totalSize := payloadOffset + 512
	img := make([]byte, totalSize)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], hdrSize)
	binary.BigEndian.PutUint64(img[16:24], 1)
	writePaddedStr(img[72:104], "sha256")
	copy(img[104:168], mustRand(64))
	writePaddedStr(img[168:208], "badarea-uuid-00000000000000000000000")
	copy(img[luks2BinHdrSize:], js)

	path := filepath.Join(t.TempDir(), "badarea.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error when all slots fail in unlockLUKS2")
	}
}

// TestDecryptRaw_TinyPartialSectorError covers the error path in decryptRaw
// when the first (and only, sub-sector) block fails to decrypt.
func TestDecryptRaw_TinyPartialSectorError(t *testing.T) {
	// 1-byte cbcKey is invalid for AES; with < 512 bytes data the partial-sector
	// path is triggered immediately on sector 0.
	sc := &sectorCipher{mode: "cbc-essiv:sha256", sectorSize: 512, cbcKey: []byte{1}}
	sc.ivKey, _ = aes.NewCipher(make([]byte, 16))
	if _, err := sc.decryptRaw(make([]byte, 100)); err == nil {
		t.Fatal("expected error for bad cbcKey in decryptRaw tiny partial sector")
	}
}

// TestLUKS2_SlotDecryptRawFail covers the decryptRaw error path in tryLUKS2Slot.
// We use aes-cbc-essiv:sha256 area encryption with Area.KeySize=1 so that
// initCBCESSIV accepts the key (uses sha256 for ESSIV IV, no key validation)
// but the actual CBC decryption fails with the 1-byte cbcKey.
func TestLUKS2_SlotDecryptRawFail(t *testing.T) {
	slot := &luks2Keyslot{
		Type: "luks2", KeySize: 1,
		KDF: luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1, Salt: mustRand(32)},
		AF:  luks2AF{Type: "luks1", Stripes: 1, Hash: "sha256"},
		// 1-byte key: initCBCESSIV accepts it but cbcDecryptSector will fail.
		Area: luks2KeyArea{Offset: "0", Encryption: "aes-cbc-essiv:sha256", KeySize: 1},
	}
	// afSize = 1 * 1 = 1 byte → decryptRaw gets 1-byte buffer → partial sector
	// path → cbcDecryptSector fails → decryptRaw returns error.
	ro := &readOnlyAt{data: make([]byte, 512)}
	if _, err := tryLUKS2Slot(ro, slot, []byte("pass")); err == nil {
		t.Fatal("expected error when decryptRaw fails in tryLUKS2Slot")
	}
}

// -----------------------------------------------------------------------
// Tests for ripemd160 hash support, iv_tweak, and IV sector number fix
// -----------------------------------------------------------------------

// TestHashFactory_RIPEMD160 verifies that ripemd160 is a supported hash name.
func TestHashFactory_RIPEMD160(t *testing.T) {
	hf, err := hashFactory("ripemd160")
	if err != nil {
		t.Fatalf("hashFactory ripemd160: %v", err)
	}
	if hf().Size() != 20 {
		t.Errorf("ripemd160 digest size = %d, want 20", hf().Size())
	}
}

// TestLUKS1_RIPEMD160Image builds a LUKS1 image using ripemd160 as hash spec
// and verifies that Open can unlock it.
func TestLUKS1_RIPEMD160Image(t *testing.T) {
	passphrase := []byte("ripemd160 test passphrase")
	volumeKey := mustRand(32)
	stripes := 8
	sectorSize := 512

	hf, _ := hashFactory("ripemd160")
	slotSalt := mustRand(32)
	slotIter := 100
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, 32, hf)

	afData := afSplitWithHash(t, volumeKey, stripes, "ripemd160")
	enc, err := newSectorCipher("aes-xts-plain64", slotKey, sectorSize)
	if err != nil {
		t.Fatalf("cipher setup: %v", err)
	}
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		end := (i + 1) * sectorSize
		if end > len(encAF) {
			end = len(encAF)
		}
		if err := enc.encryptSector(encAF[i*sectorSize:end], uint64(i)); err != nil {
			t.Fatalf("encrypt AF sector %d: %v", i, err)
		}
	}

	mkSalt := mustRand(32)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, 100, 20, hf)
	kmOffset := uint32(8)
	payloadOffset := uint32(kmOffset + uint32(len(encAF)+511)/512 + 2)

	imgData := buildLUKS1Bytes(t, buildLUKS1Params{
		cipherName: "aes", cipherMode: "xts-plain64", hashSpec: "ripemd160",
		payloadOffset: payloadOffset, keyBytes: 32,
		mkDigest: mkDigest, mkSalt: mkSalt, mkIter: 100,
		slotSalt: slotSalt, slotIter: slotIter,
		kmOffset: kmOffset, stripes: uint32(stripes), encAF: encAF,
	})
	path := filepath.Join(t.TempDir(), "ripemd160.luks1")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open ripemd160 LUKS1: %v", err)
	}
	defer dev.Close()
	if !bytes.Equal(dev.h.volumeKey, volumeKey) {
		t.Error("ripemd160 LUKS1 volume key mismatch")
	}
}

// TestLUKS2_IVTweakRoundtrip builds a LUKS2 image with iv_tweak=8 and
// verifies that ReadAt/WriteAt roundtrip works correctly.
func TestLUKS2_IVTweakRoundtrip(t *testing.T) {
	passphrase := []byte("ivtweak passphrase")
	volumeKey := mustRand(64)
	stripes := 4
	keySize := 64
	sectorSize := 512

	slotSalt := mustRand(32)
	slotIter := 100
	slotKey := pbkdf2.Key(passphrase, slotSalt, slotIter, keySize, sha256.New)

	afData := afSplit(t, volumeKey, stripes)
	areaEnc, _ := newSectorCipher("aes-xts-plain64", slotKey, sectorSize)
	encAF := make([]byte, len(afData))
	copy(encAF, afData)
	for i := 0; i*sectorSize < len(encAF); i++ {
		end := min512(i+1, len(encAF), sectorSize)
		if err := areaEnc.encryptSector(encAF[i*sectorSize:end], uint64(i)); err != nil {
			t.Fatalf("encrypt af: %v", err)
		}
	}

	mkSalt := mustRand(32)
	mkIter := 100
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, mkIter, 32, sha256.New)
	areaOffset := int64(65536)
	payloadOffset := int64(131072)
	hdrSize := uint64(32768)

	type m = map[string]interface{}
	cfg := m{
		"keyslots": m{"0": m{
			"type": "luks2", "key_size": keySize,
			"kdf": m{"type": "pbkdf2", "hash": "sha256", "iterations": slotIter, "salt": slotSalt},
			"af":  m{"type": "luks1", "stripes": stripes, "hash": "sha256"},
			"area": m{"type": "raw", "offset": fmt.Sprintf("%d", areaOffset),
				"size":       fmt.Sprintf("%d", keySize*stripes),
				"encryption": "aes-xts-plain64", "key_size": keySize},
		}},
		"segments": m{"0": m{
			"type": "crypt", "offset": fmt.Sprintf("%d", payloadOffset),
			"size": "dynamic", "encryption": "aes-xts-plain64",
			"sector_size": sectorSize, "iv_tweak": "8", // non-zero tweak
		}},
		"digests": m{"0": m{
			"type": "pbkdf2", "keyslots": []string{"0"}, "segments": []string{"0"},
			"hash": "sha256", "iterations": mkIter, "salt": mkSalt, "digest": mkDigest,
		}},
		"config": m{"json_size": "12288", "keyslots_size": "65536"},
	}
	js, _ := json.Marshal(cfg)

	totalSize := payloadOffset + 512
	img := make([]byte, totalSize)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], hdrSize)
	binary.BigEndian.PutUint64(img[16:24], 1)
	writePaddedStr(img[72:104], "sha256")
	copy(img[104:168], mustRand(64))
	writePaddedStr(img[168:208], "ivtweak-uuid-test-00000000000000000000")
	copy(img[luks2BinHdrSize:], js)
	copy(img[areaOffset:], encAF)

	path := filepath.Join(t.TempDir(), "ivtweak.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open iv_tweak=8 LUKS2: %v", err)
	}
	defer dev.Close()
	if dev.h.ivTweak != 8 {
		t.Errorf("ivTweak = %d, want 8", dev.h.ivTweak)
	}
	want := []byte("iv_tweak roundtrip test data!")
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := dev.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadAt got %q, want %q", got, want)
	}
}

// TestLUKS2_BadIVTweak exercises the parseIVTweak error path in unlockLUKS2.
func TestLUKS2_BadIVTweak(t *testing.T) {
	img := make([]byte, 32768)
	copy(img[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 32768)
	writePaddedStr(img[72:104], "sha256")
	js, _ := json.Marshal(map[string]interface{}{
		"keyslots": map[string]interface{}{},
		"segments": map[string]interface{}{
			"0": map[string]interface{}{
				"type": "crypt", "offset": "131072", "size": "dynamic",
				"encryption": "aes-xts-plain64", "sector_size": 512,
				"iv_tweak": "notanumber",
			},
		},
		"digests": map[string]interface{}{},
		"config":  map[string]interface{}{"json_size": "12288"},
	})
	copy(img[luks2BinHdrSize:], js)
	path := filepath.Join(t.TempDir(), "badtweak.luks2")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, []byte("pass")); err == nil {
		t.Fatal("expected error for invalid iv_tweak value")
	}
}

// TestParseIVTweak tests the parseIVTweak helper directly.
func TestParseIVTweak(t *testing.T) {
	if v, err := parseIVTweak(""); err != nil || v != 0 {
		t.Errorf("parseIVTweak empty: got %d %v, want 0 nil", v, err)
	}
	if v, err := parseIVTweak("0"); err != nil || v != 0 {
		t.Errorf("parseIVTweak 0: got %d %v", v, err)
	}
	if v, err := parseIVTweak("16"); err != nil || v != 16 {
		t.Errorf("parseIVTweak 16: got %d %v", v, err)
	}
	if _, err := parseIVTweak("bad"); err == nil {
		t.Fatal("parseIVTweak bad: expected error")
	}
}
