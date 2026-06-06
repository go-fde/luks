package luks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRandBytes_PanicsOnRngFailure injects a failing rand.Read into
// randBytes to drive the panic branch — production code never hits
// this path, but the safeguard is still worth pinning.
func TestRandBytes_PanicsOnRngFailure(t *testing.T) {
	prev := randReadFn
	randReadFn = func(b []byte) (int, error) {
		return 0, errors.New("synthetic rng failure")
	}
	defer func() { randReadFn = prev }()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = randBytes(8)
}

// TestNewSectorCipher_UnknownAlgo covers the unknown-cipher error
// branch in newSectorCipher.
func TestNewSectorCipher_UnknownAlgo(t *testing.T) {
	if _, err := newSectorCipher("rot13-pony", make([]byte, 32), luks1SectorSize); err == nil {
		t.Fatal("expected error for unknown cipher")
	}
}

// TestAfSplitKey_UnknownHash drives the inner-loop hashDiffuse
// error branch via an unsupported hash name.
func TestAfSplitKey_UnknownHash(t *testing.T) {
	if _, err := afSplitKey(make([]byte, 32), 100, "no-such-hash"); err == nil {
		t.Fatal("expected error for unknown hash")
	}
}

// TestFormat_FormatOnError covers the Format → FormatOn error
// forwarding path: open a file that's writable per OpenFile but
// where the rw refuses writes (simulated via a read-only-after-
// open semantic). We approximate that by giving Format a path
// inside a directory the user can't write to.
func TestFormat_FormatOnError(t *testing.T) {
	// Pre-create a file we can OpenFile() RW, but then point Format
	// at a path whose parent dir has -w on. On Unix we can chmod the
	// directory; on platforms without POSIX modes this test skips.
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.luks")
	if err := os.WriteFile(path, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod the file read-only so the WriteAt inside formatDevice
	// fails.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o600) //nolint:errcheck
	if _, err := Format(path, []byte("pp")); err == nil {
		t.Fatal("expected Format to fail on read-only file")
	}
}

// TestOpenFrom_LUKS1 covers the OpenFrom entry point — it's a thin
// wrapper around openDevice that the Open test doesn't exercise.
func TestOpenFrom_LUKS1(t *testing.T) {
	imgData, _, passphrase := buildLUKS1Image(t)
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, imgData, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(f, passphrase)
	if err != nil {
		t.Fatalf("OpenFrom: %v", err)
	}
	defer dev.Close()
}

// TestEncryptRaw_PartialLastSector covers the partial-sector branch
// inside sectorCipher.encryptRaw (used when the AF-split payload
// isn't an integer multiple of the sector size).
func TestEncryptRaw_PartialLastSector(t *testing.T) {
	sc, err := newSectorCipher("aes-xts-plain64", make([]byte, 64), luks1SectorSize)
	if err != nil {
		t.Fatalf("newSectorCipher: %v", err)
	}
	pt := make([]byte, luks1SectorSize+10) // one full + 10-byte partial
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, err := sc.encryptRaw(pt)
	if err != nil {
		t.Fatalf("encryptRaw: %v", err)
	}
	if len(ct) != len(pt) {
		t.Errorf("ciphertext len: got %d, want %d", len(ct), len(pt))
	}
}
