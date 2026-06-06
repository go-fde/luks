package luks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// failWriteRW is a blockRW that returns an error after failAfter successful
// WriteAt calls, used to test error paths in Format and FormatOn.
type failWriteRW struct {
	failAfter int
	callCount int
}

func (r *failWriteRW) ReadAt(p []byte, off int64) (int, error) { return len(p), nil }
func (r *failWriteRW) WriteAt(p []byte, off int64) (int, error) {
	r.callCount++
	if r.callCount > r.failAfter {
		return 0, errors.New("mock write error")
	}
	return len(p), nil
}
func (r *failWriteRW) Close() error { return nil }

func TestFormat_NotExist(t *testing.T) {
	_, err := Format(filepath.Join(t.TempDir(), "nofile.luks"), []byte("pass"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

// TestFormat_Success creates a LUKS1 container, writes payload data, closes,
// reopens with Open, and verifies the round-trip decryption.
func TestFormat_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("format test passphrase")
	dev, err := Format(path, passphrase)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	want := make([]byte, luks1SectorSize)
	copy(want, []byte("hello from luks format"))
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	dev2, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open after Format: %v", err)
	}
	defer dev2.Close()

	got := make([]byte, luks1SectorSize)
	if _, err := dev2.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got[:20], want[:20])
	}
}

// TestFormatOn_Success performs the same round-trip as TestFormat_Success but
// via FormatOn, passing an *os.File directly.
func TestFormatOn_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("formaton test")
	dev, err := FormatOn(f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("FormatOn: %v", err)
	}

	want := make([]byte, luks1SectorSize)
	copy(want, []byte("formaton payload"))
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	dev2, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open after FormatOn: %v", err)
	}
	defer dev2.Close()

	got := make([]byte, luks1SectorSize)
	if _, err := dev2.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestFormatOn_HeaderWriteError(t *testing.T) {
	_, err := FormatOn(&failWriteRW{failAfter: 0}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when header write fails")
	}
}

func TestFormatOn_KMWriteError(t *testing.T) {
	_, err := FormatOn(&failWriteRW{failAfter: 1}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when key-material write fails")
	}
}
