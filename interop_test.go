package luks

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// interopPassphrase is the passphrase used to create the committed
// cryptsetup-generated LUKS2 fixtures and the live-cryptsetup containers.
const interopPassphrase = "hunter2pass"

// interopMarker is the plaintext written by cryptsetup into the mapped device
// at payload offset 0 when the fixtures were generated. go-fde/luks must be
// able to read it back byte-for-byte after unlocking the container itself.
const interopMarkerPrefix = "GOFDE-INTEROP-"

// decompressFixture writes a gzipped fixture out to a temp file and returns the
// path. The fixture is a real cryptsetup-created LUKS2 container (sparse, with
// the bulk of the unused payload zeroed so it compresses well).
func decompressFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	out := filepath.Join(t.TempDir(), "container.img")
	w, err := os.Create(out)
	if err != nil {
		t.Fatalf("create temp container: %v", err)
	}
	if _, err := io.Copy(w, gr); err != nil {
		w.Close()
		t.Fatalf("decompress fixture: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close temp container: %v", err)
	}
	return out
}

// openCryptsetupFixture opens a committed cryptsetup-created LUKS2 container
// with go-fde/luks and asserts the plaintext marker cryptsetup wrote is
// readable. This is a pure-Go regression that runs in CI without cryptsetup:
// it pins our header/keyslot parse, the anti-forensic (4000-stripe sha256)
// merge, the KDF and the AES-XTS volume decryption against bytes that the real
// cryptsetup tool produced.
func openCryptsetupFixture(t *testing.T, fixture, wantMarker string) {
	t.Helper()
	path := decompressFixture(t, fixture)
	dev, err := Open(path, []byte(interopPassphrase))
	if err != nil {
		t.Fatalf("Open cryptsetup fixture %s: %v", fixture, err)
	}
	defer dev.Close()
	buf := make([]byte, len(wantMarker))
	if _, err := dev.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt payload: %v", err)
	}
	if string(buf) != wantMarker {
		t.Fatalf("payload marker mismatch:\n got %q\nwant %q", buf, wantMarker)
	}
}

// TestInterop_CryptsetupDefault_LUKS2 regresses opening a stock
// cryptsetup-default LUKS2 container (argon2id KDF, aes-xts-plain64, 4000 AF
// stripes, sha256, 4096-byte sectors).
func TestInterop_CryptsetupDefault_LUKS2(t *testing.T) {
	openCryptsetupFixture(t,
		"cryptsetup_luks2_default.img.gz",
		interopMarkerPrefix+"def-PAYLOAD-0123456789ABCDEF")
}

// TestInterop_CryptsetupPBKDF2_LUKS2 regresses opening a cryptsetup LUKS2
// container created with `--pbkdf pbkdf2` (pbkdf2-sha256 keyslot).
func TestInterop_CryptsetupPBKDF2_LUKS2(t *testing.T) {
	openCryptsetupFixture(t,
		"cryptsetup_luks2_pbkdf2.img.gz",
		interopMarkerPrefix+"pb-PAYLOAD-0123456789ABCDEF")
}

// TestInterop_LiveCryptsetup exercises the full loop against the real
// cryptsetup binary when it (and root) are available: format a LUKS2 container,
// write a known marker through cryptsetup's dm-crypt mapping, then unlock it
// with go-fde/luks and confirm the marker reads back. Skips cleanly when
// cryptsetup, root, or /dev/mapper are unavailable (e.g. macOS/CI sandboxes).
func TestInterop_LiveCryptsetup(t *testing.T) {
	cs, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Skip("cryptsetup not installed; skipping live interop")
	}
	if os.Geteuid() != 0 {
		t.Skip("live cryptsetup interop requires root (dm-crypt); skipping")
	}

	for _, tc := range []struct {
		name      string
		pbkdfArgs []string
	}{
		{"argon2id-default", nil},
		{"pbkdf2", []string{"--pbkdf", "pbkdf2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			img := filepath.Join(dir, "live.img")
			if err := os.WriteFile(img, make([]byte, 32<<20), 0o600); err != nil {
				t.Fatal(err)
			}
			mapName := "gofde_interop_" + tc.name

			format := append([]string{"luksFormat", "--type", "luks2", "--batch-mode"}, tc.pbkdfArgs...)
			format = append(format, img)
			run := func(args ...string) {
				cmd := exec.Command(cs, args...)
				cmd.Stdin = bytes.NewReader([]byte(interopPassphrase))
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("cryptsetup %v: %v\n%s", args, err, out)
				}
			}
			run(format...)
			run("open", "--type", "luks2", img, mapName)
			defer func() {
				_ = exec.Command(cs, "close", mapName).Run()
			}()

			marker := []byte("LIVE-" + tc.name + "-MARKER")
			mapped := filepath.Join("/dev/mapper", mapName)
			mf, err := os.OpenFile(mapped, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open mapped device: %v", err)
			}
			if _, err := mf.WriteAt(marker, 0); err != nil {
				mf.Close()
				t.Fatalf("write marker: %v", err)
			}
			mf.Close()
			_ = exec.Command(cs, "close", mapName).Run()

			dev, err := Open(img, []byte(interopPassphrase))
			if err != nil {
				t.Fatalf("go-fde Open of live cryptsetup container: %v", err)
			}
			defer dev.Close()
			got := make([]byte, len(marker))
			if _, err := dev.ReadAt(got, 0); err != nil {
				t.Fatalf("ReadAt: %v", err)
			}
			if !bytes.Equal(got, marker) {
				t.Fatalf("live marker mismatch: got %q want %q", got, marker)
			}
		})
	}
}
