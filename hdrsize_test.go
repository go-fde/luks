package luks

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gunzipFixture returns the bytes of a committed gzipped testdata image.
func gunzipFixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestLUKS2JSONAreaIsHdrSizeMinus4096 grows the JSON of a REAL cryptsetup
// header past 4096 bytes. hdr_size is the size of one header (LUKS2 on-disk
// format section 2.1), so the JSON area is hdr_size - 4096; reading half of it
// refused every genuine header whose JSON exceeded 4096 bytes.
func TestLUKS2JSONAreaIsHdrSizeMinus4096(t *testing.T) {
	img := gunzipFixture(t, "cryptsetup_luks2_pbkdf2.img.gz")
	hdrSize := binary.BigEndian.Uint64(img[8:16])
	if string(img[hdrSize:hdrSize+6]) != "SKUL\xba\xbe" {
		t.Fatalf("the fixture's secondary header is not at hdr_size %d", hdrSize)
	}
	area := img[luks2BinHdrSize:hdrSize]
	n := bytes.IndexByte(area, 0)
	var cfg map[string]any
	if err := json.Unmarshal(area[:n], &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["tokens"] = map[string]any{"0": map[string]any{
		"type": "test", "keyslots": []string{}, "note": strings.Repeat("x", 4096),
	}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) <= 4096 || len(b) >= len(area) {
		t.Fatalf("JSON of %d bytes does not exercise the area of %d", len(b), len(area))
	}
	clear(area)
	copy(area, b)
	dev, err := OpenFrom(&memRW{b: img}, []byte(interopPassphrase))
	if err != nil {
		t.Fatalf("a header whose %d bytes of JSON fit its %d-byte area is refused: %v", len(b), len(area), err)
	}
	dev.Close()
}

// TestInterop_CryptsetupLargeJSON has the real cryptsetup write a token that
// pushes the JSON past 4096 bytes (cryptsetup token import), then opens the
// result. Rootless: it formats a file. LUKS_REQUIRE_CRYPTSETUP=1 makes a
// missing tool a failure.
func TestInterop_CryptsetupLargeJSON(t *testing.T) {
	cs, err := exec.LookPath("cryptsetup")
	if err != nil {
		if os.Getenv("LUKS_REQUIRE_CRYPTSETUP") == "1" {
			t.Fatal("cryptsetup is required but not installed")
		}
		t.Skip("cryptsetup not installed")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "big.img")
	if err := os.WriteFile(img, make([]byte, 32<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(cs, args...)
		cmd.Stdin = bytes.NewReader([]byte(interopPassphrase))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cryptsetup %v: %v\n%s", args, err, out)
		}
	}
	run("luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", img)
	tok := filepath.Join(dir, "tok.json")
	tj, _ := json.Marshal(map[string]any{
		"type": "gofde_test", "keyslots": []string{}, "note": strings.Repeat("x", 6000),
	})
	if err := os.WriteFile(tok, tj, 0o600); err != nil {
		t.Fatal(err)
	}
	run("token", "import", "--json-file", tok, "--token-id", "0", img)
	raw, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.IndexByte(raw[luks2BinHdrSize:], 0); n <= 4096 {
		t.Fatalf("cryptsetup wrote %d bytes of JSON, want more than 4096", n)
	}
	dev, err := Open(img, []byte(interopPassphrase))
	if err != nil {
		t.Fatalf("Open of a cryptsetup header with >4096 bytes of JSON: %v", err)
	}
	dev.Close()
}

// TestLUKS2HdrSizeBounds pins both edges of the JSON area: hdr_size must leave
// a non-empty area and at most 4 MiB of it (cryptsetup's largest header is
// 4 MiB).
func TestLUKS2HdrSizeBounds(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	for _, tc := range []struct {
		name string
		size uint64
		ok   bool
	}{
		{"no JSON area", 4096, false},
		{"below the binary header", 100, false},
		{"one byte of JSON area", 4097, false},
		{"largest area", 4096 + 1<<22, true},
		{"just over", 4096 + 1<<22 + 1, false},
		{"absurd", 1 << 63, false},
		{"default", 16384, true},
	} {
		img := bytes.Clone(base)
		binary.BigEndian.PutUint64(img[8:16], tc.size)
		dev, err := OpenFrom(&memRW{b: img}, pass)
		if tc.ok != (err == nil) {
			t.Errorf("%s (hdr_size %d): err=%v", tc.name, tc.size, err)
		}
		if err == nil {
			dev.Close()
		}
	}
}
