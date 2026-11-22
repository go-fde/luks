package luks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// loadNoPanic runs loadLUKS2Copy on img and turns a crash into an error, so a
// removed guard fails an assertion here instead of panicking the suite.
func loadNoPanic(img []byte, size uint64, magic string) (c *luks2Copy, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PANIC: %v", r)
		}
	}()
	return loadLUKS2Copy(bytes.NewReader(img), 0, size, magic)
}

// TestLoadLUKS2CopyRefusals asserts, one by one, why loadLUKS2Copy refuses a
// copy. readLUKS2Header falls back to the other copy on any of them, so through
// OpenFrom they hide behind each other; here each is judged by its own message.
func TestLoadLUKS2CopyRefusals(t *testing.T) {
	base, _, _ := buildLUKS2Image(t)
	hdrSize := binary.BigEndian.Uint64(base[8:16])

	statedSize := func(size uint64) []byte {
		b := make([]byte, 16)
		copy(b, luks2MagicPrimary)
		binary.BigEndian.PutUint64(b[8:], size)
		return b
	}
	withAlg := func(alg string) []byte {
		img := bytes.Clone(base)
		clear(img[72:104])
		copy(img[72:], alg)
		if _, err := hashFactory(alg); err == nil {
			sealLUKS2(img) // an algorithm we cannot compute cannot be sealed
		}
		return img
	}
	badJSON := bytes.Clone(base)
	copy(badJSON[luks2BinHdrSize:], "{not json")
	sealLUKS2(badJSON)

	for _, tc := range []struct {
		name  string
		img   []byte
		size  uint64
		magic string
		want  string
	}{
		{"empty device", nil, 0, luks2MagicPrimary, "read binary hdr"},
		{"stated size equal to the binary header", statedSize(luks2BinHdrSize), 0, luks2MagicPrimary, "implausible"},
		{"stated size under the binary header", statedSize(luks2BinHdrSize - 1), 0, luks2MagicPrimary, "implausible"},
		{"stated JSON area over 4 MiB", statedSize(luks2BinHdrSize + 1<<22 + 1), 0, luks2MagicPrimary, "implausible"},
		{"stated size of 2^62", statedSize(1 << 62), 0, luks2MagicPrimary, "implausible"},
		{"stated JSON area of exactly 4 MiB is plausible", statedSize(luks2BinHdrSize + 1<<22), 0, luks2MagicPrimary, "read header"},
		{"header shorter than its stated size", base[:hdrSize-1], 0, luks2MagicPrimary, "read header"},
		{"wrong magic", base, hdrSize, luks2MagicSecondary, "bad header magic"},
		{"stated size differs from the expected one", base, hdrSize / 2, luks2MagicPrimary, "states hdr_size"},
		{"no checksum algorithm", withAlg(""), 0, luks2MagicPrimary, "no checksum algorithm"},
		{"unknown checksum algorithm", withAlg("nonsense"), 0, luks2MagicPrimary, "checksum algorithm"},
		{"checksum mismatch", func() []byte { b := bytes.Clone(base); b[104] ^= 1; return b }(), 0, luks2MagicPrimary, "checksum mismatch"},
		{"JSON that does not parse", badJSON, 0, luks2MagicPrimary, "parse JSON"},
	} {
		c, err := loadNoPanic(tc.img, tc.size, tc.magic)
		if err == nil {
			t.Errorf("%s: accepted (%v)", tc.name, c != nil)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}

	// And the good copy loads, with the primary's own size as well as given.
	for _, size := range []uint64{0, hdrSize} {
		if _, err := loadLUKS2Copy(bytes.NewReader(base), 0, size, luks2MagicPrimary); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
	}
}
