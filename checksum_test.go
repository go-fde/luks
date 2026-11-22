package luks

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// withSecondary returns img with a second header copy at hdr_size: the
// primary's bytes under the SKUL magic, hdr_size and seqid as given, a salt
// that tells the two apart, sealed.
func withSecondary(t *testing.T, img []byte, seq uint64) []byte {
	t.Helper()
	hdrSize := int(binary.BigEndian.Uint64(img[8:16]))
	out := bytes.Clone(img)
	if len(out) < 2*hdrSize {
		out = append(out, make([]byte, 2*hdrSize-len(out))...)
	}
	copy(out[hdrSize:2*hdrSize], out[:hdrSize])
	copy(out[hdrSize:], luks2MagicSecondary)
	binary.BigEndian.PutUint64(out[hdrSize+16:], seq)
	copy(out[hdrSize+104:hdrSize+168], bytes.Repeat([]byte{0x5E}, 64)) // the secondary's salt
	sealLUKS2At(out, hdrSize)
	return out
}

// TestLUKS2ChecksumIsVerified is the Fable reproducer: flipping the first
// byte of the salt (covered by the checksum) used to open without complaint.
// A device with no second copy has nothing to recover from, so it is refused.
func TestLUKS2ChecksumIsVerified(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	img[104] ^= 0xFF
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err == nil {
		dev.Close()
		t.Fatal("a LUKS2 header whose checksum no longer matches is opened without complaint")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("err = %v, want a checksum mismatch", err)
	}
}

// TestLUKS2ChecksumCoversTheWholeHeader flips one byte in each region the
// checksum covers: binary header, JSON area, the unused tail of the area, and
// the last byte of hdr_size. Each must be refused; the byte just past hdr_size
// is not covered.
func TestLUKS2ChecksumCoversTheWholeHeader(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	hdrSize := int(binary.BigEndian.Uint64(base[8:16]))
	for _, tc := range []struct {
		name    string
		off     int
		refused bool
	}{
		{"version", 7, true},
		{"seqid", 23, true},
		{"label", 30, true},
		{"uuid", 170, true},
		{"just before csum", luks2CsumOff - 1, true},
		{"csum first byte", luks2CsumOff, true},
		{"csum bytes past the sha256 digest", luks2CsumOff + luks2CsumLen - 1, false},
		{"just after csum", luks2CsumOff + luks2CsumLen, true},
		{"binary header padding", 2000, true},
		{"JSON area start", luks2BinHdrSize + 3, true},
		{"JSON area tail", hdrSize - 2048, true},
		{"last byte of hdr_size", hdrSize - 1, true},
		{"first byte past hdr_size", hdrSize, false},
	} {
		img := bytes.Clone(base)
		img[tc.off] ^= 0x01
		dev, err := OpenFrom(&memRW{b: img}, pass)
		if tc.refused {
			if err == nil {
				dev.Close()
				t.Errorf("%s: a flipped byte inside the checksummed range was accepted", tc.name)
			} else if tc.off != 7 && !strings.Contains(err.Error(), "checksum mismatch") {
				t.Errorf("%s: err = %v, want a checksum mismatch", tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: a byte outside the checksummed range was refused: %v", tc.name, err)
		} else {
			dev.Close()
		}
	}
}

// TestLUKS2ChecksumAlgorithm: a header must name an algorithm we can compute.
func TestLUKS2ChecksumAlgorithm(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	for _, alg := range []string{"", "md5", "nonsense"} {
		img := bytes.Clone(base)
		clear(img[72:104])
		copy(img[72:], alg)
		if dev, err := OpenFrom(&memRW{b: img}, pass); err == nil {
			dev.Close()
			t.Errorf("csum_alg %q: opened", alg)
		}
	}
	// sha512 is computed too.
	img := bytes.Clone(base)
	clear(img[72:104])
	copy(img[72:], "sha512")
	sealLUKS2(img)
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err != nil {
		t.Fatalf("csum_alg sha512: %v", err)
	}
	dev.Close()
}

// TestLUKS2RecoversFromTheSecondaryHeader: the real cryptsetup fixture has both
// copies. Corrupting the primary (a salt byte, the hdr_size field, the magic)
// must still open, through the secondary; corrupting both is refused.
func TestLUKS2RecoversFromTheSecondaryHeader(t *testing.T) {
	base := gunzipFixture(t, "cryptsetup_luks2_pbkdf2.img.gz")
	hdrSize := int(binary.BigEndian.Uint64(base[8:16]))
	pass := []byte(interopPassphrase)

	// open judges the header selection only (the fixture's PBKDF2 slot costs
	// seconds to unlock); the salt case below unlocks for real.
	open := func(name string, img []byte, wantOpen bool) {
		t.Helper()
		_, err := readLUKS2Header(&memRW{b: img})
		if wantOpen != (err == nil) {
			t.Errorf("%s: header err = %v, want usable=%v", name, err, wantOpen)
		}
	}
	open("untouched", base, true)

	img := bytes.Clone(base)
	img[104] ^= 0xFF
	open("primary salt flipped", img, true)
	if dev, err := OpenFrom(&memRW{b: img}, pass); err != nil {
		t.Errorf("a device with a corrupted primary does not unlock through the secondary: %v", err)
	} else {
		dev.Close()
	}
	c, err := readLUKS2Header(&memRW{b: img})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.bin.salt[:], base[hdrSize+104:hdrSize+168]) || bytes.Equal(c.bin.salt[:], img[104:168]) {
		t.Error("the corrupted primary was used instead of the secondary")
	}

	img = bytes.Clone(base)
	binary.BigEndian.PutUint64(img[8:16], 2*uint64(hdrSize)) // plausible but wrong hdr_size
	open("primary hdr_size wrong", img, true)

	img = bytes.Clone(base)
	binary.BigEndian.PutUint64(img[8:16], 1<<24) // over the 4 MiB bound, small enough to allocate if it were not refused
	open("primary hdr_size absurd", img, true)

	img = bytes.Clone(base)
	img[104] ^= 0xFF
	img[hdrSize+104] ^= 0xFF
	open("both corrupted", img, false)

	img = bytes.Clone(base)
	img[104] ^= 0xFF
	copy(img[hdrSize:], luks2MagicPrimary) // the secondary carries the wrong magic
	open("secondary wrong magic", img, false)

	img = bytes.Clone(base)
	img[104] ^= 0xFF
	binary.BigEndian.PutUint64(img[hdrSize+8:], uint64(hdrSize)*2) // secondary states another hdr_size
	open("secondary hdr_size mismatch", img, false)
}

// TestLUKS2PicksTheHigherSeqid: with both copies valid, the higher seqid wins
// (a tie goes to the primary).
func TestLUKS2PicksTheHigherSeqid(t *testing.T) {
	base, _, pass := buildLUKS2Image(t) // primary seqid 1
	for _, tc := range []struct {
		name          string
		secondarySeq  uint64
		wantSecondary bool
	}{
		{"secondary newer", 2, true},
		{"secondary much newer", 1 << 40, true},
		{"tie", 1, false},
		{"secondary older", 0, false},
	} {
		img := withSecondary(t, base, tc.secondarySeq)
		c, err := readLUKS2Header(&memRW{b: img})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		isSecondary := bytes.Equal(c.bin.salt[:], bytes.Repeat([]byte{0x5E}, 64))
		if isSecondary != tc.wantSecondary {
			t.Errorf("%s: secondary chosen = %v, want %v", tc.name, isSecondary, tc.wantSecondary)
		}
		dev, err := OpenFrom(&memRW{b: img}, pass)
		if err != nil {
			t.Fatalf("%s: open: %v", tc.name, err)
		}
		dev.Close()
	}

	// A newer but corrupt secondary never wins over a valid primary.
	img := withSecondary(t, base, 9)
	hdrSize := int(binary.BigEndian.Uint64(img[8:16]))
	img[hdrSize+100] ^= 0x01
	c, err := readLUKS2Header(&memRW{b: img})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c.bin.salt[:], bytes.Repeat([]byte{0x5E}, 64)) {
		t.Error("a secondary with a bad checksum was chosen for its seqid")
	}
}
