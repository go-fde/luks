package luks

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
)

// growDev is a growable in-memory device: reads past the end are short and
// return io.EOF, writes past the end extend it.
type growDev struct{ data []byte }

func (m *growDev) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *growDev) WriteAt(p []byte, off int64) (int, error) {
	if end := off + int64(len(p)); end > int64(len(m.data)) {
		m.data = append(m.data, make([]byte, end-int64(len(m.data)))...)
	}
	return copy(m.data[off:], p), nil
}

// failAfter fails every read that reaches past limit with a non-EOF error.
type failAfter struct {
	growDev
	limit int64
}

func (f *failAfter) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.limit {
		return 0, errors.New("device error")
	}
	return f.growDev.ReadAt(p, off)
}

var sectorCases = []struct {
	cipher string
	keyLen int
}{
	{"aes-xts-plain64", 32},
	{"aes-xts-plain64", 64},
	{"aes-cbc-essiv:sha256", 16},
	{"aes-cbc-essiv:sha256", 32},
}

// TestSectorsMatchModel writes and reads at random offsets and lengths
// (partial first and last sectors, several sectors, zero length) and checks
// the device against a plaintext model, and its ciphertext against the
// sector-by-sector encryption the batched paths replaced.
func TestSectorsMatchModel(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, c := range sectorCases {
		for _, ss := range []int{512, 4096} {
			key := make([]byte, c.keyLen)
			rng.Read(key)
			sc, err := newSectorCipher(c.cipher, key, ss)
			if err != nil {
				t.Fatal(err)
			}
			const base, tweak, size = 8192, 5, 64 << 10
			sc.fileBase, sc.ivTweak = base, tweak
			dev := &growDev{data: make([]byte, base)}
			model := make([]byte, size)
			// The device starts as the encryption of zeros.
			if _, err := sc.writeAt(dev, model, base); err != nil {
				t.Fatal(err)
			}
			for i := range 200 {
				off := rng.Intn(size)
				n := rng.Intn(min(3*ss, size-off) + 1)
				p := make([]byte, n)
				rng.Read(p)
				if w, err := sc.writeAt(dev, p, base+int64(off)); err != nil || w != n {
					t.Fatalf("%s/%d: write %d at %d: %d %v", c.cipher, ss, n, off, w, err)
				}
				copy(model[off:], p)

				roff := rng.Intn(size)
				rn := rng.Intn(min(3*ss, size-roff) + 1)
				got := make([]byte, rn)
				if r, err := sc.readAt(dev, got, base+int64(roff)); err != nil || r != rn {
					t.Fatalf("%s/%d: read %d at %d: %d %v", c.cipher, ss, rn, roff, r, err)
				}
				if !bytes.Equal(got, model[roff:roff+rn]) {
					t.Fatalf("%s/%d: round %d: read at %d differs from the model", c.cipher, ss, i, roff)
				}
			}
			// The ciphertext is what one sector at a time produces.
			for s := 0; s < size; s += ss {
				sec := append([]byte(nil), dev.data[base+s:base+s+ss]...)
				if err := sc.decryptSector(sec, uint64(s/ss)+tweak); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sec, model[s:s+ss]) {
					t.Fatalf("%s/%d: sector %d differs from per-sector decryption", c.cipher, ss, s/ss)
				}
			}
		}
	}
}

func TestReadAtShortRead(t *testing.T) {
	sc, _ := newSectorCipher("aes-xts-plain64", make([]byte, 32), 512)
	dev := &growDev{}
	plain := bytes.Repeat([]byte{7}, 1024)
	if _, err := sc.writeAt(dev, plain, 0); err != nil {
		t.Fatal(err)
	}
	// 2 sectors exist; ask for 3 from the middle of the first.
	p := make([]byte, 1100)
	n, err := sc.readAt(dev, p, 100)
	if !errors.Is(err, io.EOF) || n != 924 || !bytes.Equal(p[:n], plain[100:]) {
		t.Fatalf("short read: %d %v", n, err)
	}
	// nothing at all past the end
	if n, err := sc.readAt(dev, p, 4096); err == nil || n != 0 {
		t.Fatalf("read past the end: %d %v", n, err)
	}
	if n, err := sc.readAt(dev, nil, 0); err != nil || n != 0 {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if n, err := sc.writeAt(dev, nil, 0); err != nil || n != 0 {
		t.Fatalf("empty write: %d %v", n, err)
	}
}

// TestWriteAtLastSectorReadError: the last partial sector's read fails
// with a device error (not EOF) and nothing is written.
func TestWriteAtLastSectorReadError(t *testing.T) {
	sc, _ := newSectorCipher("aes-cbc-essiv:sha256", make([]byte, 16), 512)
	dev := &failAfter{growDev: growDev{data: make([]byte, 2048)}, limit: 1024}
	// starts aligned at 0, ends inside sector 2: only the last sector is read
	if _, err := sc.writeAt(dev, make([]byte, 1100), 0); err == nil {
		t.Fatal("write went on after the last sector could not be read")
	}
	if !bytes.Equal(dev.data, make([]byte, 2048)) {
		t.Fatal("the device was written")
	}
}
