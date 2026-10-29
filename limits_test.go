package luks

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// memRW is an in-memory block device.
type memRW struct{ b []byte }

func (m *memRW) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.b)) {
		return 0, errors.New("EOF")
	}
	return copy(p, m.b[off:]), nil
}
func (m *memRW) WriteAt(p []byte, off int64) (int, error) { return copy(m.b[off:], p), nil }
func (m *memRW) Close() error                             { return nil }

// patchLUKS2 rewrites the JSON area of a LUKS2 image built by
// buildLUKS2Image through edit.
func patchLUKS2(t *testing.T, img []byte, edit func(cfg map[string]any)) []byte {
	t.Helper()
	out := bytes.Clone(img)
	area := out[luks2BinHdrSize : 16384-luks2BinHdrSize+luks2BinHdrSize]
	n := bytes.IndexByte(area, 0)
	var cfg map[string]any
	if err := json.Unmarshal(area[:n], &cfg); err != nil {
		t.Fatal(err)
	}
	edit(cfg)
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clear(area)
	copy(area, b)
	return out
}

func slot0(cfg map[string]any) map[string]any {
	return cfg["keyslots"].(map[string]any)["0"].(map[string]any)
}

// openQuickly opens img and requires an ErrLimit within a second: a header
// that asks for too much is refused before the work, not after it.
func openQuickly(t *testing.T, name string, img []byte, pass []byte, lim Limits) {
	t.Helper()
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("%s: panic: %v", name, p)
		}
	}()
	_, err := OpenFromLimited(&memRW{b: img}, pass, lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("%s: %v, want ErrLimit", name, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%s: refused after %s", name, d)
	}
}

func TestLimitsLUKS2(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	argon := func(time, mem, cpus float64) func(map[string]any) {
		return func(cfg map[string]any) {
			slot0(cfg)["kdf"] = map[string]any{"type": "argon2id", "time": time, "memory": mem, "cpus": cpus, "salt": []byte("salt")}
		}
	}
	for name, edit := range map[string]func(map[string]any){
		"2^31 PBKDF2 iterations": func(cfg map[string]any) { slot0(cfg)["kdf"].(map[string]any)["iterations"] = 1 << 31 },
		"zero PBKDF2 iterations": func(cfg map[string]any) { slot0(cfg)["kdf"].(map[string]any)["iterations"] = 0 },
		"argon2 4 TiB":           argon(4, 1<<32-1, 1),
		"argon2 zero passes":     argon(0, 1024, 1), // panicked in x/crypto/argon2
		"argon2 zero threads":    argon(4, 1024, 0), // panicked too
		"argon2 255 threads":     argon(4, 1<<20, 255),
		"argon2 2^31 passes":     argon(1<<31, 1024, 1),
		"argon2 memory below 8p": argon(4, 8, 4),
		"100000 stripes":         func(cfg map[string]any) { slot0(cfg)["af"].(map[string]any)["stripes"] = 100000 },
		"a 1 MiB key":            func(cfg map[string]any) { slot0(cfg)["key_size"] = 1 << 20 },
		"a negative area key":    func(cfg map[string]any) { slot0(cfg)["area"].(map[string]any)["key_size"] = -1 },
		"2^31 digest iterations": func(cfg map[string]any) {
			cfg["digests"].(map[string]any)["0"].(map[string]any)["iterations"] = 1 << 31
		},
		"an empty digest": func(cfg map[string]any) {
			cfg["digests"].(map[string]any)["0"].(map[string]any)["digest"] = []byte{}
		},
	} {
		openQuickly(t, name, patchLUKS2(t, img, edit), pass, DefaultLimits)
	}
	// The image as built opens with the defaults, and a caller's tighter
	// limit refuses it, naming the slot.
	if _, err := OpenFrom(&memRW{b: bytes.Clone(img)}, pass); err != nil {
		t.Fatalf("default limits: %v", err)
	}
	_, err := OpenFromLimited(&memRW{b: bytes.Clone(img)}, pass, Limits{MaxPBKDF2Iterations: 100, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 1})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("a tight limit: %v", err)
	}
}

func TestLimitsLUKS1(t *testing.T) {
	img, _, pass := buildLUKS1Image(t)
	put := func(off int, v uint32) []byte {
		b := bytes.Clone(img)
		binary.BigEndian.PutUint32(b[off:], v)
		return b
	}
	for name, b := range map[string][]byte{
		"slot iterations 2^32-1": put(208+4, 1<<32-1),
		"slot iterations 0":      put(208+4, 0),
		"digest iterations 2^32": put(164, 1<<32-1),
		"stripes 2^32-1":         put(208+44, 1<<32-1),
		"key bytes 2^32-1":       put(108, 1<<32-1),
	} {
		openQuickly(t, name, b, pass, DefaultLimits)
	}
	if _, err := OpenFrom(&memRW{b: bytes.Clone(img)}, pass); err != nil {
		t.Fatalf("default limits: %v", err)
	}
	if _, err := OpenFromLimited(&memRW{b: bytes.Clone(img)}, pass, Limits{MaxPBKDF2Iterations: 10}); !errors.Is(err, ErrLimit) {
		t.Fatalf("a tight limit: %v", err)
	}
}

func TestOpenLimitedPath(t *testing.T) {
	if _, err := OpenLimited("/does/not/exist", nil, DefaultLimits); err == nil {
		t.Fatal("a missing path opened")
	}
}
