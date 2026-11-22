package luks

import "testing"

// FuzzOpenHeader feeds arbitrary header bytes (the first 64 KiB of a
// container) to the LUKS1 and LUKS2 parsers. A header is untrusted input: the
// contract is an error or a Device, never a panic, a hang or an allocation
// out of proportion to the input. The seed corpus is committed in
// testdata/fuzz/FuzzOpenHeader (real cryptsetup headers and mutations of them).
func FuzzOpenHeader(f *testing.F) {
	lim := Limits{MaxPBKDF2Iterations: 1000, MaxArgon2Time: 2, MaxArgon2MemoryKiB: 1 << 10}
	f.Fuzz(func(t *testing.T, hdr []byte) {
		if len(hdr) > 1<<16 {
			hdr = hdr[:1<<16]
		}
		b := make([]byte, 1<<20)
		copy(b, hdr)
		dev, err := OpenFromLimited(&memRW{b: b}, []byte("fuzz"), lim)
		if err != nil {
			return
		}
		dev.ReadAt(make([]byte, 512), 0)
		dev.Close()
	})
}
