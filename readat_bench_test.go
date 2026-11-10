package luks

import "testing"

// benchDev is an in-memory device for the ReadAt / WriteAt benchmarks.
type benchDev struct{ data []byte }

func (d *benchDev) ReadAt(p []byte, off int64) (int, error)  { return copy(p, d.data[off:]), nil }
func (d *benchDev) WriteAt(p []byte, off int64) (int, error) { return copy(d.data[off:], p), nil }

var benchCiphers = []struct {
	name, cipher string
	keyLen       int
}{
	{"XTS-128", "aes-xts-plain64", 32},
	{"XTS-256", "aes-xts-plain64", 64},
	{"CBC-ESSIV-128", "aes-cbc-essiv:sha256", 16},
	{"CBC-ESSIV-256", "aes-cbc-essiv:sha256", 32},
}

// BenchmarkReadAt is a Device read: 1 MiB of 512-byte sectors through
// sectorCipher.readAt, the path Device.ReadAt takes.
func BenchmarkReadAt(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			sc, err := newSectorCipher(c.cipher, benchData(c.keyLen), 512)
			if err != nil {
				b.Fatal(err)
			}
			dev := &benchDev{data: benchData(2 << 20)}
			p := make([]byte, 1<<20)
			b.SetBytes(int64(len(p)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := sc.readAt(dev, p, 4096); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWriteAt is a Device write of 1 MiB, sector-aligned.
func BenchmarkWriteAt(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			sc, err := newSectorCipher(c.cipher, benchData(c.keyLen), 512)
			if err != nil {
				b.Fatal(err)
			}
			dev := &benchDev{data: benchData(2 << 20)}
			p := benchData(1 << 20)
			b.SetBytes(int64(len(p)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := sc.writeAt(dev, p, 4096); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
