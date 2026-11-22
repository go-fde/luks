package luks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

// readNoPanic turns a crash inside ReadAt into an ordinary error, so that the
// caller's assertion (want ErrOffset) is what fails.
func readNoPanic(t *testing.T, dev *Device, n int, off int64) (got int, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			got, err = 0, fmt.Errorf("recovered a crash: %v", r)
		}
	}()
	return dev.ReadAt(make([]byte, n), off)
}

// TestDeviceNegativeOffset: a negative offset was a slice panic on ReadAt and,
// on WriteAt, encrypted over the LUKS header (WriteAt(p, -PayloadOffset)
// returned n=512, nil and the volume no longer opened).
func TestDeviceNegativeOffset(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	m := &memRW{b: bytes.Clone(img)}
	dev, err := OpenFrom(m, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readNoPanic(t, dev, 16, -1); !errors.Is(err, ErrOffset) {
		t.Errorf("ReadAt(-1): %v, want ErrOffset", err)
	}
	for _, off := range []int64{-1, -512, -dev.PayloadOffset(), math.MinInt64} {
		n, err := writeNoPanic(dev, 512, off)
		if n != 0 || !errors.Is(err, ErrOffset) {
			t.Errorf("WriteAt(%d) = (%d, %v), want (0, ErrOffset)", off, n, err)
		}
	}
	if !bytes.Equal(m.b, img) {
		t.Error("a refused write changed the device")
	}
	if _, err := OpenFrom(m, pass); err != nil {
		t.Errorf("reopen after the refused writes: %v", err)
	}
}

// TestDeviceOffsetOverflow: payloadOff+off must not wrap.
func TestDeviceOffsetOverflow(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	dev, err := OpenFrom(&memRW{b: bytes.Clone(img)}, pass)
	if err != nil {
		t.Fatal(err)
	}
	// 512 bytes at the largest offset whose end still fits is not an overflow
	// (the device then simply has no such byte); one more is.
	last := int64(math.MaxInt64) - dev.PayloadOffset() - 512
	if _, err := readNoPanic(t, dev, 512, last); errors.Is(err, ErrOffset) {
		t.Errorf("ReadAt(%d) refused as an overflow, but it fits: %v", last, err)
	}
	for _, off := range []int64{math.MaxInt64, math.MaxInt64 - dev.PayloadOffset(), last + 1} {
		if _, err := readNoPanic(t, dev, 512, off); !errors.Is(err, ErrOffset) {
			t.Errorf("ReadAt(%d): %v, want ErrOffset", off, err)
		}
		if _, err := writeNoPanic(dev, 512, off); !errors.Is(err, ErrOffset) {
			t.Errorf("WriteAt(%d): %v, want ErrOffset", off, err)
		}
	}
}

func writeNoPanic(dev *Device, n int, off int64) (got int, err error) {
	defer func() {
		if r := recover(); r != nil {
			got, err = 0, fmt.Errorf("recovered a crash: %v", r)
		}
	}()
	return dev.WriteAt(make([]byte, n), off)
}

// TestDeviceFixedSegmentSize: with segments.0.size = "512", the device ends at
// 512; I/O at 4096 used to reach the bytes the header's author placed after
// the segment.
func TestDeviceFixedSegmentSize(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	base = append(base, make([]byte, 8192)...)
	img := patchLUKS2(t, base, func(cfg map[string]any) { segment0(cfg)["size"] = "512" })
	rw := &memRW{b: img}
	dev, err := OpenFrom(rw, pass)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Size() != 512 {
		t.Fatalf("Size() = %d", dev.Size())
	}
	before := bytes.Clone(rw.b)

	if n, err := readNoPanic(t, dev, 512, 4096); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at 4096 = (%d, %v), want (0, EOF)", n, err)
	}
	if n, err := readNoPanic(t, dev, 1, 512); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at the end = (%d, %v), want (0, EOF)", n, err)
	}
	if n, err := readNoPanic(t, dev, 1024, 0); n != 512 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt of 1024 at 0 = (%d, %v), want (512, EOF)", n, err)
	}
	if n, err := readNoPanic(t, dev, 100, 500); n != 12 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt of 100 at 500 = (%d, %v), want (12, EOF)", n, err)
	}
	if n, err := readNoPanic(t, dev, 512, 0); n != 512 || err != nil {
		t.Errorf("ReadAt of the whole segment = (%d, %v)", n, err)
	}
	for _, w := range []struct {
		n   int
		off int64
	}{{512, 4096}, {513, 0}, {1, 512}, {512, 1}, {1, 1 << 40}} {
		if n, err := writeNoPanic(dev, w.n, w.off); n != 0 || !errors.Is(err, ErrOffset) {
			t.Errorf("WriteAt(%d bytes at %d) = (%d, %v), want (0, ErrOffset)", w.n, w.off, n, err)
		}
	}
	if !bytes.Equal(before, rw.b) {
		t.Error("a refused write changed the device")
	}
	// The edges that are inside still work.
	if n, err := dev.WriteAt(bytes.Repeat([]byte{0xBB}, 512), 0); n != 512 || err != nil {
		t.Errorf("WriteAt of the whole segment = (%d, %v)", n, err)
	}
	if n, err := dev.WriteAt(nil, 512); n != 0 || err != nil {
		t.Errorf("empty WriteAt at the end = (%d, %v)", n, err)
	}
	got := make([]byte, 512)
	if _, err := dev.ReadAt(got, 0); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xBB}, 512)) {
		t.Errorf("read back: %v", err)
	}
}
