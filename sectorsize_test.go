package luks

import (
	"runtime"
	"testing"
)

// TestLUKS2SectorSizeIsRefusedAtOpen: a sector_size cryptsetup would not
// write is refused at Open, not met as a panic in the XTS library (-512, 1, 7,
// 8, 24, 500, 520) or a 64 MiB allocation that returns (0, nil) at the first
// ReadAt (1<<26).
func TestLUKS2SectorSizeIsRefusedAtOpen(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	base = append(base, make([]byte, 1<<16)...)
	for _, ss := range []int{-512, -1, 1, 7, 8, 24, 500, 511, 513, 520, 768, 8192, 1 << 26} {
		img := patchLUKS2(t, base, func(cfg map[string]any) { segment0(cfg)["sector_size"] = ss })
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("sector_size %d: panic %v", ss, r)
				}
			}()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			dev, err := OpenFrom(&memRW{b: img}, pass)
			if err == nil {
				n, rerr := dev.ReadAt(make([]byte, 512), 0)
				runtime.ReadMemStats(&after)
				t.Errorf("sector_size %d accepted; ReadAt(512)=(%d, %v), %d KiB allocated",
					ss, n, rerr, (after.TotalAlloc-before.TotalAlloc)>>10)
			}
		}()
	}
}

// TestLUKS2SectorSizesAllowed: the four sizes cryptsetup writes still open.
func TestLUKS2SectorSizesAllowed(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	for _, ss := range []int{0, 512, 1024, 2048, 4096} {
		img := patchLUKS2(t, base, func(cfg map[string]any) { segment0(cfg)["sector_size"] = ss })
		dev, err := OpenFrom(&memRW{b: img}, pass)
		if err != nil {
			t.Errorf("sector_size %d: %v", ss, err)
			continue
		}
		dev.Close()
	}
}

// TestLUKS2SegmentAlignment: the payload offset and a fixed segment size must
// be whole sectors.
func TestLUKS2SegmentAlignment(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	for _, tc := range []struct {
		name  string
		edit  func(seg map[string]any)
		wantO bool
	}{
		{"aligned 4096", func(s map[string]any) { s["sector_size"] = 4096; s["size"] = "8192" }, true},
		{"size not a multiple", func(s map[string]any) { s["sector_size"] = 4096; s["size"] = "4608" }, false},
		{"size 511", func(s map[string]any) { s["size"] = "511" }, false},
		{"offset not a multiple", func(s map[string]any) { s["sector_size"] = 4096; s["offset"] = "131584" }, false},
	} {
		img := patchLUKS2(t, base, func(cfg map[string]any) { tc.edit(segment0(cfg)) })
		dev, err := OpenFrom(&memRW{b: img}, pass)
		if tc.wantO != (err == nil) {
			t.Errorf("%s: err=%v", tc.name, err)
		}
		if err == nil {
			dev.Close()
		}
	}
}
