package luks

import (
	"strconv"
	"testing"
)

func segment0(cfg map[string]any) map[string]any {
	return cfg["segments"].(map[string]any)["0"].(map[string]any)
}

func TestPayloadSizeLUKS2(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	for _, c := range []struct {
		size string
		want int64
		bad  bool
	}{
		{"dynamic", 0, false},
		{"4096", 4096, false},
		{"0", 0, false},
		{"-512", 0, true},
		{"4096x", 0, true},
		{"99999999999999999999", 0, true},
	} {
		patched := patchLUKS2(t, img, func(cfg map[string]any) { segment0(cfg)["size"] = c.size })
		dev, err := OpenFrom(&memRW{b: patched}, pass)
		if c.bad {
			if err == nil {
				t.Errorf("size %q: opened, want an error", c.size)
			}
			continue
		}
		if err != nil {
			t.Fatalf("size %q: %v", c.size, err)
		}
		if got := dev.Size(); got != c.want {
			t.Errorf("size %q: Size() = %d, want %d", c.size, got, c.want)
		}
	}
}

func TestPayloadOffset(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	var want int64
	patchLUKS2(t, img, func(cfg map[string]any) {
		want, _ = strconv.ParseInt(segment0(cfg)["offset"].(string), 10, 64)
	})
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got := dev.PayloadOffset(); got != want || want <= 0 {
		t.Errorf("LUKS2 PayloadOffset() = %d, want the segment's %d", got, want)
	}

	img1, _, pass1 := buildLUKS1Image(t)
	dev1, err := OpenFrom(&memRW{b: img1}, pass1)
	if err != nil {
		t.Fatal(err)
	}
	if got := dev1.PayloadOffset(); got <= 0 || got%luks1SectorSize != 0 {
		t.Errorf("LUKS1 PayloadOffset() = %d, want a positive multiple of %d", got, luks1SectorSize)
	}
	if dev1.Size() != 0 {
		t.Errorf("LUKS1 Size() = %d, want 0 (to the end of the device)", dev1.Size())
	}
}

func TestNegativeSegmentOffset(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	patched := patchLUKS2(t, img, func(cfg map[string]any) { segment0(cfg)["offset"] = "-4096" })
	if _, err := OpenFrom(&memRW{b: patched}, pass); err == nil {
		t.Fatal("a negative segment offset opened")
	}
}
