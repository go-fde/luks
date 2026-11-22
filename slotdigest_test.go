package luks

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// cloneMap copies a JSON object one level deep, so an edit of the copy does
// not reach the original.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestLUKS2SlotAndDigestCountsAreBounded: the JSON area holds hundreds of key
// slots and digests; cryptsetup writes at most 32 and 8. More is refused with
// ErrLimit before any derivation (the audit measured 3155x the cost of a
// one-slot header at 100 x 100).
func TestLUKS2SlotAndDigestCountsAreBounded(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	grow := func(slots, digests int) []byte {
		return patchLUKS2(t, base, func(cfg map[string]any) {
			ks := cfg["keyslots"].(map[string]any)
			for i := 1; i < slots; i++ {
				ks[fmt.Sprint(i)] = cloneMap(ks["0"].(map[string]any))
			}
			ds := cfg["digests"].(map[string]any)
			for i := 1; i < digests; i++ {
				ds[fmt.Sprint(i)] = cloneMap(ds["0"].(map[string]any))
			}
		})
	}
	for _, tc := range []struct {
		slots, digests int
		refused        bool
	}{
		{32, 8, false},
		{33, 1, true},
		{1, 9, true},
	} {
		_, err := OpenFrom(&memRW{b: grow(tc.slots, tc.digests)}, pass)
		if got := errors.Is(err, ErrLimit); got != tc.refused {
			t.Errorf("%d slots, %d digests: ErrLimit=%v (err=%v), want %v", tc.slots, tc.digests, got, err, tc.refused)
		}
	}
}

// TestLUKS2SlotIsCheckedOnlyAgainstItsDigests: a wrong passphrase costs the
// slot's KDF plus the digests that slot lists, not every digest of the header.
// Seven decoy digests at 2M iterations that no slot lists would cost seconds if
// each candidate key were checked against all of them.
func TestLUKS2SlotIsCheckedOnlyAgainstItsDigests(t *testing.T) {
	base, _, _ := buildLUKS2Image(t)
	img := patchLUKS2(t, base, func(cfg map[string]any) {
		ds := cfg["digests"].(map[string]any)
		for i := 1; i < 8; i++ {
			d := cloneMap(ds["0"].(map[string]any))
			d["iterations"] = 2_000_000
			d["keyslots"] = []string{"unlisted"}
			ds[fmt.Sprint(i)] = d
		}
	})
	lim := DefaultLimits
	start := time.Now()
	_, err := OpenFromLimited(&memRW{b: img}, []byte("wrong passphrase"), lim)
	if err == nil {
		t.Fatal("opened with a wrong passphrase")
	}
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("wrong passphrase took %v: the decoy digests were checked", d)
	}
}

// TestLUKS2SlotNoDigestListsCannotUnlock: the right passphrase does not open a
// header in which no digest lists the slot.
func TestLUKS2SlotNoDigestListsCannotUnlock(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	if _, err := OpenFrom(&memRW{b: base}, pass); err != nil {
		t.Fatal(err)
	}
	img := patchLUKS2(t, base, func(cfg map[string]any) {
		cfg["digests"].(map[string]any)["0"].(map[string]any)["keyslots"] = []string{}
	})
	if _, err := OpenFrom(&memRW{b: img}, pass); err == nil {
		t.Fatal("a slot that no digest lists unlocked the device")
	}
}
