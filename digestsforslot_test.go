package luks

import (
	"slices"
	"testing"
)

// TestLUKS2DigestsForSlot pins which digests a slot is checked against.
func TestLUKS2DigestsForSlot(t *testing.T) {
	cfg := &luks2JSON{Digests: map[string]luks2Digest{
		"0": {Keyslots: []string{"0", "2"}, Iterations: 10},
		"1": {Keyslots: []string{"1"}, Iterations: 11},
		"2": {Iterations: 12}, // lists nothing
	}}
	iters := func(slot string) []int {
		var out []int
		for _, d := range digestsForSlot(cfg, slot) {
			out = append(out, d.Iterations)
		}
		slices.Sort(out)
		return out
	}
	for slot, want := range map[string][]int{"0": {10}, "1": {11}, "2": {10}, "3": nil} {
		if got := iters(slot); !slices.Equal(got, want) {
			t.Errorf("slot %s: digests %v, want %v", slot, got, want)
		}
	}
}
