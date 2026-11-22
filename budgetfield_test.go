package luks

import (
	"errors"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// costOfOneOpen is the work one correct unlock of img charges.
func costOfOneOpen(t *testing.T, img, pass []byte) uint64 {
	t.Helper()
	c, err := spentBy(t, img, pass)
	if err != nil || c == 0 {
		t.Fatalf("spent %d, err %v", c, err)
	}
	return c
}

// TestLimitsBudgetSmallRefusesWhatDefaultAccepts: a header the default budget
// accepts is refused with ErrLimit under a caller's smaller Budget, and the
// same Budget with room opens it.
func TestLimitsBudgetSmallRefusesWhatDefaultAccepts(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	c := costOfOneOpen(t, img, pass)

	dev, err := OpenFromLimited(&memRW{b: img}, pass, DefaultLimits)
	if err != nil {
		t.Fatalf("default budget refused the header: %v", err)
	}
	dev.Close()

	small := DefaultLimits
	small.Budget = kdfbudget.Unlimited()
	small.Budget.MaxWork = c - 1
	if _, err := OpenFromLimited(&memRW{b: img}, pass, small); !errors.Is(err, ErrLimit) {
		t.Fatalf("a budget of %d units: err = %v, want ErrLimit", c-1, err)
	}

	fits := DefaultLimits
	fits.Budget = kdfbudget.Unlimited()
	fits.Budget.MaxWork = c
	dev, err = OpenFromLimited(&memRW{b: img}, pass, fits)
	if err != nil {
		t.Fatalf("a budget of exactly %d units refused: %v", c, err)
	}
	dev.Close()
}

// TestLimitsBudgetSharedIsDrainedAcrossOpens: one Budget given to two Opens is
// spent by both, so room for one unlock refuses the second.
func TestLimitsBudgetSharedIsDrainedAcrossOpens(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	c := costOfOneOpen(t, img, pass)

	lim := DefaultLimits
	lim.Budget = kdfbudget.Unlimited()
	lim.Budget.MaxWork = c
	dev, err := OpenFromLimited(&memRW{b: img}, pass, lim)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	dev.Close()
	if got := lim.Budget.Spent(); got != c {
		t.Fatalf("spent %d after one open, want %d", got, c)
	}
	if _, err := OpenFromLimited(&memRW{b: img}, pass, lim); !errors.Is(err, ErrLimit) {
		t.Fatalf("second open on the drained budget: err = %v, want ErrLimit", err)
	}

	// With the default (nil Budget) each Open has its own, so a second succeeds.
	for i := range 2 {
		dev, err := OpenFromLimited(&memRW{b: img}, pass, DefaultLimits)
		if err != nil {
			t.Fatalf("nil-budget open %d: %v", i, err)
		}
		dev.Close()
	}
}
