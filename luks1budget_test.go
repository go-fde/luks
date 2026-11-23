package luks

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// hostileLUKS1 returns img with all 8 key slots active and asking for iter
// PBKDF2 iterations each, and the master-key digest asking for iter too.
func hostileLUKS1(img []byte, iter uint32) []byte {
	out := append([]byte(nil), img...)
	for i := range luks1NumKeySlots {
		base := 208 + i*48
		copy(out[base:base+48], img[208:256])
		binary.BigEndian.PutUint32(out[base+4:base+8], iter)
	}
	binary.BigEndian.PutUint32(out[164:168], iter)
	return out
}

// TestLUKS1TotalKDFWorkIsBudgeted: a normal LUKS1 volume opens, a budget one
// unit short of what it costs refuses it with ErrLimit.
func TestLUKS1TotalKDFWorkIsBudgeted(t *testing.T) {
	img, _, pass := buildLUKS1Image(t)
	c, err := spentBy(t, img, pass)
	if err != nil || c == 0 {
		t.Fatalf("spent %d, err %v", c, err)
	}
	if err := withBudget(img, pass, c); err != nil {
		t.Fatalf("a budget of exactly %d units refused: %v", c, err)
	}
	if err := withBudget(img, pass, c-1); !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, ErrLimit) {
		t.Fatalf("a budget of %d units: err = %v, want ErrLimit", c-1, err)
	}
}

// TestLUKS1HostileHeaderIsRefusedBeforeItsWork: eight slots of 5e7 iterations
// each (inside the per-slot limit) with the master-key digest too are refused
// with ErrLimit by a budget smaller than one slot, before any of that work
// runs (the test would take minutes otherwise).
func TestLUKS1HostileHeaderIsRefusedBeforeItsWork(t *testing.T) {
	img, _, _ := buildLUKS1Image(t)
	hostile := hostileLUKS1(img, 50_000_000)
	if err := withBudget(hostile, []byte("wrong passphrase"), 1<<27); !errors.Is(err, ErrLimit) || !errors.Is(err, kdfbudget.ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestLUKS1SlotsAreChargedInTurn: with a wrong passphrase every active slot is
// tried, so eight slots cost eight times one; a budget that holds one is
// refused at the second.
func TestLUKS1SlotsAreChargedInTurn(t *testing.T) {
	img, _, pass := buildLUKS1Image(t)
	one, err := spentBy(t, img, pass)
	if err != nil {
		t.Fatal(err)
	}
	eight := hostileLUKS1(img, 1000)
	wrong := []byte("wrong passphrase")
	if err := withBudget(eight, wrong, one); !errors.Is(err, ErrLimit) {
		t.Fatalf("a budget of one slot, eight tried: err = %v, want ErrLimit", err)
	}
	if err := withBudget(eight, wrong, 8*one); errors.Is(err, ErrLimit) {
		t.Fatalf("a budget of eight slots refused: %v", err)
	}
}

// TestLUKS1CallerBudgetIsCharged: a caller's Limits.Budget is spent by a
// LUKS1 open.
func TestLUKS1CallerBudgetIsCharged(t *testing.T) {
	img, _, pass := buildLUKS1Image(t)
	lim := DefaultLimits
	lim.Budget = kdfbudget.Unlimited()
	dev, err := OpenFromLimited(&memRW{b: img}, pass, lim)
	if err != nil {
		t.Fatal(err)
	}
	dev.Close()
	if lim.Budget.Spent() == 0 {
		t.Fatal("the caller's budget was not charged")
	}
}
