package luks

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// spentBy opens img with pass under an unlimited budget and returns the work
// that open charged, and the error it gave.
func spentBy(t *testing.T, img, pass []byte) (uint64, error) {
	t.Helper()
	var b *kdfbudget.Budget
	old := newKDFBudget
	newKDFBudget = func() *kdfbudget.Budget { b = kdfbudget.Unlimited(); return b }
	defer func() { newKDFBudget = old }()
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err == nil {
		dev.Close()
	}
	return b.Spent(), err
}

// withBudget opens img with pass under a budget of maxWork units.
func withBudget(img, pass []byte, maxWork uint64) error {
	old := newKDFBudget
	newKDFBudget = func() *kdfbudget.Budget {
		b := kdfbudget.Unlimited()
		b.MaxWork = maxWork
		return b
	}
	defer func() { newKDFBudget = old }()
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err == nil {
		dev.Close()
	}
	return err
}

// TestLUKS2TotalKDFWorkIsBudgeted: a header may hold many key slots, each
// within its own limit; the work of all of them (and of their digests) is
// charged to one budget before it is spent. The boundary is asserted on both
// sides: exactly the work of the slots tried fits, one unit less is refused.
func TestLUKS2TotalKDFWorkIsBudgeted(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	wrong := []byte("wrong passphrase")

	// One slot, right passphrase: the cost C of one slot and its digest.
	c, err := spentBy(t, base, pass)
	if err != nil || c == 0 {
		t.Fatalf("one slot: spent %d, err %v", c, err)
	}
	if err := withBudget(base, pass, c); err != nil {
		t.Errorf("a budget of exactly %d units refused the header: %v", c, err)
	}
	if err := withBudget(base, pass, c-1); !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, ErrLimit) {
		t.Errorf("a budget of %d units: err = %v, want ErrLimit", c-1, err)
	} else if !strings.HasPrefix(err.Error(), "luks2: digest for key slot") {
		t.Errorf("a budget of %d units: err = %v, want the digest refused (the slot fits)", c-1, err)
	}

	// Three identical slots, wrong passphrase: all three are tried.
	three := patchLUKS2(t, base, func(cfg map[string]any) {
		ks := cfg["keyslots"].(map[string]any)
		ds := cfg["digests"].(map[string]any)["0"].(map[string]any)
		list := []string{"0"}
		for i := 1; i < 3; i++ {
			ks[fmt.Sprint(i)] = cloneMap(ks["0"].(map[string]any))
			list = append(list, fmt.Sprint(i))
		}
		ds["keyslots"] = list
	})
	total, err := spentBy(t, three, wrong)
	if err == nil || errors.Is(err, ErrLimit) {
		t.Fatalf("three slots, wrong passphrase: err = %v, want a plain mismatch", err)
	}
	if total != 3*c {
		t.Fatalf("three slots charged %d units, want 3 x %d", total, c)
	}
	if err := withBudget(three, wrong, total); errors.Is(err, ErrLimit) {
		t.Errorf("a budget of exactly %d units refused: %v", total, err)
	}
	if err := withBudget(three, wrong, total-1); !errors.Is(err, ErrLimit) {
		t.Errorf("a budget of %d units: err = %v, want ErrLimit", total-1, err)
	}
}

// TestLUKS2ChargeIsBeforeTheDerivation: a charge that does not fit is refused
// with ErrLimit and spends nothing, so no derivation ran for it.
func TestLUKS2ChargeIsBeforeTheDerivation(t *testing.T) {
	base, _, pass := buildLUKS2Image(t)
	b := kdfbudget.Unlimited()
	b.MaxWork = 1 // nothing fits
	old := newKDFBudget
	newKDFBudget = func() *kdfbudget.Budget { return b }
	defer func() { newKDFBudget = old }()
	_, err := OpenFrom(&memRW{b: base}, pass)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
	if !strings.HasPrefix(err.Error(), "luks2: key slot") {
		t.Errorf("err = %v: refused at the digest, so the slot KDF was run", err)
	}
	if b.Spent() != 0 {
		t.Errorf("a refused charge spent %d units", b.Spent())
	}
}

// TestChargeLUKS2Costs pins the units charged, absolutely: PBKDF2 is
// 2 x iterations x hash cost per output block, Argon2 is passes x KiB x 8.
func TestChargeLUKS2Costs(t *testing.T) {
	slot := func(kdf luks2KDF, keySize int) *luks2Keyslot {
		return &luks2Keyslot{KeySize: keySize, KDF: kdf}
	}
	for _, tc := range []struct {
		name   string
		charge func(b *kdfbudget.Budget) error
		want   uint64
	}{
		{"pbkdf2 sha256 slot, one block", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Slot(b, slot(luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1000}, 32))
		}, 2000},
		{"pbkdf2 sha256 slot, two blocks", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Slot(b, slot(luks2KDF{Type: "pbkdf2", Hash: "sha256", Iterations: 1000}, 33))
		}, 4000},
		{"pbkdf2 sha512 slot", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Slot(b, slot(luks2KDF{Type: "pbkdf2", Hash: "sha512", Iterations: 1000}, 64))
		}, 4000},
		{"argon2id slot", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Slot(b, slot(luks2KDF{Type: "argon2id", Time: 2, Memory: 1024, CPUs: 1}, 32))
		}, 2 * 1024 * 8},
		{"unknown KDF", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Slot(b, slot(luks2KDF{Type: "scrypt"}, 32))
		}, 0},
		{"pbkdf2 digest", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Digest(b, &luks2Digest{Type: "pbkdf2", Hash: "sha256", Iterations: 1000, Digest: make([]byte, 32)})
		}, 2000},
		{"digest of another type", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Digest(b, &luks2Digest{Type: "other", Hash: "sha256", Iterations: 1000, Digest: make([]byte, 32)})
		}, 0},
		{"unsupported hash is refused where it is derived", func(b *kdfbudget.Budget) error {
			return chargeLUKS2Digest(b, &luks2Digest{Type: "pbkdf2", Hash: "nonsense", Iterations: 1000, Digest: make([]byte, 32)})
		}, 0},
	} {
		func() {
			b := kdfbudget.Unlimited()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: PANIC %v", tc.name, r)
				}
			}()
			if err := tc.charge(b); err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			if got := b.Spent(); got != tc.want {
				t.Errorf("%s: charged %d units, want %d", tc.name, got, tc.want)
			}
		}()
	}
}
