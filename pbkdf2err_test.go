package luks

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-encryptions/hmac"
)

// The PBKDF2 of go-encryptions/hmac refuses a count below 1 where x/crypto
// ran one round for 0. Each call site must pass that refusal on, not go on
// with a nil key.

func TestLUKS1SlotKDFRefusesZeroIterations(t *testing.T) {
	img, _, pass := buildLUKS1Image(t)
	h, err := parseLUKS1Phdr(&memRW{b: img})
	if err != nil {
		t.Fatal(err)
	}
	slot := &h.keySlots[0]
	slot.iterations = 0
	if _, err := tryLUKS1Slot(&memRW{b: img}, h, slot, pass, sha256.New); !errors.Is(err, hmac.ErrIterations) {
		t.Errorf("tryLUKS1Slot with 0 iterations: %v, want hmac.ErrIterations", err)
	}
}

func TestLUKS1DigestRefusesZeroIterations(t *testing.T) {
	err := verifyMasterKey(make([]byte, 32), make([]byte, 20), make([]byte, 32), 0, sha256.New)
	if !errors.Is(err, hmac.ErrIterations) {
		t.Errorf("verifyMasterKey with 0 iterations: %v, want hmac.ErrIterations", err)
	}
}

func TestFormatKDFRefusesZeroIterations(t *testing.T) {
	vk := make([]byte, formatKeyBytes)
	if _, err := buildLUKS1SlotIter(vk, []byte("pass"), 0); !errors.Is(err, hmac.ErrIterations) {
		t.Errorf("buildLUKS1SlotIter with 0 iterations: %v, want hmac.ErrIterations", err)
	}
	slot := &luks1SlotData{}
	if _, err := buildLUKS1HdrBytesIter(vk, slot, 0); !errors.Is(err, hmac.ErrIterations) {
		t.Errorf("buildLUKS1HdrBytesIter with 0 iterations: %v, want hmac.ErrIterations", err)
	}
	if _, err := buildLUKS1SlotIter(vk, []byte("pass"), 1); err != nil {
		t.Errorf("buildLUKS1SlotIter with 1 iteration: %v", err)
	}
	if _, err := buildLUKS1HdrBytesIter(vk, slot, 1); err != nil {
		t.Errorf("buildLUKS1HdrBytesIter with 1 iteration: %v", err)
	}
}
