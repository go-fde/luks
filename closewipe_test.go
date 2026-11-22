package luks

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// TestCloseWipesVolumeKey: Close used to only close the file; the volume key
// stayed in Device.h.volumeKey (Fable F9 / Opus #7 reproducers).
func TestCloseWipesVolumeKey(t *testing.T) {
	img, vk, pass := buildLUKS2Image(t)
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dev.h.volumeKey, vk) {
		t.Fatal("precondition: the open Device holds the volume key")
	}
	held := dev.h.volumeKey // the backing array, not a copy
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dev.h.volumeKey, vk) || dev.h.volumeKey != nil {
		t.Error("after Close the Device still references the volume key")
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Error("the key's backing array was dropped, not zeroed")
	}
	if dev.enc != nil {
		t.Error("after Close the Device still holds the sector cipher")
	}
}

func TestCloseWipesLUKS1VolumeKey(t *testing.T) {
	img, vk, pass := buildLUKS1Image(t)
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dev.h.volumeKey, vk) {
		t.Fatal("precondition: the open Device holds the volume key")
	}
	held := dev.h.volumeKey
	dev.Close()
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Error("the LUKS1 key's backing array was not zeroed by Close")
	}
}

// TestUseAfterCloseIsRefused: with the cipher dropped, I/O must be an error,
// not a nil dereference.
func TestUseAfterCloseIsRefused(t *testing.T) {
	img, _, pass := buildLUKS2Image(t)
	dev, err := OpenFrom(&memRW{b: img}, pass)
	if err != nil {
		t.Fatal(err)
	}
	dev.Close()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("I/O after Close crashed: %v", r)
			}
		}()
		if n, err := dev.ReadAt(make([]byte, 16), 0); n != 0 || !errors.Is(err, os.ErrClosed) {
			t.Errorf("ReadAt after Close = (%d, %v), want os.ErrClosed", n, err)
		}
		if n, err := dev.WriteAt(make([]byte, 16), 0); n != 0 || !errors.Is(err, os.ErrClosed) {
			t.Errorf("WriteAt after Close = (%d, %v), want os.ErrClosed", n, err)
		}
	}()
}
