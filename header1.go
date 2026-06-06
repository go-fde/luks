package luks

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

const (
	luksHeaderMagic    = "LUKS\xba\xbe"
	luks1SectorSize    = 512
	luks1NumKeySlots   = 8
	luks1KeySlotActive = 0x00AC71F3
)

// luks1KeySlot holds the parsed data of one LUKS1 key slot.
type luks1KeySlot struct {
	active         uint32
	iterations     uint32
	salt           [32]byte
	keyMaterialOff uint32 // in 512-byte sectors
	stripes        uint32
}

// luks1Phdr holds the parsed LUKS1 phdr (physical header).
type luks1Phdr struct {
	cipherName         string
	cipherMode         string
	hashSpec           string
	payloadOffset      uint32 // in 512-byte sectors
	keyBytes           uint32
	mkDigest           [20]byte
	mkDigestSalt       [32]byte
	mkDigestIterations uint32
	keySlots           [luks1NumKeySlots]luks1KeySlot
}

// parseLUKS1Phdr reads and validates the LUKS1 header from f at offset 0.
func parseLUKS1Phdr(f io.ReaderAt) (*luks1Phdr, error) {
	buf := make([]byte, 592)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("luks1: read phdr: %w", err)
	}
	h := &luks1Phdr{
		cipherName:         nullStr(buf[8:40]),
		cipherMode:         nullStr(buf[40:72]),
		hashSpec:           nullStr(buf[72:104]),
		payloadOffset:      binary.BigEndian.Uint32(buf[104:108]),
		keyBytes:           binary.BigEndian.Uint32(buf[108:112]),
		mkDigestIterations: binary.BigEndian.Uint32(buf[164:168]),
	}
	copy(h.mkDigest[:], buf[112:132])
	copy(h.mkDigestSalt[:], buf[132:164])
	for i := range h.keySlots {
		base := 208 + i*48
		h.keySlots[i] = luks1KeySlot{
			active:         binary.BigEndian.Uint32(buf[base : base+4]),
			iterations:     binary.BigEndian.Uint32(buf[base+4 : base+8]),
			keyMaterialOff: binary.BigEndian.Uint32(buf[base+40 : base+44]),
			stripes:        binary.BigEndian.Uint32(buf[base+44 : base+48]),
		}
		copy(h.keySlots[i].salt[:], buf[base+8:base+40])
	}
	return h, nil
}

// unlockLUKS1 tries each active key slot with passphrase and returns the
// container description if a slot matches.
func unlockLUKS1(f io.ReaderAt, passphrase []byte) (*luksHeader, error) {
	h, err := parseLUKS1Phdr(f)
	if err != nil {
		return nil, err
	}
	hashFn, err := hashFactory(h.hashSpec)
	if err != nil {
		return nil, fmt.Errorf("luks1: %w", err)
	}
	for i := range h.keySlots {
		slot := &h.keySlots[i]
		if slot.active != luks1KeySlotActive {
			continue
		}
		mk, err := tryLUKS1Slot(f, h, slot, passphrase, hashFn)
		if err != nil {
			continue // wrong passphrase or decryption error
		}
		return &luksHeader{
			version:    1,
			volumeKey:  mk,
			payloadOff: int64(h.payloadOffset) * luks1SectorSize,
			cipher:     h.cipherName + "-" + h.cipherMode,
			sectorSize: luks1SectorSize,
		}, nil
	}
	return nil, fmt.Errorf("luks1: no key slot matches passphrase")
}

// tryLUKS1Slot derives the slot key, decrypts the AF material, and verifies
// the master key digest. Returns the master key on success.
func tryLUKS1Slot(f io.ReaderAt, h *luks1Phdr, slot *luks1KeySlot, passphrase []byte, hf func() hash.Hash) ([]byte, error) {
	slotKey := pbkdf2.Key(passphrase, slot.salt[:], int(slot.iterations), int(h.keyBytes), hf)
	afKey, err := readAndDecryptKeyMaterial(f, h, slot, slotKey)
	if err != nil {
		return nil, err
	}
	mk, err := afMerge(afKey, int(h.keyBytes), int(slot.stripes), h.hashSpec)
	if err != nil {
		return nil, err
	}
	if err := verifyMasterKey(mk, h.mkDigest[:], h.mkDigestSalt[:], int(h.mkDigestIterations), hf); err != nil {
		return nil, err
	}
	return mk, nil
}

// readAndDecryptKeyMaterial reads the AF-split material from disk and decrypts it.
func readAndDecryptKeyMaterial(f io.ReaderAt, h *luks1Phdr, slot *luks1KeySlot, slotKey []byte) ([]byte, error) {
	afSize := int(h.keyBytes) * int(slot.stripes)
	afData := make([]byte, afSize)
	off := int64(slot.keyMaterialOff) * luks1SectorSize
	if _, err := f.ReadAt(afData, off); err != nil {
		return nil, fmt.Errorf("luks1: read key material: %w", err)
	}
	enc, err := newSectorCipher(h.cipherName+"-"+h.cipherMode, slotKey, luks1SectorSize)
	if err != nil {
		return nil, fmt.Errorf("luks1: cipher for key slot: %w", err)
	}
	return enc.decryptRaw(afData)
}

// verifyMasterKey confirms that mk produces the expected digest.
func verifyMasterKey(mk, digest, salt []byte, iter int, hf func() hash.Hash) error {
	computed := pbkdf2.Key(mk, salt, iter, len(digest), hf)
	for i, b := range computed {
		if b != digest[i] {
			return fmt.Errorf("luks1: master key digest mismatch")
		}
	}
	return nil
}

// hashFactory returns a hash.Hash constructor for the given LUKS hash name.
func hashFactory(name string) (func() hash.Hash, error) {
	switch name {
	case "sha1":
		return sha1.New, nil
	case "sha256", "":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "ripemd160":
		return ripemd160.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash %q", name)
	}
}

// nullStr converts a null-terminated C string slice to a Go string.
func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
