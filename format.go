package luks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	formatKeyBytes = 32
	formatStripes  = 4000
	formatMKIter   = 1000
	formatSlotIter = 1000
	formatKMSector = uint32(8)
	formatCipher   = "aes"
	formatMode     = "xts-plain64"
	formatHash     = "sha256"
)

// luks1SlotData holds computed values for one active LUKS1 key slot.
type luks1SlotData struct {
	salt        [32]byte
	iterations  uint32
	stripes     uint32
	afEncrypted []byte
	payloadOff  uint32 // in sectors
}

// randReadFn is the crypto-rand entry point used by randBytes. It's
// a package var so tests can inject a failing implementation to
// exercise the panic path; production code never overrides it.
var randReadFn = rand.Read

// randBytes returns n cryptographically random bytes. A failure here
// would indicate a broken crypto-RNG which the caller cannot do
// anything sensible about — we panic rather than propagate, in line
// with the practical behaviour of every modern OS.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := randReadFn(b); err != nil {
		panic("luks: crypto/rand.Read failed: " + err.Error())
	}
	return b
}

// Format creates a new LUKS1 container at path, protecting it with passphrase.
// The file must already exist. Returns an opened Device ready for payload I/O.
func Format(path string, passphrase []byte) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("luks: format %s: %w", path, err)
	}
	dev, err := FormatOn(f, passphrase)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

// FormatOn creates a new LUKS1 container on rw, protecting it with passphrase.
// Returns an opened Device ready for payload I/O.
func FormatOn(rw blockRW, passphrase []byte) (*Device, error) {
	return formatDevice(rw, passphrase)
}

// formatDevice is the shared implementation for Format and FormatOn.
func formatDevice(rw blockRW, passphrase []byte) (*Device, error) {
	vk := randBytes(formatKeyBytes)
	slot, err := buildLUKS1Slot(vk, passphrase)
	if err != nil {
		return nil, err
	}
	hdr, err := buildLUKS1HdrBytes(vk, slot)
	if err != nil {
		return nil, err
	}
	if err := writeLUKS1Container(rw, hdr, slot); err != nil {
		return nil, err
	}
	return openFormatted(rw, vk, slot.payloadOff)
}

// buildLUKS1Slot derives the slot key and produces the encrypted AF-split.
func buildLUKS1Slot(vk, passphrase []byte) (*luks1SlotData, error) {
	saltSlice := randBytes(32)
	slotKey := pbkdf2.Key(passphrase, saltSlice, formatSlotIter, formatKeyBytes, sha256.New)
	afPlain, err := afSplitKey(vk, formatStripes, formatHash)
	if err != nil {
		return nil, err
	}
	enc, err := newSectorCipher(formatCipher+"-"+formatMode, slotKey, luks1SectorSize)
	if err != nil {
		return nil, fmt.Errorf("luks: format: slot cipher: %w", err)
	}
	afEnc, err := enc.encryptRaw(afPlain)
	if err != nil {
		return nil, err
	}
	afSectors := uint32(len(afPlain)+luks1SectorSize-1) / luks1SectorSize
	var slot luks1SlotData
	copy(slot.salt[:], saltSlice)
	slot.iterations = formatSlotIter
	slot.stripes = formatStripes
	slot.afEncrypted = afEnc
	slot.payloadOff = formatKMSector + afSectors
	return &slot, nil
}

// buildLUKS1HdrBytes serialises the 592-byte LUKS1 physical header.
func buildLUKS1HdrBytes(vk []byte, slot *luks1SlotData) ([]byte, error) {
	mkSalt := randBytes(32)
	mkDigest := pbkdf2.Key(vk, mkSalt, formatMKIter, 20, sha256.New)
	buf := make([]byte, 592)
	copy(buf[0:6], luksHeaderMagic)
	binary.BigEndian.PutUint16(buf[6:8], 1)
	writeNullPad(buf[8:40], formatCipher)
	writeNullPad(buf[40:72], formatMode)
	writeNullPad(buf[72:104], formatHash)
	binary.BigEndian.PutUint32(buf[104:108], slot.payloadOff)
	binary.BigEndian.PutUint32(buf[108:112], formatKeyBytes)
	copy(buf[112:132], mkDigest)
	copy(buf[132:164], mkSalt)
	binary.BigEndian.PutUint32(buf[164:168], formatMKIter)
	// UUID at [168:208] left as zeros; slot 0 is active.
	binary.BigEndian.PutUint32(buf[208:212], luks1KeySlotActive)
	binary.BigEndian.PutUint32(buf[212:216], slot.iterations)
	copy(buf[216:248], slot.salt[:])
	binary.BigEndian.PutUint32(buf[248:252], formatKMSector)
	binary.BigEndian.PutUint32(buf[252:256], slot.stripes)
	for i := 1; i < luks1NumKeySlots; i++ {
		binary.BigEndian.PutUint32(buf[208+i*48:], 0xDEAD0000)
	}
	return buf, nil
}

// writeNullPad writes s into buf, null-padding the remainder.
func writeNullPad(buf []byte, s string) {
	n := copy(buf, s)
	for i := n; i < len(buf); i++ {
		buf[i] = 0
	}
}

// writeLUKS1Container writes the header and encrypted key material to rw.
func writeLUKS1Container(rw blockRW, hdr []byte, slot *luks1SlotData) error {
	if _, err := rw.WriteAt(hdr, 0); err != nil {
		return fmt.Errorf("luks: format: write header: %w", err)
	}
	kmOff := int64(formatKMSector) * luks1SectorSize
	if _, err := rw.WriteAt(slot.afEncrypted, kmOff); err != nil {
		return fmt.Errorf("luks: format: write key material: %w", err)
	}
	return nil
}

// openFormatted builds and returns a Device ready for payload I/O after formatting.
func openFormatted(rw blockRW, vk []byte, payloadSector uint32) (*Device, error) {
	enc, err := newSectorCipher(formatCipher+"-"+formatMode, vk, luks1SectorSize)
	if err != nil {
		return nil, fmt.Errorf("luks: format: cipher: %w", err)
	}
	payloadBytes := int64(payloadSector) * luks1SectorSize
	enc.fileBase = payloadBytes
	h := luksHeader{
		version:    1,
		volumeKey:  vk,
		payloadOff: payloadBytes,
		cipher:     formatCipher + "-" + formatMode,
		sectorSize: luks1SectorSize,
	}
	return &Device{f: rw, h: h, enc: enc}, nil
}
