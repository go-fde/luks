package luks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-fde/luks/internal/xts"
)

// sectorCipher wraps the cipher logic for a LUKS payload or key area.
// It supports aes-xts-plain64 and aes-cbc-essiv:sha256.
type sectorCipher struct {
	mode       string
	sectorSize int
	// fileBase is the absolute file offset of logical sector 0. When the
	// cipher is used for a device payload, this is set to the payload's file
	// offset so that IV sector numbers start at 0 (or ivTweak) regardless of
	// where the payload sits in the file.
	fileBase int64
	// ivTweak is added to every logical sector number before IV computation.
	// LUKS2 supports non-zero iv_tweak values in the segment descriptor.
	ivTweak int64
	// xts mode
	xtsEnc *xts.Cipher
	// cbc-essiv mode
	cbcKey []byte
	ivKey  cipher.Block // AES block cipher for ESSIV IV generation
}

// newSectorCipher creates a sectorCipher from a LUKS cipher string and key.
// cipherStr is in the form "name-mode" (e.g. "aes-xts-plain64").
func newSectorCipher(cipherStr string, key []byte, sectorSize int) (*sectorCipher, error) {
	parts := strings.SplitN(strings.ToLower(cipherStr), "-", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("cipher: unrecognised cipher string %q", cipherStr)
	}
	name, mode := parts[0], parts[1]
	if name != "aes" {
		return nil, fmt.Errorf("cipher: unsupported cipher %q (only aes is supported)", name)
	}
	sc := &sectorCipher{mode: mode, sectorSize: sectorSize}
	switch {
	case strings.HasPrefix(mode, "xts"):
		return sc, sc.initXTS(key)
	case strings.HasPrefix(mode, "cbc"):
		return sc, sc.initCBCESSIV(key)
	default:
		return nil, fmt.Errorf("cipher: unsupported mode %q", mode)
	}
}

// initXTS initialises AES-XTS. The key must be 32 or 64 bytes (split 50/50).
func (sc *sectorCipher) initXTS(key []byte) error {
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return fmt.Errorf("cipher: xts init: %w", err)
	}
	sc.xtsEnc = c
	return nil
}

// initCBCESSIV initialises AES-CBC with ESSIV:sha256.
// The full key is the AES-CBC encryption key. The ESSIV IV derivation key is
// AES-256(SHA256(cipherKey)) — SHA256 always produces 32 bytes (AES-256).
func (sc *sectorCipher) initCBCESSIV(key []byte) error {
	ivHash := sha256.Sum256(key)
	// sha256.Sum256 always yields 32 bytes; aes.NewCipher cannot fail here.
	ivBlock, _ := aes.NewCipher(ivHash[:])
	sc.cbcKey = key
	sc.ivKey = ivBlock
	return nil
}

// decryptSector decrypts one sector of ciphertext in-place.
// sectorNum is the logical sector index (for IV derivation).
func (sc *sectorCipher) decryptSector(ct []byte, sectorNum uint64) error {
	if strings.HasPrefix(sc.mode, "xts") {
		sc.xtsEnc.Decrypt(ct, ct, sectorNum)
		return nil
	}
	return sc.cbcDecryptSector(ct, sectorNum)
}

// encryptSector encrypts one sector of plaintext in-place.
func (sc *sectorCipher) encryptSector(pt []byte, sectorNum uint64) error {
	if strings.HasPrefix(sc.mode, "xts") {
		sc.xtsEnc.Encrypt(pt, pt, sectorNum)
		return nil
	}
	return sc.cbcEncryptSector(pt, sectorNum)
}

// cbcDecryptSector decrypts one sector using AES-CBC-ESSIV.
func (sc *sectorCipher) cbcDecryptSector(ct []byte, sectorNum uint64) error {
	iv := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(iv, sectorNum)
	sc.ivKey.Encrypt(iv, iv)
	block, err := aes.NewCipher(sc.cbcKey)
	if err != nil {
		return err
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ct, ct)
	return nil
}

// cbcEncryptSector encrypts one sector using AES-CBC-ESSIV.
func (sc *sectorCipher) cbcEncryptSector(pt []byte, sectorNum uint64) error {
	iv := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(iv, sectorNum)
	sc.ivKey.Encrypt(iv, iv)
	block, err := aes.NewCipher(sc.cbcKey)
	if err != nil {
		return err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(pt, pt)
	return nil
}

// decryptRaw decrypts data spanning an integer number of sectors starting at
// sector 0. If the last sector is partial it is padded to sector size before
// decryption and the result is trimmed back to the original length.
// Used for key-material areas.
func (sc *sectorCipher) decryptRaw(ct []byte) ([]byte, error) {
	ss := sc.sectorSize
	out := make([]byte, len(ct))
	copy(out, ct)
	for i := 0; i*ss < len(out); i++ {
		start := i * ss
		end := start + ss
		if end > len(out) {
			// Pad the last partial sector.
			padded := make([]byte, ss)
			copy(padded, out[start:])
			if err := sc.decryptSector(padded, uint64(i)); err != nil {
				return nil, fmt.Errorf("cipher: decrypt partial sector %d: %w", i, err)
			}
			copy(out[start:], padded[:len(out)-start])
			break
		}
		if err := sc.decryptSector(out[start:end], uint64(i)); err != nil {
			return nil, fmt.Errorf("cipher: decrypt sector %d: %w", i, err)
		}
	}
	return out, nil
}

// encryptRaw encrypts plaintext spanning an integer number of sectors starting
// at sector 0. If the last sector is partial it is padded before encryption.
// Used for key-material areas during LUKS1 formatting.
func (sc *sectorCipher) encryptRaw(pt []byte) ([]byte, error) {
	ss := sc.sectorSize
	out := make([]byte, len(pt))
	copy(out, pt)
	for i := 0; i*ss < len(out); i++ {
		start := i * ss
		end := start + ss
		if end > len(out) {
			padded := make([]byte, ss)
			copy(padded, out[start:])
			if err := sc.encryptSector(padded, uint64(i)); err != nil {
				return nil, fmt.Errorf("cipher: encrypt partial sector %d: %w", i, err)
			}
			copy(out[start:], padded[:len(out)-start])
			break
		}
		if err := sc.encryptSector(out[start:end], uint64(i)); err != nil {
			return nil, fmt.Errorf("cipher: encrypt sector %d: %w", i, err)
		}
	}
	return out, nil
}

// readAt reads and decrypts data from the underlying file at absolute offset
// absOff, where absOff is aligned to the start of the payload. Partial-sector
// reads are handled by decrypting the full sector and slicing.
func (sc *sectorCipher) readAt(f io.ReaderAt, p []byte, absOff int64) (int, error) {
	ss := int64(sc.sectorSize)
	total := 0
	for len(p) > 0 {
		sectorNum := uint64((absOff-sc.fileBase)/ss) + uint64(sc.ivTweak)
		offInSector := int(absOff % ss)
		sector := make([]byte, ss)
		if _, err := f.ReadAt(sector, absOff-int64(offInSector)); err != nil {
			return total, fmt.Errorf("cipher: read sector %d: %w", sectorNum, err)
		}
		if err := sc.decryptSector(sector, sectorNum); err != nil {
			return total, err
		}
		n := copy(p, sector[offInSector:])
		p = p[n:]
		absOff += int64(n)
		total += n
	}
	return total, nil
}

// writeAt encrypts p and writes it to f at absolute offset absOff.
// For partial sectors, the existing sector is read-decrypt-modify-encrypt-write.
func (sc *sectorCipher) writeAt(f io.ReaderAt, p []byte, absOff int64) (int, error) {
	ss := int64(sc.sectorSize)
	type writerAt interface {
		WriteAt([]byte, int64) (int, error)
	}
	fw, ok := f.(writerAt)
	if !ok {
		return 0, fmt.Errorf("cipher: underlying device does not support WriteAt")
	}
	total := 0
	for len(p) > 0 {
		sectorNum := uint64((absOff-sc.fileBase)/ss) + uint64(sc.ivTweak)
		offInSector := int(absOff % ss)
		sector := make([]byte, ss)
		sectorBase := absOff - int64(offInSector)
		if _, err := f.ReadAt(sector, sectorBase); err != nil && !errors.Is(err, io.EOF) {
			return total, fmt.Errorf("cipher: read sector %d for rmw: %w", sectorNum, err)
		}
		if err := sc.decryptSector(sector, sectorNum); err != nil {
			return total, err
		}
		n := copy(sector[offInSector:], p)
		// encryptSector cannot fail here: the key was already accepted by
		// decryptSector above (same symmetric key, same cipher).
		_ = sc.encryptSector(sector, sectorNum)
		if _, err := fw.WriteAt(sector, sectorBase); err != nil {
			return total, fmt.Errorf("cipher: write sector %d: %w", sectorNum, err)
		}
		p = p[n:]
		absOff += int64(n)
		total += n
	}
	return total, nil
}
