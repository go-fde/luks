package luks

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-encryptions/cbc"
	"github.com/go-encryptions/xts"
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
	// cbc-essiv mode: the data cipher, and the ESSIV one (AES-256 keyed by
	// SHA-256 of the data key), both built once.
	cbcEnc *cbc.Cipher
	essiv  *cbc.Cipher
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
	c, err := cbc.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher: cbc init: %w", err)
	}
	ivHash := sha256.Sum256(key)
	// sha256.Sum256 always yields 32 bytes: a valid AES-256 key.
	essiv, _ := cbc.NewCipher(ivHash[:])
	sc.cbcEnc, sc.essiv = c, essiv
	return nil
}

// essivIVs returns the ESSIV IV of each of n sectors from first:
// AES_{SHA-256(K)}(LE128(sector)), 8 blocks at a time.
func (sc *sectorCipher) essivIVs(first uint64, n int) []byte {
	ivs := make([]byte, 16*n)
	for i := range n {
		binary.LittleEndian.PutUint64(ivs[16*i:], first+uint64(i))
	}
	sc.essiv.EncryptECB(ivs, ivs)
	return ivs
}

// decryptSectors decrypts consecutive whole sectors in place; first is the
// IV sector number of buf's first sector. XTS goes through
// xts.DecryptSectors (8 tweaks at a time), CBC through cbc.DecryptSectors
// (8 blocks at a time).
func (sc *sectorCipher) decryptSectors(buf []byte, first uint64) {
	if sc.xtsEnc != nil {
		sc.xtsEnc.DecryptSectors(buf, buf, sc.sectorSize, first)
		return
	}
	sc.cbcEnc.DecryptSectors(buf, buf, sc.sectorSize, sc.essivIVs(first, len(buf)/sc.sectorSize))
}

// encryptSectors is the inverse of decryptSectors. CBC encryption is serial
// within a sector, so each sector is its own call.
func (sc *sectorCipher) encryptSectors(buf []byte, first uint64) {
	if sc.xtsEnc != nil {
		sc.xtsEnc.EncryptSectors(buf, buf, sc.sectorSize, first)
		return
	}
	ss := sc.sectorSize
	ivs := sc.essivIVs(first, len(buf)/ss)
	for i := 0; i < len(buf); i += ss {
		sc.cbcEnc.Encrypt(buf[i:i+ss], buf[i:i+ss], ivs[16*(i/ss):16*(i/ss)+16])
	}
}

// decryptSector decrypts one unit in place: any multiple of 16 bytes,
// shorter than a sector included, with sectorNum's IV, as before. It cannot
// fail once the cipher is built; the error is kept for the callers.
func (sc *sectorCipher) decryptSector(ct []byte, sectorNum uint64) error {
	if sc.xtsEnc != nil {
		sc.xtsEnc.Decrypt(ct, ct, sectorNum)
		return nil
	}
	sc.cbcEnc.Decrypt(ct, ct, sc.essivIVs(sectorNum, 1))
	return nil
}

// encryptSector encrypts one unit in place; see decryptSector.
func (sc *sectorCipher) encryptSector(pt []byte, sectorNum uint64) error {
	if sc.xtsEnc != nil {
		sc.xtsEnc.Encrypt(pt, pt, sectorNum)
		return nil
	}
	sc.cbcEnc.Encrypt(pt, pt, sc.essivIVs(sectorNum, 1))
	return nil
}

// padded copies b into a buffer of whole sectors (the last one padded with
// zeros) and returns it.
func (sc *sectorCipher) padded(b []byte) []byte {
	ss := sc.sectorSize
	out := make([]byte, (len(b)+ss-1)/ss*ss)
	copy(out, b)
	return out
}

// decryptRaw decrypts data spanning sectors from sector 0. A partial last
// sector is padded to the sector size before decryption and the result is
// trimmed back to the original length. Used for key-material areas. It
// cannot fail once the cipher is built.
func (sc *sectorCipher) decryptRaw(ct []byte) ([]byte, error) {
	out := sc.padded(ct)
	sc.decryptSectors(out, 0)
	return out[:len(ct)], nil
}

// encryptRaw encrypts plaintext spanning sectors from sector 0, padding a
// partial last sector. Used for key-material areas during LUKS1 formatting.
func (sc *sectorCipher) encryptRaw(pt []byte) ([]byte, error) {
	out := sc.padded(pt)
	sc.encryptSectors(out, 0)
	return out[:len(pt)], nil
}

// span returns the whole-sector range [start, end) of the file that covers
// [absOff, absOff+n), sectors counted from fileBase, and the IV sector
// number of its first sector.
func (sc *sectorCipher) span(absOff int64, n int) (start, end int64, first uint64) {
	ss := int64(sc.sectorSize)
	rel := absOff - sc.fileBase
	start = sc.fileBase + rel/ss*ss
	end = sc.fileBase + (rel+int64(n)+ss-1)/ss*ss
	first = uint64(rel/ss) + uint64(sc.ivTweak)
	return start, end, first
}

// readAt reads and decrypts data from the underlying file at absolute offset
// absOff (payload-relative sectors start at fileBase). The whole-sector span
// is read with one ReadAt and decrypted in one pass.
func (sc *sectorCipher) readAt(f io.ReaderAt, p []byte, absOff int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	start, end, first := sc.span(absOff, len(p))
	// A read of whole sectors decrypts in the caller's buffer.
	var buf []byte
	if start == absOff && end-start == int64(len(p)) {
		buf = p
	} else {
		buf = make([]byte, end-start)
	}
	got, err := f.ReadAt(buf, start)
	// A short read (the end of the file) still returns the whole sectors
	// it holds, with the error, as the sector-by-sector loop did.
	whole := got / sc.sectorSize * sc.sectorSize
	sc.decryptSectors(buf[:whole], first)
	n := 0
	if skip := int(absOff - start); whole > skip {
		n = copy(p, buf[skip:whole])
	}
	if err != nil && n < len(p) {
		return n, fmt.Errorf("cipher: read sectors from %d: %w", first, err)
	}
	return n, nil
}

// writeAt encrypts p and writes it to f at absolute offset absOff. A
// partial first or last sector is read and decrypted first, so that the
// bytes p does not cover are kept; the whole span is then encrypted in one
// pass and written with one WriteAt.
func (sc *sectorCipher) writeAt(f io.ReaderAt, p []byte, absOff int64) (int, error) {
	type writerAt interface {
		WriteAt([]byte, int64) (int, error)
	}
	fw, ok := f.(writerAt)
	if !ok {
		return 0, fmt.Errorf("cipher: underlying device does not support WriteAt")
	}
	if len(p) == 0 {
		return 0, nil
	}
	ss := int64(sc.sectorSize)
	start, end, first := sc.span(absOff, len(p))
	buf := make([]byte, end-start)
	// The sectors p covers only in part: the first, and the last if it is
	// another one. Past the end of the file they read as zeros (io.EOF).
	rmw := func(at int64) error {
		sec := buf[at-start : at-start+ss]
		if _, err := f.ReadAt(sec, at); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("cipher: read sector %d for rmw: %w", first+uint64((at-start)/ss), err)
		}
		sc.decryptSectors(sec, first+uint64((at-start)/ss))
		return nil
	}
	if absOff != start || end-start == ss && absOff+int64(len(p)) != end {
		if err := rmw(start); err != nil {
			return 0, err
		}
	}
	if last := end - ss; last != start && absOff+int64(len(p)) != end {
		if err := rmw(last); err != nil {
			return 0, err
		}
	}
	copy(buf[absOff-start:], p)
	sc.encryptSectors(buf, first)
	if _, err := fw.WriteAt(buf, start); err != nil {
		return 0, fmt.Errorf("cipher: write sectors from %d: %w", first, err)
	}
	return len(p), nil
}
