package luks

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/go-encryptions/hmac"
	"golang.org/x/crypto/argon2"
)

// luks2BinHdr is the fixed binary superblock that precedes the JSON area.
// Size: 512 bytes (the checksum-protected part is 448 bytes; full block is 4096).
type luks2BinHdr struct {
	hdrSize  uint64 // size of ONE header copy: binary header + JSON area
	seqID    uint64
	checkAlg string // "sha256" etc.
	salt     [64]byte
	uuid     string
}

// luks2JSON is the decoded JSON configuration area.
type luks2JSON struct {
	Keyslots map[string]luks2Keyslot `json:"keyslots"`
	Segments map[string]luks2Segment `json:"segments"`
	Digests  map[string]luks2Digest  `json:"digests"`
}

type luks2Keyslot struct {
	Type    string       `json:"type"`
	KeySize int          `json:"key_size"`
	KDF     luks2KDF     `json:"kdf"`
	AF      luks2AF      `json:"af"`
	Area    luks2KeyArea `json:"area"`
}

type luks2KDF struct {
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	Time       int    `json:"time"`
	Memory     int    `json:"memory"`
	CPUs       int    `json:"cpus"`
	Salt       []byte `json:"salt"`
}

type luks2AF struct {
	Type    string `json:"type"`
	Stripes int    `json:"stripes"`
	Hash    string `json:"hash"`
}

type luks2KeyArea struct {
	Type       string `json:"type"`
	Offset     string `json:"offset"`
	Size       string `json:"size"`
	Encryption string `json:"encryption"`
	KeySize    int    `json:"key_size"`
}

type luks2Segment struct {
	Type       string `json:"type"`
	Offset     string `json:"offset"`
	Size       string `json:"size"`
	Encryption string `json:"encryption"`
	SectorSize int    `json:"sector_size"`
	IVTweak    string `json:"iv_tweak"`
}

type luks2Digest struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Hash       string   `json:"hash"`
	Iterations int      `json:"iterations"`
	Salt       []byte   `json:"salt"`
	Digest     []byte   `json:"digest"`
}

const luks2BinHdrSize = 4096 // size of the binary superblock block

const (
	luks2CsumOff        = 448 // the 64-byte csum field in the binary header
	luks2CsumLen        = 64
	luks2MagicPrimary   = "LUKS\xba\xbe"
	luks2MagicSecondary = "SKUL\xba\xbe"
)

// luks2StandardHdrSizes are the header sizes the format defines (16 KiB to
// 4 MiB); the secondary header of a device whose primary is unreadable can
// only be at one of them (LUKS2 on-disk format, section 2.1).
var luks2StandardHdrSizes = []uint64{
	1 << 14, 1 << 15, 1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20, 1 << 21, 1 << 22,
}

// luks2Copy is one verified copy of the header (primary or secondary).
type luks2Copy struct {
	bin *luks2BinHdr
	cfg *luks2JSON
}

// loadLUKS2Copy reads the header copy at off, checks its magic, its hdr_size
// and its checksum, and decodes it. size is the expected hdr_size; 0 takes it
// from the copy's own binary header (the primary case).
//
// hdr_size is the size of ONE header, binary header included; the JSON area is
// hdr_size - 4096 (LUKS2 on-disk format, sections 2.1 and 2.2), and the
// checksum covers all hdr_size bytes with the csum field zeroed.
func loadLUKS2Copy(f io.ReaderAt, off int64, size uint64, magic string) (*luks2Copy, error) {
	if size == 0 {
		var first [16]byte
		if _, err := f.ReadAt(first[:], off); err != nil {
			return nil, fmt.Errorf("luks2: read binary hdr: %w", err)
		}
		size = binary.BigEndian.Uint64(first[8:16])
	}
	if size <= luks2BinHdrSize || size-luks2BinHdrSize > 1<<22 {
		return nil, fmt.Errorf("luks2: implausible JSON area size %d", int64(size)-luks2BinHdrSize)
	}
	raw := make([]byte, size)
	if _, err := f.ReadAt(raw, off); err != nil {
		return nil, fmt.Errorf("luks2: read header: %w", err)
	}
	if string(raw[:6]) != magic {
		return nil, fmt.Errorf("luks2: bad header magic at offset %d", off)
	}
	if got := binary.BigEndian.Uint64(raw[8:16]); got != size {
		return nil, fmt.Errorf("luks2: header at offset %d states hdr_size %d, want %d", off, got, size)
	}
	bin := &luks2BinHdr{
		hdrSize:  size,
		seqID:    binary.BigEndian.Uint64(raw[16:24]),
		checkAlg: nullStr(raw[72:104]),
		uuid:     nullStr(raw[168:208]),
	}
	copy(bin.salt[:], raw[104:168])
	if err := verifyLUKS2Checksum(raw, bin.checkAlg); err != nil {
		return nil, err
	}
	cfg, err := decodeLUKS2JSON(raw[luks2BinHdrSize:])
	if err != nil {
		return nil, err
	}
	return &luks2Copy{bin: bin, cfg: cfg}, nil
}

// verifyLUKS2Checksum recomputes the header checksum over raw (one whole
// header copy) with the csum field zeroed and compares it with the stored one.
func verifyLUKS2Checksum(raw []byte, alg string) error {
	if alg == "" {
		return fmt.Errorf("luks2: header has no checksum algorithm")
	}
	hf, err := hashFactory(alg)
	if err != nil {
		return fmt.Errorf("luks2: checksum algorithm: %w", err)
	}
	// Every digest hashFactory returns is at most luks2CsumLen (64) bytes.
	h := hf()
	h.Write(raw[:luks2CsumOff])
	h.Write(make([]byte, luks2CsumLen))
	h.Write(raw[luks2CsumOff+luks2CsumLen:])
	if !bytes.Equal(h.Sum(nil), raw[luks2CsumOff:luks2CsumOff+h.Size()]) {
		return fmt.Errorf("luks2: header checksum mismatch")
	}
	return nil
}

// decodeLUKS2JSON decodes the null-padded JSON configuration area.
func decodeLUKS2JSON(area []byte) (*luks2JSON, error) {
	if i := bytes.IndexByte(area, 0); i >= 0 {
		area = area[:i]
	}
	var cfg luks2JSON
	if err := json.Unmarshal(area, &cfg); err != nil {
		return nil, fmt.Errorf("luks2: parse JSON: %w", err)
	}
	return &cfg, nil
}

// readLUKS2Header returns the header to use: of the primary copy (offset 0) and
// the secondary copy (offset hdr_size) it takes the one whose checksum
// verifies, the higher seqid when both do (the secondary is the older one
// after an interrupted update, the newer after a failed primary write), and
// refuses when neither does. When the primary is unreadable its hdr_size is
// not trusted either, so the secondary is looked for at every standard size.
func readLUKS2Header(f io.ReaderAt) (*luks2Copy, error) {
	primary, perr := loadLUKS2Copy(f, 0, 0, luks2MagicPrimary)
	var sizes []uint64
	if perr == nil {
		sizes = []uint64{primary.bin.hdrSize}
	} else {
		var first [16]byte
		if _, err := f.ReadAt(first[:], 0); err == nil {
			sizes = append(sizes, binary.BigEndian.Uint64(first[8:16]))
		}
		sizes = append(sizes, luks2StandardHdrSizes...)
	}
	var secondary *luks2Copy
	for _, size := range sizes {
		if size == 0 || size > math.MaxInt64 {
			continue
		}
		if c, err := loadLUKS2Copy(f, int64(size), size, luks2MagicSecondary); err == nil {
			secondary = c
			break
		}
	}
	switch {
	case primary != nil && (secondary == nil || secondary.bin.seqID <= primary.bin.seqID):
		return primary, nil
	case secondary != nil:
		return secondary, nil
	}
	return nil, perr
}

// unlockLUKS2 tries each key slot with passphrase and returns a luksHeader.
func unlockLUKS2(f io.ReaderAt, passphrase []byte, lim Limits) (*luksHeader, error) {
	hdr, err := readLUKS2Header(f)
	if err != nil {
		return nil, err
	}
	cfg := hdr.cfg
	seg, payloadOff, sectorSize, cipher, err := parseMainSegment(cfg)
	if err != nil {
		return nil, err
	}
	ivTweak, err := parseIVTweak(seg.IVTweak)
	if err != nil {
		return nil, fmt.Errorf("luks2: iv_tweak: %w", err)
	}
	payloadLen, err := parseSegmentSize(seg.Size)
	if err != nil {
		return nil, fmt.Errorf("luks2: segment size: %w", err)
	}
	if payloadLen%int64(sectorSize) != 0 {
		return nil, fmt.Errorf("luks2: segment size %d is not a multiple of sector_size %d", payloadLen, sectorSize)
	}
	if err := checkLUKS2Digests(cfg, lim); err != nil {
		return nil, fmt.Errorf("luks2: %w", err)
	}
	var refused error // the first slot the limits refused, said if none opens
	for name, slot := range cfg.Keyslots {
		if err := checkLUKS2Slot(&slot, lim); err != nil {
			if refused == nil {
				refused = fmt.Errorf("luks2: key slot %v: %w", name, err)
			}
			continue
		}
		mk, err := tryLUKS2Slot(f, &slot, passphrase)
		if err != nil {
			continue
		}
		if err := verifyLUKS2MasterKey(mk, cfg); err != nil {
			continue
		}
		return &luksHeader{
			version:    2,
			volumeKey:  mk,
			payloadOff: payloadOff,
			payloadLen: payloadLen,
			cipher:     cipher,
			sectorSize: sectorSize,
			ivTweak:    ivTweak,
		}, nil
	}
	if refused != nil {
		return nil, refused
	}
	return nil, fmt.Errorf("luks2: no key slot matches passphrase")
}

// checkLUKS2Slot refuses a key slot whose parameters exceed lim, before any
// work is done for it.
func checkLUKS2Slot(slot *luks2Keyslot, lim Limits) error {
	if slot.Area.KeySize < 0 || slot.Area.KeySize > maxKeyBytes {
		return fmt.Errorf("%w: a key area key of %d bytes", ErrLimit, slot.Area.KeySize)
	}
	if err := split(int64(slot.KeySize), int64(slot.AF.Stripes)); err != nil {
		return err
	}
	switch slot.KDF.Type {
	case "pbkdf2":
		return lim.pbkdf2("key slot", int64(slot.KDF.Iterations))
	case "argon2i", "argon2id":
		return lim.argon2(int64(slot.KDF.Time), int64(slot.KDF.Memory), int64(slot.KDF.CPUs))
	}
	return nil // an unknown KDF is refused by deriveKeyLUKS2
}

// checkLUKS2Digests bounds every master-key digest: each candidate key is
// checked against all of them.
func checkLUKS2Digests(cfg *luks2JSON, lim Limits) error {
	for _, d := range cfg.Digests {
		if d.Type != "pbkdf2" {
			continue
		}
		if len(d.Digest) == 0 || len(d.Digest) > maxDigestBytes {
			return fmt.Errorf("%w: a digest of %d bytes", ErrLimit, len(d.Digest))
		}
		if err := lim.pbkdf2("master-key digest", int64(d.Iterations)); err != nil {
			return err
		}
	}
	return nil
}

// parseMainSegment extracts the payload offset, sector size and cipher from
// the first "crypt" segment.
func parseMainSegment(cfg *luks2JSON) (luks2Segment, int64, int, string, error) {
	for _, seg := range cfg.Segments {
		if seg.Type != "crypt" {
			continue
		}
		off, err := parseOffset(seg.Offset)
		if err == nil && off < 0 {
			err = fmt.Errorf("negative offset %d", off)
		}
		if err != nil {
			return seg, 0, 0, "", fmt.Errorf("luks2: parse segment offset: %w", err)
		}
		ss := seg.SectorSize
		if ss == 0 {
			ss = 512
		}
		// cryptsetup accepts exactly these (lib/luks2/luks2_json_format.c);
		// anything else panics the XTS library or allocates without bound.
		switch ss {
		case 512, 1024, 2048, 4096:
		default:
			return seg, 0, 0, "", fmt.Errorf("luks2: unsupported sector_size %d (512, 1024, 2048 or 4096)", ss)
		}
		if off%int64(ss) != 0 {
			return seg, 0, 0, "", fmt.Errorf("luks2: segment offset %d is not a multiple of sector_size %d", off, ss)
		}
		return seg, off, ss, seg.Encryption, nil
	}
	return luks2Segment{}, 0, 0, "", fmt.Errorf("luks2: no crypt segment found")
}

// tryLUKS2Slot derives the slot key, decrypts the key material, and AF-merges.
func tryLUKS2Slot(f io.ReaderAt, slot *luks2Keyslot, passphrase []byte) ([]byte, error) {
	slotKey, err := deriveKeyLUKS2(slot, passphrase)
	if err != nil {
		return nil, err
	}
	areaOff, err := parseOffset(slot.Area.Offset)
	if err != nil {
		return nil, fmt.Errorf("luks2: parse area offset: %w", err)
	}
	afSize := slot.KeySize * slot.AF.Stripes
	if afSize <= 0 {
		return nil, fmt.Errorf("luks2: invalid af size")
	}
	afData := make([]byte, afSize)
	if _, err := f.ReadAt(afData, areaOff); err != nil {
		return nil, fmt.Errorf("luks2: read key area: %w", err)
	}
	enc, err := newSectorCipher(slot.Area.Encryption, slotKey[:slot.Area.KeySize], 512)
	if err != nil {
		return nil, fmt.Errorf("luks2: cipher for key area: %w", err)
	}
	plain, err := enc.decryptRaw(afData)
	if err != nil {
		return nil, err
	}
	hashName := slot.AF.Hash
	if hashName == "" {
		hashName = "sha256"
	}
	return afMerge(plain, slot.KeySize, slot.AF.Stripes, hashName)
}

// deriveKeyLUKS2 runs the KDF for a LUKS2 key slot.
func deriveKeyLUKS2(slot *luks2Keyslot, passphrase []byte) ([]byte, error) {
	keyLen := slot.Area.KeySize
	if keyLen == 0 {
		keyLen = slot.KeySize
	}
	switch slot.KDF.Type {
	case "pbkdf2":
		hf, err := hashFactory(slot.KDF.Hash)
		if err != nil {
			return nil, fmt.Errorf("luks2: pbkdf2: %w", err)
		}
		return hmac.PBKDF2(hf, passphrase, slot.KDF.Salt, slot.KDF.Iterations, keyLen)
	case "argon2i":
		return argon2.Key(passphrase, slot.KDF.Salt, uint32(slot.KDF.Time),
			uint32(slot.KDF.Memory), uint8(slot.KDF.CPUs), uint32(keyLen)), nil
	case "argon2id":
		return argon2.IDKey(passphrase, slot.KDF.Salt, uint32(slot.KDF.Time),
			uint32(slot.KDF.Memory), uint8(slot.KDF.CPUs), uint32(keyLen)), nil
	default:
		return nil, fmt.Errorf("luks2: unsupported KDF %q", slot.KDF.Type)
	}
}

// verifyLUKS2MasterKey checks mk against every PBKDF2 digest in the JSON.
func verifyLUKS2MasterKey(mk []byte, cfg *luks2JSON) error {
	for _, d := range cfg.Digests {
		if d.Type != "pbkdf2" {
			continue
		}
		hf, err := hashFactory(d.Hash)
		if err != nil {
			continue
		}
		computed, err := hmac.PBKDF2(hf, mk, d.Salt, d.Iterations, len(d.Digest))
		if err != nil {
			continue
		}
		match := true
		for i, b := range computed {
			if b != d.Digest[i] {
				match = false
				break
			}
		}
		clear(computed)
		if match {
			return nil
		}
	}
	return fmt.Errorf("luks2: master key digest mismatch")
}

// parseOffset converts a JSON string offset (decimal bytes) to int64.
func parseOffset(s string) (int64, error) {
	var v int64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("invalid offset %q: %w", s, err)
	}
	return v, nil
}

// parseSegmentSize parses a LUKS2 segment size: a decimal byte count, or
// "dynamic" for a segment that runs to the end of the device, which is 0
// here as in cryptsetup's json_segment_get_size (lib/luks2/luks2_segment.c).
func parseSegmentSize(s string) (int64, error) {
	if s == "" || s == "dynamic" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return v, nil
}

// parseIVTweak parses a LUKS2 iv_tweak string (decimal sector number).
// An empty string returns 0 (the default).
func parseIVTweak(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	return parseOffset(s)
}
