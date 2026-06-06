package luks

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// luks2BinHdr is the fixed binary superblock that precedes the JSON area.
// Size: 512 bytes (the checksum-protected part is 448 bytes; full block is 4096).
type luks2BinHdr struct {
	hdrSize  uint64 // total size of BOTH header copies
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

// parseLUKS2BinHdr reads the LUKS2 binary superblock.
func parseLUKS2BinHdr(f io.ReaderAt) (*luks2BinHdr, error) {
	buf := make([]byte, luks2BinHdrSize)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("luks2: read binary hdr: %w", err)
	}
	h := &luks2BinHdr{
		hdrSize:  binary.BigEndian.Uint64(buf[8:16]),
		seqID:    binary.BigEndian.Uint64(buf[16:24]),
		checkAlg: nullStr(buf[72:104]),
		uuid:     nullStr(buf[168:208]),
	}
	copy(h.salt[:], buf[104:168])
	return h, nil
}

// parseLUKS2JSON reads and decodes the JSON configuration area from f.
func parseLUKS2JSON(f io.ReaderAt, binHdr *luks2BinHdr) (*luks2JSON, error) {
	jsonStart := int64(luks2BinHdrSize)
	jsonEnd := int64(binHdr.hdrSize/2) - int64(luks2BinHdrSize)
	if jsonEnd <= 0 || jsonEnd > 1<<20 {
		return nil, fmt.Errorf("luks2: implausible JSON area size %d", jsonEnd)
	}
	buf := make([]byte, jsonEnd)
	if _, err := f.ReadAt(buf, jsonStart); err != nil {
		return nil, fmt.Errorf("luks2: read JSON area: %w", err)
	}
	// JSON is null-padded; trim at first null.
	for i, c := range buf {
		if c == 0 {
			buf = buf[:i]
			break
		}
	}
	var cfg luks2JSON
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("luks2: parse JSON: %w", err)
	}
	return &cfg, nil
}

// unlockLUKS2 tries each key slot with passphrase and returns a luksHeader.
func unlockLUKS2(f io.ReaderAt, passphrase []byte) (*luksHeader, error) {
	binHdr, err := parseLUKS2BinHdr(f)
	if err != nil {
		return nil, err
	}
	cfg, err := parseLUKS2JSON(f, binHdr)
	if err != nil {
		return nil, err
	}
	seg, payloadOff, sectorSize, cipher, err := parseMainSegment(cfg)
	if err != nil {
		return nil, err
	}
	ivTweak, err := parseIVTweak(seg.IVTweak)
	if err != nil {
		return nil, fmt.Errorf("luks2: iv_tweak: %w", err)
	}
	for _, slot := range cfg.Keyslots {
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
			cipher:     cipher,
			sectorSize: sectorSize,
			ivTweak:    ivTweak,
		}, nil
	}
	return nil, fmt.Errorf("luks2: no key slot matches passphrase")
}

// parseMainSegment extracts the payload offset, sector size and cipher from
// the first "crypt" segment.
func parseMainSegment(cfg *luks2JSON) (luks2Segment, int64, int, string, error) {
	for _, seg := range cfg.Segments {
		if seg.Type != "crypt" {
			continue
		}
		off, err := parseOffset(seg.Offset)
		if err != nil {
			return seg, 0, 0, "", fmt.Errorf("luks2: parse segment offset: %w", err)
		}
		ss := seg.SectorSize
		if ss == 0 {
			ss = 512
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
		return pbkdf2.Key(passphrase, slot.KDF.Salt, slot.KDF.Iterations, keyLen, hf), nil
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
		computed := pbkdf2.Key(mk, d.Salt, d.Iterations, len(d.Digest), hf)
		match := true
		for i, b := range computed {
			if b != d.Digest[i] {
				match = false
				break
			}
		}
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

// parseIVTweak parses a LUKS2 iv_tweak string (decimal sector number).
// An empty string returns 0 (the default).
func parseIVTweak(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	return parseOffset(s)
}
