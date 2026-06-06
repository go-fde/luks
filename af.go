package luks

import (
	"crypto/hmac"
	"fmt"
)

// afMerge reconstructs the master key from AF-split material.
//
// The LUKS anti-forensic (AF) split stores keyBytes * stripes bytes on disk.
// The first (stripes-1) * keyBytes bytes are random diffusion data; the last
// keyBytes bytes, XOR-combined with the diffusion state, give the actual key.
//
// Algorithm (as per the LUKS specification §5.2.1):
//
//	d[0]   = 0  (zero block, keyBytes wide)
//	d[i+1] = hash_diffuse( d[i] XOR s[i] )   for i in [0, stripes-1)
//	key    = d[stripes-1] XOR s[stripes-1]
func afMerge(afData []byte, keyBytes, stripes int, hashName string) ([]byte, error) {
	if len(afData) < keyBytes*stripes {
		return nil, fmt.Errorf("af: data too short (got %d, want %d)", len(afData), keyBytes*stripes)
	}
	if stripes < 1 {
		return nil, fmt.Errorf("af: stripes must be >= 1")
	}
	d := make([]byte, keyBytes)
	for i := 0; i < stripes-1; i++ {
		stripe := afData[i*keyBytes : (i+1)*keyBytes]
		xorBytes(d, stripe)
		if err := hashDiffuse(d, hashName); err != nil {
			return nil, err
		}
	}
	// Final stripe: XOR without hashing.
	last := afData[(stripes-1)*keyBytes : stripes*keyBytes]
	xorBytes(d, last)
	return d, nil
}

// hashDiffuse applies the LUKS diffusion function to d in-place.
//
// The block d is divided into (blockLen / digestLen) sub-blocks. Each
// sub-block is replaced by HMAC-hash(counter || sub-block) where counter
// is a 4-byte big-endian integer. A partial sub-block at the end is handled
// by taking only the required bytes from the HMAC output.
func hashDiffuse(d []byte, hashName string) error {
	hf, err := hashFactory(hashName)
	if err != nil {
		return err
	}
	digestLen := hf().Size()
	counter := make([]byte, 4)
	pos := 0
	for i := 0; pos < len(d); i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)
		h := hmac.New(hf, counter)
		remaining := len(d) - pos
		chunk := remaining
		if chunk > digestLen {
			chunk = digestLen
		}
		_, _ = h.Write(d[pos : pos+chunk])
		sum := h.Sum(nil)
		copy(d[pos:pos+chunk], sum[:chunk])
		pos += chunk
	}
	return nil
}

// xorBytes XORs src into dst in-place (both must be the same length).
func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// afSplitKey produces the anti-forensic split of key using hashName-based
// diffusion. The output is stripes * len(key) bytes; it is the inverse of
// afMerge.
func afSplitKey(key []byte, stripes int, hashName string) ([]byte, error) {
	klen := len(key)
	out := make([]byte, klen*stripes)
	d := make([]byte, klen)
	for i := 0; i < stripes-1; i++ {
		s := randBytes(klen)
		copy(out[i*klen:], s)
		xorBytes(d, s)
		if err := hashDiffuse(d, hashName); err != nil {
			return nil, err
		}
	}
	last := out[(stripes-1)*klen : stripes*klen]
	copy(last, d)
	xorBytes(last, key)
	return out, nil
}
