package luks

import (
	"encoding/binary"
	"hash"
)

// sealLUKS2 writes the header checksum of the LUKS2 header copy at the start of
// img: the hash named by csum_alg over hdr_size bytes with the csum field
// zeroed, stored in the csum field. Test builders call it once the header is
// final, as cryptsetup does on every header write.
func sealLUKS2(img []byte) { sealLUKS2At(img, 0) }

// sealLUKS2At seals the header copy that starts at off.
func sealLUKS2At(img []byte, off int) {
	raw := img[off : off+int(binary.BigEndian.Uint64(img[off+8:off+16]))]
	hf, err := hashFactory(nullStr(raw[72:104]))
	if err != nil {
		panic(err)
	}
	clear(raw[luks2CsumOff : luks2CsumOff+luks2CsumLen])
	var h hash.Hash = hf()
	h.Write(raw)
	copy(raw[luks2CsumOff:], h.Sum(nil))
}
