// Package luks provides pure-Go support for LUKS1 and LUKS2 full-disk encryption.
//
// Supported:
//   - LUKS version 1 (key derivation: PBKDF2; ciphers: aes-xts-plain64, aes-cbc-essiv:sha256)
//   - LUKS version 2 (key derivation: PBKDF2 and Argon2id/i; ciphers: aes-xts-plain64)
//
// Usage:
//
//	dev, err := luks.Open("/dev/sdb", []byte("passphrase"))
//	if err != nil { log.Fatal(err) }
//	defer dev.Close()
//	// use dev.ReadAt / dev.WriteAt to access plaintext payload
package luks

import (
	"fmt"
	"io"
	"os"
)

// blockRW is the interface expected from any underlying block device.
type blockRW interface {
	io.ReaderAt
	WriteAt([]byte, int64) (int, error)
	io.Closer
}

// luksHeader is the common result of parsing either LUKS1 or LUKS2.
type luksHeader struct {
	version    int
	volumeKey  []byte
	payloadOff int64 // byte offset of the plaintext payload
	payloadLen int64 // 0 = extends to end of device
	cipher     string
	sectorSize int
	// ivTweak is the logical sector number of the first payload sector, used as
	// the starting offset for IV computation. Always 0 for LUKS1. LUKS2 may set
	// a non-zero value via the segment's iv_tweak field.
	ivTweak int64
}

// Device is an unlocked LUKS device. Its ReadAt and WriteAt methods
// transparently decrypt/encrypt the payload using the volume key.
type Device struct {
	f   blockRW
	h   luksHeader
	enc *sectorCipher
}

// Open opens the LUKS1 or LUKS2 container at path and unlocks it using
// passphrase. Returns a Device that exposes the plaintext payload.
func Open(path string, passphrase []byte) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("luks: open %s: %w", path, err)
	}
	dev, err := openDevice(f, passphrase)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

// OpenFrom unlocks a LUKS container from any read-write-closable block device.
// This allows LUKS to be layered on top of e.g. a QCOW2 device.
// The caller is responsible for ensuring that rw remains valid for the
// lifetime of the returned Device; Close on the Device also closes rw.
func OpenFrom(rw blockRW, passphrase []byte) (*Device, error) {
	return openDevice(rw, passphrase)
}

// openDevice is the shared implementation for Open and OpenFrom.
func openDevice(rw blockRW, passphrase []byte) (*Device, error) {
	h, err := unlock(rw, passphrase)
	if err != nil {
		return nil, err
	}
	enc, err := newSectorCipher(h.cipher, h.volumeKey, h.sectorSize)
	if err != nil {
		return nil, fmt.Errorf("luks: cipher setup: %w", err)
	}
	// Configure the cipher so IV sector numbers are relative to the payload
	// start and respect the LUKS2 iv_tweak offset.
	enc.fileBase = h.payloadOff
	enc.ivTweak = h.ivTweak
	return &Device{f: rw, h: *h, enc: enc}, nil
}

// Detect returns true if the file at path begins with a LUKS header magic.
func Detect(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(f, buf); err != nil {
		return false, nil
	}
	return string(buf) == luksHeaderMagic, nil
}

// ReadAt reads decrypted data from the plaintext payload starting at off.
// off is relative to the start of the payload (sector 0 of the plaintext).
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	return d.enc.readAt(d.f, p, d.h.payloadOff+off)
}

// WriteAt encrypts p and writes it to the payload starting at off.
// off is relative to the start of the payload.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	return d.enc.writeAt(d.f, p, d.h.payloadOff+off)
}

// Size returns the size of the plaintext payload in bytes.
// Returns 0 if the size was not determined from the header (dynamic).
func (d *Device) Size() int64 { return d.h.payloadLen }

// Close releases the underlying file descriptor.
func (d *Device) Close() error { return d.f.Close() }

// unlock detects the LUKS version and dispatches to the appropriate parser.
func unlock(f blockRW, passphrase []byte) (*luksHeader, error) {
	magic := make([]byte, 8)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("luks: read header: %w", err)
	}
	if string(magic[:6]) != luksHeaderMagic {
		return nil, fmt.Errorf("luks: not a LUKS device (bad magic)")
	}
	version := int(magic[6])<<8 | int(magic[7])
	switch version {
	case 1:
		return unlockLUKS1(f, passphrase)
	case 2:
		return unlockLUKS2(f, passphrase)
	default:
		return nil, fmt.Errorf("luks: unsupported version %d", version)
	}
}
