package luks

import (
	"errors"
	"fmt"
)

// Limits bound the work a header may make Open do. A header is read from
// the image, so it is untrusted: without bounds a key slot can ask for 2^32
// PBKDF2 iterations (hours), 4 TiB of Argon2 memory (2^32 KiB), or zero
// Argon2 rounds or threads (a panic in golang.org/x/crypto/argon2).
//
// Two kinds of bound:
//
//   - Structural, always enforced, from cryptsetup's own limits for the
//     KDFs it writes (lib/crypto_backend/pbkdf_check.c,
//     crypt_pbkdf_get_limits): Argon2 memory at most 4 GiB and 1 to 4
//     threads (and Argon2's own floor of 8 KiB per thread); at least one
//     iteration; and the anti-forensic split of a
//     key slot at most 4000 stripes (LUKS1 and LUKS2 headers use 4000) of
//     a key of at most 128 bytes.
//   - Cost, chosen by the caller: cryptsetup accepts up to 2^32 iterations
//     because it trusts headers it wrote; a program opening images from
//     elsewhere -- an upload, a browser -- should not. DefaultLimits are
//     generous enough for headers calibrated on fast machines.
type Limits struct {
	// MaxPBKDF2Iterations bounds a PBKDF2 key slot's iterations and a
	// master-key digest's.
	MaxPBKDF2Iterations uint32
	// MaxArgon2Time bounds an Argon2 key slot's passes.
	MaxArgon2Time uint32
	// MaxArgon2MemoryKiB bounds an Argon2 key slot's memory; at most
	// argon2MaxMemoryKiB whatever it says.
	MaxArgon2MemoryKiB uint32
}

// DefaultLimits are what Open and OpenFrom use.
var DefaultLimits = Limits{
	MaxPBKDF2Iterations: 1 << 26,
	MaxArgon2Time:       1000,
	MaxArgon2MemoryKiB:  argon2MaxMemoryKiB,
}

// Structural limits (cryptsetup's).
const (
	// argon2MinMemoryKiB is Argon2's own floor (RFC 9106 §3.1: at least
	// 8 KiB per lane, checked against the threads below), not cryptsetup's
	// 32 KiB, which is what it writes rather than what a header may hold.
	argon2MinMemoryKiB = 8
	argon2MaxMemoryKiB = 4 << 20 // 4 GiB
	argon2MaxThreads   = 4
	maxStripes         = 4000
	maxKeyBytes        = 128
	maxDigestBytes     = 64
)

// ErrLimit is a key slot or digest whose parameters a Limits refuses.
var ErrLimit = errors.New("luks: the header asks for more than the limits allow")

func (l Limits) pbkdf2(what string, iter int64) error {
	switch {
	case iter < 1:
		return fmt.Errorf("%w: %s: %d PBKDF2 iterations", ErrLimit, what, iter)
	case iter > int64(l.MaxPBKDF2Iterations):
		return fmt.Errorf("%w: %s: %d PBKDF2 iterations, at most %d", ErrLimit, what, iter, l.MaxPBKDF2Iterations)
	}
	return nil
}

func (l Limits) argon2(time, memKiB, threads int64) error {
	maxMem := int64(min(l.MaxArgon2MemoryKiB, argon2MaxMemoryKiB))
	switch {
	case time < 1 || time > int64(l.MaxArgon2Time):
		return fmt.Errorf("%w: %d Argon2 passes (1 to %d)", ErrLimit, time, l.MaxArgon2Time)
	case memKiB < argon2MinMemoryKiB || memKiB > maxMem:
		return fmt.Errorf("%w: %d KiB of Argon2 memory (%d to %d)", ErrLimit, memKiB, argon2MinMemoryKiB, maxMem)
	case threads < 1 || threads > argon2MaxThreads:
		return fmt.Errorf("%w: %d Argon2 threads (1 to %d)", ErrLimit, threads, argon2MaxThreads)
	case memKiB < 8*threads:
		return fmt.Errorf("%w: %d KiB of Argon2 memory for %d threads", ErrLimit, memKiB, threads)
	}
	return nil
}

// split bounds a key slot's anti-forensic material: keyBytes * stripes
// bytes are read and allocated.
func split(keyBytes, stripes int64) error {
	if keyBytes < 1 || keyBytes > maxKeyBytes || stripes < 1 || stripes > maxStripes {
		return fmt.Errorf("%w: a key of %d bytes split in %d stripes (1 to %d bytes, 1 to %d stripes)",
			ErrLimit, keyBytes, stripes, maxKeyBytes, maxStripes)
	}
	return nil
}

// OpenLimited is Open with lim instead of DefaultLimits.
func OpenLimited(path string, passphrase []byte, lim Limits) (*Device, error) {
	return open(path, passphrase, lim)
}

// OpenFromLimited is OpenFrom with lim instead of DefaultLimits.
func OpenFromLimited(rw blockRW, passphrase []byte, lim Limits) (*Device, error) {
	return openDevice(rw, passphrase, lim)
}
