// Isolated benchmark module.
//
// This module is intentionally NOT named github.com/go-fde/luks/benchmarks as a
// submodule of the main package; it is a standalone module so that the repo's
// `go test ./...` / `go build ./...` (and therefore the CI coverage gate) never
// descend into it. It reproduces the exact crypto construction used by
// go-fde/luks (golang.org/x/crypto/xts over crypto/aes, plus pbkdf2/argon2) so
// the bulk-XTS and KDF numbers can be regenerated standalone.
module gofde-luks-benchmarks

go 1.25.0

require golang.org/x/crypto v0.50.0

require golang.org/x/sys v0.43.0 // indirect
