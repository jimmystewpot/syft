/*
Package rust provides a concrete Cataloger implementation relating to packages within the Rust language ecosystem.
*/
package rust

import (
	"regexp"

	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	cargoAuditBinaryCatalogerName = "cargo-auditable-binary-cataloger"
	cargoLockCatalogerName        = "cargo-lock-cataloger"
)

var (
	crateLicenseRegex = regexp.MustCompile(`(?P<license>\S+)`)
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger() pkg.Cataloger {
	return generic.NewCataloger(cargoLockCatalogerName).
		WithParserByGlobs(parseCargoLock, "**/Cargo.lock")
}

// NewAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewAuditBinaryCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(cargoAuditBinaryCatalogerName).
		WithParserByMimeTypes(
			newCargoAuditBinaryCataloger(opts).parseAuditBinary,
			mimetype.ExecutableMIMETypeSet.List()...,
		)
}
