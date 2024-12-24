package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
)

type rustConfig struct {
	SearchLocalCargoLicenses *bool `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	SearchRemoteLicenses     *bool `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
}

var _ interface {
	clio.FieldDescriber
} = (*rustConfig)(nil)

func (o *rustConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchLocalCargoLicenses, `search for rust package licences in the Cargo.toml file of the system running Syft, note that this is outside the
container filesystem and potentially outside the root of a local directory scan`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for rust package licences by retrieving the package from a network proxy`)
}

func defaultRustConfig() rustConfig {
	def := rust.DefaultCatalogerConfig()
	return rustConfig{
		SearchRemoteLicenses:     &def.SearchRemoteLicenses,
		SearchLocalCargoLicenses: &def.SearchLocalCargoLicenses,
	}
}
