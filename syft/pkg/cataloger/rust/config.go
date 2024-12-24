package rust

const (
	directProxyOnly = "direct"
)

var (
	directProxiesOnly = []string{directProxyOnly}
)

type CatalogerConfig struct {
	SearchLocalCargoLicenses bool     `yaml:"search-local-cargo-licenses" json:"search-local-cargo-licenses" mapstructure:"search-local-cargo-licenses"`
	SearchRemoteLicenses     bool     `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxies                  []string `yaml:"proxies,omitempty" json:"proxies,omitempty" mapstructure:"proxies"`
	NoProxy                  []string `yaml:"no-proxy,omitempty" json:"no-proxy,omitempty" mapstructure:"no-proxy"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		SearchLocalCargoLicenses: true,
		SearchRemoteLicenses:     false,
	}
}

func (g CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	g.SearchRemoteLicenses = input
	return g
}
