package options

type java struct {
	UseNetwork              bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	MavenURL                string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
	MaxParentRecursiveDepth int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
	UseParentPomVersion     bool   `yaml:"use-parent-pom-version" json:"use-parent-pom-version" mapstructure:"use-parent-pom-version"`
}
