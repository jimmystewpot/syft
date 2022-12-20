package golang

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseGoMod(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/one-package",
			expected: []pkg.Package{
				{
					Name:         "github.com/bmatcuk/doublestar",
					Version:      "v1.3.1",
					PURL:         "pkg:golang/github.com/bmatcuk/doublestar@v1.3.1",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/one-package")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
			},
		},
		{

			fixture: "test-fixtures/many-packages",
			expected: []pkg.Package{
				{
					Name:         "github.com/anchore/go-testutils",
					Version:      "v0.0.0-20200624184116-66aa578126db",
					PURL:         "pkg:golang/github.com/anchore/go-testutils@v0.0.0-20200624184116-66aa578126db",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
				{
					Name:         "github.com/anchore/go-version",
					Version:      "v1.2.2-0.20200701162849-18adb9c92b9b",
					PURL:         "pkg:golang/github.com/anchore/go-version@v1.2.2-0.20200701162849-18adb9c92b9b",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
				{
					Name:         "github.com/anchore/stereoscope",
					Version:      "v0.0.0-20200706164556-7cf39d7f4639",
					PURL:         "pkg:golang/github.com/anchore/stereoscope@v0.0.0-20200706164556-7cf39d7f4639",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
				{
					Name:         "github.com/bmatcuk/doublestar",
					Version:      "v8.8.8",
					PURL:         "pkg:golang/github.com/bmatcuk/doublestar@v8.8.8",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
				{
					Name:         "github.com/go-test/deep",
					Version:      "v1.0.6",
					PURL:         "pkg:golang/github.com/go-test/deep@v1.0.6",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromFile(t, test.fixture).
				Expects(test.expected, nil).
				TestParser(t, parseGoModFile)
		})
	}
}

func Test_GoSumHashes(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/go-sum-hashes",
			expected: []pkg.Package{
				{
					Name:         "github.com/CycloneDX/cyclonedx-go",
					Version:      "v0.6.0",
					PURL:         "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0",
					Locations:    source.NewLocationSet(source.NewLocation("go.mod")),
					FoundBy:      "go-mod-file-cataloger",
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata:     pkg.GolangMetadata{},
				},
				{
					Name:         "github.com/acarl005/stripansi",
					Version:      "v0.0.0-20180116102854-5a71ef0e047d",
					PURL:         "pkg:golang/github.com/acarl005/stripansi@v0.0.0-20180116102854-5a71ef0e047d",
					Locations:    source.NewLocationSet(source.NewLocation("go.mod")),
					FoundBy:      "go-mod-file-cataloger",
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata: pkg.GolangMetadata{
						H1Digest: "h1:licZJFw2RwpHMqeKTCYkitsPqHNxTmd4SNR5r94FGM8=",
					},
				},
				{
					Name:         "github.com/mgutz/ansi",
					Version:      "v0.0.0-20200706080929-d51e80ef957d",
					PURL:         "pkg:golang/github.com/mgutz/ansi@v0.0.0-20200706080929-d51e80ef957d",
					Locations:    source.NewLocationSet(source.NewLocation("go.mod")),
					FoundBy:      "go-mod-file-cataloger",
					Language:     pkg.Go,
					Type:         pkg.GoModulePkg,
					MetadataType: pkg.GolangMetadataType,
					Metadata: pkg.GolangMetadata{
						H1Digest: "h1:5PJl274Y63IEHC+7izoQE9x6ikvDFZS2mDVS3drnohI=",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expected, nil).
				TestCataloger(t, NewGoModFileCataloger())
		})
	}
}
