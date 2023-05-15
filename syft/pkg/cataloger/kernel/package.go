package kernel

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const linuxKernelPackageName = "linux-kernel"

func newLinuxKernelPackage(metadata pkg.LinuxKernelMetadata, archiveLocation source.Location) pkg.Package {
	p := pkg.Package{
		Name:         linuxKernelPackageName,
		Version:      metadata.Version,
		Locations:    source.NewLocationSet(archiveLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:         packageURL(linuxKernelPackageName, metadata.Version),
		Type:         pkg.LinuxKernelPkg,
		MetadataType: pkg.LinuxKernelMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

func newLinuxKernelModulePackage(metadata pkg.LinuxKernelModuleMetadata, kmLocation source.Location) pkg.Package {
	p := pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Locations:    source.NewLocationSet(kmLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:     pkg.NewLicenseSet(pkg.NewLicensesFromLocation(kmLocation, metadata.License)...),
		PURL:         packageURL(metadata.Name, metadata.Version),
		Type:         pkg.LinuxKernelModulePkg,
		MetadataType: pkg.LinuxKernelModuleMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Kernel package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	var namespace string

	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}