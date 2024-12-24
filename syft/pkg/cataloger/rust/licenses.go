package rust

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

type rustLicenseResolver struct {
	catalogerName         string
	opts                  CatalogerConfig
	licenseCache          cache.Resolver[[]pkg.License]
	lowerLicenseFileNames *strset.Set
}

type cratesVersionMetadata struct {
	Version struct {
		Checksum     string `json:"checksum"`
		Crate        string `json:"crate"`
		Description  string `json:"description"`
		DownloadPath string `json:"dl_path"`
		License      string `json:"license"`
		Num          string `json:"num"`
		Repository   string `json:"repository"`
	} `json:"version"`
}

func newRustLicenseResolver(catalogerName string, opts CatalogerConfig) *rustLicenseResolver {
	return &rustLicenseResolver{
		catalogerName: catalogerName,
		opts:          opts,
	}
}

func (r *rustLicenseResolver) getLicenses(ctx context.Context, scanner licenses.Scanner, resolver file.Resolver, crateName, crateVersion string) ([]pkg.License, error) {
	// resolver is not used at this stage, this only checks the upstream crates.io service for licensing.
	if r.opts.SearchRemoteLicenses {
		if scanner != nil {
			fmt.Println("Holding")
		}
		if resolver != nil {
			fmt.Println("Holding")
		}
		return r.getLicensesFromRemote(ctx, crateName, crateVersion)
	}
	return nil, nil
}

func (r *rustLicenseResolver) getLicensesFromRemote(ctx context.Context, crateName, crateVersion string) ([]pkg.License, error) {
	return r.licenseCache.Resolve(fmt.Sprintf("%s/%s", crateName, crateVersion), func() ([]pkg.License, error) {
		return r.getCrate(ctx, crateName, crateVersion)
	})
}

func (r *rustLicenseResolver) getCrate(ctx context.Context, crateName, crateVersion string) ([]pkg.License, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "recovered from panic while resolving license at: \n%s", string(debug.Stack()))
		}
	}()
	return makeCratesRequest(ctx, crateName, crateVersion)
}

func makeCratesRequest(ctx context.Context, crateName, crateVersion string) ([]pkg.License, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", crateName, crateVersion)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req = setHeaders(req)

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	licenseInfo, err := getCrateLicenseInfo(url, resp.Body)
	if err != nil {
		return nil, err
	}
	return licenseInfo, nil
}

func getCrateLicenseInfo(url string, reader io.Reader) ([]pkg.License, error) {
	var crateInfo cratesVersionMetadata
	err := json.NewDecoder(reader).Decode(&crateInfo)

	if err != nil {
		return nil, err
	}
	ids := parseCratesLicenseField(crateInfo.Version.License)

	if len(ids) != 0 {
		licenses, err := parseLicenseIDs(url, ids)
		if err != nil {
			return nil, err
		}
		return licenses, nil
	}

	return []pkg.License{}, nil
}

func parseCratesLicenseField(s string) []string {
	matches := crateLicenseRegex.FindAllStringSubmatch(s, -1)
	licenseIDs := make([]string, 0)
	for _, match := range matches {
		if match[1] != "OR" {
			licenseIDs = append(licenseIDs, match[1])
		}
	}
	return licenseIDs
}

func parseLicenseIDs(location string, ids []string) ([]pkg.License, error) {
	licenses := make([]pkg.License, 0)
	for _, id := range ids {
		lic := pkg.NewLicenseFromURLs(id, location)
		lic.Type = license.Concluded
		licenses = append(licenses, lic)
	}
	return licenses, nil
}

func setHeaders(request *http.Request) *http.Request {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "github.com/anchore/syft")
	return request
}
