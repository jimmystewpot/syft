package rust

import (
	"os"
	"reflect"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseCratesLicenseField(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "a OR b",
			args: args{
				s: "a OR b",
			},
			want: []string{"a", "b"},
		},
		{
			name: "c",
			args: args{
				s: "c",
			},
			want: []string{"c"},
		},
		{
			name: "no license",
			args: args{
				s: "",
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCratesLicenseField(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCratesLicenseField() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getCrateLicenseInfo(t *testing.T) {
	type args struct {
		url      string
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    []pkg.License
		wantErr bool
	}{
		{
			name: "clap crate",
			args: args{
				url:      "https://crates.io/api/v1/crates/clap/4.5.23",
				filename: "test-fixtures/glob-paths/crates_io-clap-crate.json",
			},
			wantErr: false,
			want: []pkg.License{
				{
					Type:           "concluded",
					Value:          "MIT",
					SPDXExpression: "MIT",
					URLs:           []string{"https://crates.io/api/v1/crates/clap/4.5.23"},
				},
				{
					Type:           "concluded",
					Value:          "Apache-2.0",
					SPDXExpression: "Apache-2.0",
					URLs:           []string{"https://crates.io/api/v1/crates/clap/4.5.23"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, _ := os.Open(tt.args.filename)
			defer reader.Close()
			got, err := getCrateLicenseInfo(tt.args.url, reader)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got, "got %+v, want %+v", got, tt.want)
		})
	}
}
