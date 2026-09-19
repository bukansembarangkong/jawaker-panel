// Package version exposes build metadata injected at compile time.
//
// Values are populated via -ldflags "-X .../version.Version=..." so every
// artifact (binary, API response, UI bundle through /api/v1/version) reports
// the same identity. Unset values fall back to explicit development markers
// rather than fake release strings.
package version

// Build metadata. Overridden at link time; never set at runtime.
var (
	// Version is the semantic version from the repository VERSION file.
	Version = "0.0.0-dev"
	// Commit is the short git SHA the binary was built from.
	Commit = "unknown"
	// BuildTime is the UTC RFC3339 timestamp of the build.
	BuildTime = "unknown"
)

// Info is the serializable build metadata payload.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}

// String renders build metadata for log lines and CLI banners.
func String() string {
	return Version + " (" + Commit + ", built " + BuildTime + ")"
}
