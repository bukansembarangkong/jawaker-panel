// Package webdist embeds the compiled React frontend into the controller binary.
//
// The dist/ subdirectory is a copy of apps/web/dist/, built by "npm run build".
// The CI pipeline runs the build before compiling the Go binary so the embedded
// files are always in sync with the API surface they talk to.
package webdist

import "embed"

//go:embed all:dist
var FS embed.FS
