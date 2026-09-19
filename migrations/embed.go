// Package migrations embeds the control-plane SQL migration set into the
// controller binary. Keeping the embed here (rather than in cmd/) means the
// SQL travels with the package that owns it and cannot drift from the
// directory layout.
package migrations

import "embed"

// FS contains every migration file in this directory. The migration runner
// ignores non-.sql files (like this package's Go sources and README).
//
//go:embed *.sql
var FS embed.FS
