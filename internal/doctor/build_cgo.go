//go:build cgo

package doctor

// cgoEnabled is true when the binary was built with CGO_ENABLED=1.
//
// The `cgo` build tag is set by the Go toolchain from CGO_ENABLED, so this
// reflects the ACTUAL binary rather than the current shell environment. The
// release pipeline builds with CGO_ENABLED=0, so "enabled" here means the binary
// on this host is not the one the pipeline produced.
const cgoEnabled = true
