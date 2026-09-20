//go:build !cgo

package doctor

// cgoEnabled is false when the binary was built with CGO_ENABLED=0, which is how
// the release pipeline builds it.
const cgoEnabled = false
