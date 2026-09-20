package nodeagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// marshalJSON encodes a value as compact JSON.
func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// decodeJSONStrict parses JSON into dst, refusing unknown fields and trailing
// values.
//
// The strictness matters for FILES as much as for network payloads: a config
// file left by a newer agent version would otherwise load with the fields this
// version understands and silently drop the rest, producing an agent that runs
// with a different configuration than the one on disk says.
func decodeJSONStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("value contains more than one JSON document")
	}
	return nil
}

// writeFileAtomic writes data to path via a temporary file and a rename.
//
// An interrupted write must never leave a half-written identity or config: a
// truncated private key file is indistinguishable from a corrupted one, and the
// node would refuse to start with a message about decoding rather than about the
// interruption that caused it.
//
// The temporary file is created in the SAME directory so the rename stays within
// one filesystem and is therefore atomic. Creating it elsewhere (the system temp
// directory, say) would make the rename a copy across devices, which is neither
// atomic nor necessarily permitted.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("nodeagent: create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Remove the temporary file if anything below fails, so a failed write does
	// not accumulate debris in a directory the operator reads.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	// Set the mode BEFORE writing, so the file never exists with a wider mode
	// than intended even for the instant between creation and chmod.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodeagent: set permissions on temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodeagent: write temporary file: %w", err)
	}
	// Sync before rename: without it the rename can be durable while the contents
	// are not, which on a crash yields an empty file under the final name.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodeagent: sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nodeagent: close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("nodeagent: replace %s: %w", path, err)
	}
	tmpName = "" // renamed; nothing to clean up
	return nil
}
