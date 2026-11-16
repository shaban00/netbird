//go:build wasm

package ipcauth

import "os"

// openReadableFile always fails on wasm: there is no local IPC caller whose
// access could be checked, so it fails closed like OpenOwnedFile.
func openReadableFile(Identity, *callerToken, string) (*os.File, error) {
	return nil, errUnsupported
}
