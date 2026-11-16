//go:build wasm

package ipcauth

import "os"

// There is no local IPC on wasm, so no caller whose access could be checked:
// directory access always fails closed, like OpenOwnedFile.

func openWritableDir(Identity, *callerToken, string) (*os.File, error) {
	return nil, errUnsupported
}

func openReadableDir(Identity, *callerToken, string) (*os.File, error) {
	return nil, errUnsupported
}
