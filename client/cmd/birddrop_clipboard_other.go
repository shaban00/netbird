//go:build !linux && !darwin && !windows

package cmd

import (
	"context"
	"errors"
)

var errClipboardUnsupported = errors.New("clipboard transfer is not supported on this platform; send a file instead")

func readClipboardText(context.Context) (string, error) { return "", errClipboardUnsupported }

func writeClipboardText(context.Context, string) error { return errClipboardUnsupported }
