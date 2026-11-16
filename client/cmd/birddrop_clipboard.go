//go:build linux || darwin

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type clipboardCommand struct {
	name string
	args []string
}

// runClipboardCommands runs the first available command, feeding it stdin when
// given, and returns its output
func runClipboardCommands(
	ctx context.Context,
	op string,
	stdin *string,
	commands []clipboardCommand,
	missingCommandError string,
) (string, error) {
	var lastErr error

	for _, candidate := range commands {
		path, err := exec.LookPath(candidate.name)
		if err != nil {
			continue
		}

		cmd := exec.CommandContext(ctx, path, candidate.args...)
		if stdin != nil {
			cmd.Stdin = strings.NewReader(*stdin)
		}

		out, err := cmd.Output()
		if err == nil {
			return string(out), nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", fmt.Errorf("%s clipboard: %w", op, lastErr)
	}
	return "", errors.New(missingCommandError)
}

func readClipboardWithCommands(ctx context.Context, commands []clipboardCommand, missingCommandError string) (string, error) {
	return runClipboardCommands(ctx, "read", nil, commands, missingCommandError)
}

func writeClipboardWithCommands(ctx context.Context, text string, commands []clipboardCommand, missingCommandError string) error {
	_, err := runClipboardCommands(ctx, "write", &text, commands, missingCommandError)
	return err
}
