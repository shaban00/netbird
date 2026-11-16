//go:build unix

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

// richConsole reports whether the console can render the Unicode progress glyphs.
// Supported Unix terminals are UTF-8, so this is always true.
func richConsole() bool { return true }

// terminalWidth returns the console width in columns, or 0 if it cannot be determined.
func terminalWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stderr.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil {
		return 0
	}
	return int(ws.Col)
}
