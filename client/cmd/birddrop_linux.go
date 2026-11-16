//go:build linux

package cmd

import "context"

func readClipboardText(ctx context.Context) (string, error) {
	return readClipboardWithCommands(
		ctx,
		[]clipboardCommand{
			{name: "wl-paste", args: []string{"--no-newline"}},
			{name: "xclip", args: []string{"-selection", "clipboard", "-out"}},
			{name: "xsel", args: []string{"--clipboard", "--output"}},
		},
		"clipboard access requires wl-paste, xclip, or xsel",
	)
}

func writeClipboardText(ctx context.Context, text string) error {
	return writeClipboardWithCommands(
		ctx,
		text,
		[]clipboardCommand{
			{name: "wl-copy"},
			{name: "xclip", args: []string{"-selection", "clipboard", "-in"}},
			{name: "xsel", args: []string{"--clipboard", "--input"}},
		},
		"clipboard access requires wl-copy, xclip, or xsel",
	)
}
