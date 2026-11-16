//go:build darwin

package cmd

import "context"

func readClipboardText(ctx context.Context) (string, error) {
	return readClipboardWithCommands(
		ctx,
		[]clipboardCommand{
			{name: "pbpaste"},
		},
		"clipboard access requires pbpaste",
	)
}

func writeClipboardText(ctx context.Context, text string) error {
	return writeClipboardWithCommands(
		ctx,
		text,
		[]clipboardCommand{
			{name: "pbcopy"},
		},
		"clipboard access requires pbcopy",
	)
}
