package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/birddrop"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var (
	glyphOK       = "✓"
	glyphNo       = "✗"
	glyphArrow    = "→"
	glyphDots     = "…"
	spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	barFull       = "█"
	barEmpty      = "░"

	lastLineWidth int

	copyToClipboard = writeClipboardText
)

var (
	allowBirdDrop     bool
	dropReceiveOut    string
	dropReceiveStdout bool
	dropSendTimeout   time.Duration
	dropSendClipboard bool
	dropReceiveAll    bool
	dropRejectAll     bool
)

// allowBirdDropFlag controls whether this peer accepts inbound Birddrop offers.
const allowBirdDropFlag = "allow-birddrop"

// daemonErr strips the gRPC transport envelope ("rpc error: code = ... desc = ")
func daemonErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(status.Convert(err).Message())
}

// resolveIDs turns (args, --all) into the id list sent to the daemon: an empty
// slice means "every pending item". Requiring one or the other -- and rejecting
// both together -- keeps `receive`/`reject` symmetric and makes a bulk action
// something the user always asks for explicitly.
func resolveIDs(verb string, args []string, all bool) ([]string, error) {
	switch {
	case all && len(args) > 0:
		return nil, fmt.Errorf("pass either ids or --all to %s, not both", verb)
	case all:
		return nil, nil
	case len(args) == 0:
		return nil, fmt.Errorf("specify one or more ids from `netbird drop list`, or --all to %s everything pending", verb)
	default:
		return args, nil
	}
}

var dropCmd = &cobra.Command{
	Use:   "drop",
	Short: "Send and receive files, folders, or clipboard text between NetBird peers",
}

var dropSendCmd = &cobra.Command{
	Use:   "send <peer> [file|folder]",
	Short: "Send a file, folder, or clipboard text to a NetBird peer",
	Args: func(cmd *cobra.Command, args []string) error {
		if dropSendClipboard {
			return cobra.ExactArgs(1)(cmd, args)
		}
		return cobra.ExactArgs(2)(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		cmd.SetOut(cmd.OutOrStdout())
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return err
		}

		peerArg := args[0]

		req := &proto.BirddropSendRequest{
			Peer:           peerArg,
			TimeoutSeconds: int64(dropSendTimeout.Seconds()),
		}

		if dropSendClipboard {
			text, err := readClipboardText(cmd.Context())
			if err != nil {
				return err
			}

			if !utf8.ValidString(text) {
				return errors.New("clipboard content is not valid UTF-8 and cannot be sent")
			}

			req.Type = proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD
			req.ClipboardText = text
		} else {
			pathArg := args[1]

			absPath, err := filepath.Abs(pathArg)
			if err != nil {
				return fmt.Errorf("resolve path %q: %w", pathArg, err)
			}
			if _, err := os.Stat(absPath); err != nil {
				return fmt.Errorf("%q: %w", pathArg, err)
			}

			req.Path = absPath
		}

		conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to daemon: %v", err)
			return err
		}
		defer conn.Close()

		client := proto.NewDaemonServiceClient(conn)
		stream, err := client.BirddropSend(cmd.Context(), req)
		if err != nil {
			return err
		}

		return renderSend(cmd, stream)
	},
}

var dropListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List pending incoming item(s)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		cmd.SetOut(cmd.OutOrStdout())
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to daemon: %v", err)
			return err
		}
		defer conn.Close()

		resp, err := proto.NewDaemonServiceClient(conn).BirddropList(ctx, &proto.BirddropListRequest{})
		if err != nil {
			return daemonErr(err)
		}
		items := resp.GetItems()
		if len(items) == 0 {
			cmd.Println("No pending items.")
			return nil
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tFROM\tNAME\tKIND\tSIZE\tRECEIVED")
		for _, it := range items {
			kind := "unknown"
			switch it.GetType() {
			case proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_FILE:
				kind = "file"
			case proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_DIRECTORY:
				kind = "folder"
			case proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD:
				kind = "clipboard"
			}
			when := time.Unix(it.GetReceivedUnix(), 0).Format("2006-01-02 15:04")
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				shortBirddropID(it.GetId()),
				it.GetFrom(),
				it.GetName(),
				kind,
				humanBytes(it.GetSize()),
				when,
			)
		}
		_ = tw.Flush()
		cmd.Printf("\nReceive: netbird drop receive <id...> | --all   Reject: netbird drop reject <id...> | --all\n")
		return nil
	},
}

// resolveReceiveDest resolves the destination in the CLI process so an omitted
// --out refers to the directory where the user ran the command
func resolveReceiveDest(dest string) (string, error) {
	if dest == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve current directory: %w", err)
		}
		return wd, nil
	}

	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("resolve --out %q: %w", dest, err)
	}

	return absDest, nil
}

var dropReceiveCmd = &cobra.Command{
	Use:   "receive [id...] | --all",
	Short: "Receive pending item(s) from sender",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		cmd.SetOut(cmd.OutOrStdout())
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return err
		}
		ids, err := resolveIDs("receive", args, dropReceiveAll)
		if err != nil {
			return err
		}

		dest, err := resolveReceiveDest(dropReceiveOut)
		if err != nil {
			return err
		}

		conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to daemon: %v", err)
			return err
		}
		defer conn.Close()

		stream, err := proto.NewDaemonServiceClient(conn).BirddropReceive(cmd.Context(),
			&proto.BirddropReceiveRequest{Ids: ids, Dest: dest})
		if err != nil {
			return daemonErr(err)
		}
		return renderReceive(cmd, stream, dropReceiveStdout)
	},
}

var dropRejectCmd = &cobra.Command{
	Use:   "reject [id...] | --all",
	Short: "Reject pending item(s) from sender",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		cmd.SetOut(cmd.OutOrStdout())
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return err
		}
		ids, err := resolveIDs("reject", args, dropRejectAll)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to daemon: %v", err)
			return err
		}
		defer conn.Close()
		resp, err := proto.NewDaemonServiceClient(conn).BirddropReject(ctx, &proto.BirddropRejectRequest{Ids: ids})
		if err != nil {
			return daemonErr(err)
		}
		cmd.Printf("%s rejected %d item(s)\n", glyphNo, resp.GetRejected())
		return nil
	},
}

// ellipsis returns the truncation marker suited to the console.
func ellipsis() string {
	if richConsole() {
		return "…"
	}
	return "..."
}

// fitName shortens name so a progress line built from it fits the terminal.
func fitName(name string, overhead int) string {
	w := terminalWidth()
	if w <= 0 {
		return name // unknown width: leave formatting alone
	}

	budget := w - 1 - overhead
	const minBudget = 12
	if budget < minBudget {
		budget = minBudget
	}
	r := []rune(name)
	if len(r) <= budget {
		return name
	}
	ell := []rune(ellipsis())
	keep := budget - len(ell)
	if keep < 2 {
		return string(r[:max(budget, 1)])
	}
	head := (keep + 1) / 2
	tail := keep - head
	return string(r[:head]) + string(ell) + string(r[len(r)-tail:])
}

// barOrEmpty returns the progress bar prefixed with two spaces, or an empty
// string on terminals too narrow to show it.
func barOrEmpty(done, total int64) string {
	const narrow = 70
	if w := terminalWidth(); w > 0 && w < narrow {
		return ""
	}
	return "  " + bar(done, total)
}

// clampToWidth truncates s so it cannot wrap onto a second row
func clampToWidth(s string) string {
	w := terminalWidth()
	if w <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) < w {
		return s
	}
	return string(r[:w-1])
}

// drawLine repaints one terminal line and erases any leftover characters.
func drawLine(s string) {
	s = clampToWidth(s)
	w := utf8.RuneCountInString(s)
	pad := lastLineWidth - w
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(os.Stderr, "\r%s%s", s, strings.Repeat(" ", pad))
	lastLineWidth = w
}

// clearLine erases the current progress line and returns to column zero.
func clearLine() {
	if lastLineWidth > 0 {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", lastLineWidth))
		lastLineWidth = 0
	}
}

// renderSend consumes the send stream and renders waiting/progress/terminal state.
func renderSend(cmd *cobra.Command, stream proto.DaemonService_BirddropSendClient) error {
	tty := isTTY()
	var (
		mu      sync.Mutex
		latest  *proto.BirddropSendEvent
		done    = make(chan struct{})
		printed bool
	)

	if tty {
		go func() {
			frames := spinnerFrames
			i := 0
			t := time.NewTicker(100 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					mu.Lock()
					ev := latest
					mu.Unlock()
					if ev != nil && ev.GetState() == "waiting" {
						drawLine(fmt.Sprintf("  waiting for %s to accept%s  %c", peerLabel(ev), glyphDots, frames[i%len(frames)]))
						i++
					}
				}
			}
		}()
	}

	var final *proto.BirddropSendEvent
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(done)
			return daemonErr(err)
		}
		mu.Lock()
		latest = ev
		mu.Unlock()

		if !printed {
			cmd.Printf("%s sending %s (%s) to %s %s\n", glyphArrow, ev.GetName(), humanBytes(ev.GetTotal()), peerLabel(ev), glyphDots)
			printed = true
		}

		switch ev.GetState() {
		case "transferring":
			if tty {
				drawLine(fmt.Sprintf("  sending%s%s  %s/%s (%3.0f%%)", glyphDots,
					barOrEmpty(ev.GetTransferred(), ev.GetTotal()),
					humanBytes(ev.GetTransferred()), humanBytes(ev.GetTotal()),
					pct(ev.GetTransferred(), ev.GetTotal())))
			}
		case "delivered", "declined", "timed_out", "canceled", "error":
			final = ev
		}
	}
	close(done)
	if tty {
		clearLine()
	}

	if final == nil {
		return nil
	}
	switch final.GetState() {
	case "delivered":
		cmd.Printf("%s Transfer complete\n", glyphOK)
		return nil
	case "declined":
		cmd.Printf("%s Transfer declined\n", glyphNo)
	case "timed_out":
		cmd.Printf("%s Transfer timed out\n", glyphNo)
	case "canceled":
		if msg := final.GetMessage(); msg != "" && msg != "canceled" {
			cmd.Printf("%s %s\n", glyphNo, msg)
		} else {
			cmd.Printf("%s Transfer canceled\n", glyphNo)
		}
	default:
		cmd.Printf("%s error: %s\n", glyphNo, final.GetMessage())
	}
	return fmt.Errorf("transfer not completed (%s)", final.GetState())
}

func peerLabel(ev *proto.BirddropSendEvent) string {
	if ev.GetPeerFqdn() != "" {
		return ev.GetPeerFqdn()
	}
	return ev.GetPeerIp()
}

func bar(done, total int64) string {
	const width = 24
	if total <= 0 {
		return strings.Repeat(barEmpty, width)
	}
	filled := int(float64(width) * float64(done) / float64(total))
	if filled > width {
		filled = width
	}
	return strings.Repeat(barFull, filled) + strings.Repeat(barEmpty, width-filled)
}

func pct(done, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(done) / float64(total)
}

// renderReceive consumes the receive stream and renders progress for each item.
func renderReceive(
	cmd *cobra.Command,
	stream proto.DaemonService_BirddropReceiveClient,
	clipboardStdout bool,
) error {
	tty := isTTY()
	receivedAny := false
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if tty {
				clearLine()
			}
			return daemonErr(err)
		}
		switch ev.GetState() {
		case "receiving":
			if tty {
				const prefix = "  receiving "
				rest := fmt.Sprintf("%s%s  %s/%s (%3.0f%%)",
					glyphDots, barOrEmpty(ev.GetTransferred(), ev.GetTotal()),
					humanBytes(ev.GetTransferred()), humanBytes(ev.GetTotal()),
					pct(ev.GetTransferred(), ev.GetTotal()))
				overhead := utf8.RuneCountInString(prefix) + utf8.RuneCountInString(rest)
				drawLine(prefix + fitName(ev.GetName(), overhead) + rest)
			}
		case "done":
			if tty {
				clearLine()
			}

			receivedAny = true

			if ev.GetType() == proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD {
				if clipboardStdout {
					cmd.Print(clipboardForOutput(cmd.OutOrStdout(), ev.GetClipboardText()))
					continue
				}

				if err := copyToClipboard(cmd.Context(), ev.GetClipboardText()); err != nil {
					cmd.PrintErrf("Could not copy to the clipboard (%v); printing it instead:\n", err)
					cmd.Print(clipboardForOutput(cmd.OutOrStdout(), ev.GetClipboardText()))
					continue
				}

				cmd.Println("Copied to clipboard")
				continue
			}

			if ev.GetType() == proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_DIRECTORY {
				if ev.GetFiles() == 0 {
					cmd.Printf("Written to %s %s (empty folder)\n", glyphArrow, ev.GetSavedAs())
				} else {
					cmd.Printf("Written to %s %s\n", glyphArrow, ev.GetSavedAs())
				}
			} else {
				cmd.Printf("Written to %s %s\n", glyphArrow, ev.GetSavedAs())
			}
		case "error":
			if tty {
				clearLine()
			}
			return fmt.Errorf("%s", ev.GetMessage())
		}
	}
	if !receivedAny {
		return errors.New("nothing was received (the offer may have been withdrawn by the " +
			"sender); run `netbird drop list` to check what is still pending")
	}
	return nil
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// humanBytes renders a byte count in binary units.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// shortBirddropID returns the 12-character ID shown by `netbird drop list`.
// The daemon retains the full ID and resolves these display prefixes uniquely.
func shortBirddropID(id string) string {
	const n = 12

	if len(id) <= n {
		return id
	}

	return id[:n]
}

func clipboardForOutput(w io.Writer, text string) string {
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		text = birddrop.EscapeForTerminal(text)
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
	}
	return text
}

func init() {
	if !richConsole() {
		glyphOK = "+"
		glyphNo = "x"
		spinnerFrames = []rune{'|', '/', '-', '\\'}
	}

	dropReceiveCmd.Flags().StringVar(&dropReceiveOut, "out", "", "destination directory (default: current directory)")
	dropReceiveCmd.Flags().BoolVar(&dropReceiveAll, "all", false, "receive every pending item")
	dropReceiveCmd.Flags().BoolVar(&dropReceiveStdout, "stdout", false, "print received clipboard text instead of copying it to the local clipboard")
	dropRejectCmd.Flags().BoolVar(&dropRejectAll, "all", false, "reject every pending item")
	dropSendCmd.Flags().DurationVar(&dropSendTimeout, "timeout", 30*time.Minute, "how long to wait for the peer to accept")
	dropSendCmd.Flags().BoolVar(&dropSendClipboard, "clipboard", false, "send the current text clipboard instead of a file or folder")
	dropCmd.AddCommand(dropSendCmd, dropListCmd, dropReceiveCmd, dropRejectCmd)

	upCmd.PersistentFlags().BoolVar(&allowBirdDrop, allowBirdDropFlag, false, "Allow peers to send and receive Birddrop items")
}
