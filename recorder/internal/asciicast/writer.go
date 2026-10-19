// asciicast v3 recording format (https://docs.asciinema.org/manual/asciicast/v3/)
package asciicast

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

const defaultTermType = "xterm-256color"

type header struct {
	Version int      `json:"version"`
	Term    termInfo `json:"term"`
}

type termInfo struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Type string `json:"type,omitempty"`
}

type Writer struct {
	w io.Writer

	mu       sync.Mutex
	lastTime time.Time
}

// Header returns the asciicast v3 header line for cols/rows
func Header(cols, rows uint32) ([]byte, error) {
	h := header{
		Version: 3,
		Term:    termInfo{Cols: int(cols), Rows: int(rows), Type: defaultTermType},
	}
	data, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshal asciicast header: %w", err)
	}
	return data, nil
}

// NewWriter writes the asciicast header immediately and returns a Writer ready for incremental events.
func NewWriter(w io.Writer, cols, rows uint32, startedAt time.Time) (*Writer, error) {
	data, err := Header(cols, rows)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("write asciicast header: %w", err)
	}

	return &Writer{w: w, lastTime: startedAt}, nil
}

func (cw *Writer) Output(t time.Time, data []byte) error {
	return cw.writeEvent(t, "o", string(data))
}

// Resize writes a terminal resize ("r") event.
func (cw *Writer) Resize(t time.Time, cols, rows uint32) error {
	return cw.writeEvent(t, "r", fmt.Sprintf("%dx%d", cols, rows))
}

// Exit writes a session-exit ("x") event carrying the command's exit code.
func (cw *Writer) Exit(t time.Time, exitCode int32) error {
	return cw.writeEvent(t, "x", fmt.Sprintf("%d", exitCode))
}

func (cw *Writer) writeEvent(t time.Time, code, data string) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	interval := t.Sub(cw.lastTime).Seconds()
	if interval < 0 {
		interval = 0
	}
	cw.lastTime = t

	event := [3]any{interval, code, data}
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal asciicast %q event: %w", code, err)
	}
	if _, err := cw.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write asciicast %q event: %w", code, err)
	}
	return nil
}
