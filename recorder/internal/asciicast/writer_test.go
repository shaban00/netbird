package asciicast

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type failAfterN struct {
	n     int
	calls int
}

func TestWriter_HeaderAndOutputEvent(t *testing.T) {
	var buf bytes.Buffer
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	w, err := NewWriter(&buf, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Output(start.Add(100*time.Millisecond), []byte("hello\r\n")); err != nil {
		t.Fatalf("Output: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 event), got %d: %q", len(lines), buf.String())
	}

	var h header
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if h.Version != 3 || h.Term.Cols != 80 || h.Term.Rows != 24 {
		t.Fatalf("unexpected header: %+v", h)
	}

	var ev []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if len(ev) != 3 {
		t.Fatalf("expected 3-element event array, got %d", len(ev))
	}
	var interval float64
	if err := json.Unmarshal(ev[0], &interval); err != nil {
		t.Fatalf("unmarshal interval: %v", err)
	}
	if interval < 0.099 || interval > 0.101 {
		t.Fatalf("expected ~0.1s interval, got %v", interval)
	}
	var code, data string
	if err := json.Unmarshal(ev[1], &code); err != nil {
		t.Fatalf("unmarshal code: %v", err)
	}
	if code != "o" {
		t.Fatalf("expected code %q, got %q", "o", code)
	}
	if err := json.Unmarshal(ev[2], &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data != "hello\r\n" {
		t.Fatalf("expected data %q, got %q", "hello\r\n", data)
	}
}

func TestWriter_RelativeTimingBetweenEvents(t *testing.T) {
	var buf bytes.Buffer
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	w, err := NewWriter(&buf, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Output(start.Add(1*time.Second), []byte("a")); err != nil {
		t.Fatalf("Output 1: %v", err)
	}
	if err := w.Output(start.Add(1500*time.Millisecond), []byte("b")); err != nil {
		t.Fatalf("Output 2: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	intervalOf := func(line string) float64 {
		var ev []json.RawMessage
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		var f float64
		if err := json.Unmarshal(ev[0], &f); err != nil {
			t.Fatalf("unmarshal interval: %v", err)
		}
		return f
	}

	first := intervalOf(lines[1])
	second := intervalOf(lines[2])
	if first < 0.99 || first > 1.01 {
		t.Fatalf("expected first interval ~1.0s, got %v", first)
	}

	if second < 0.49 || second > 0.51 {
		t.Fatalf("expected second interval ~0.5s (relative to previous event), got %v", second)
	}
}

func TestWriter_ResizeEvent(t *testing.T) {
	var buf bytes.Buffer
	start := time.Now()

	w, err := NewWriter(&buf, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Resize(start.Add(time.Second), 120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var ev []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	var code, data string
	_ = json.Unmarshal(ev[1], &code)
	_ = json.Unmarshal(ev[2], &data)
	if code != "r" {
		t.Fatalf("expected code %q, got %q", "r", code)
	}
	if data != "120x40" {
		t.Fatalf("expected %q, got %q", "120x40", data)
	}
}

func TestWriter_ExitEvent(t *testing.T) {
	var buf bytes.Buffer
	start := time.Now()

	w, err := NewWriter(&buf, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Exit(start.Add(time.Second), 42); err != nil {
		t.Fatalf("Exit: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var ev []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	var code, data string
	_ = json.Unmarshal(ev[1], &code)
	_ = json.Unmarshal(ev[2], &data)
	if code != "x" || data != "42" {
		t.Fatalf("expected [_, \"x\", \"42\"], got code=%q data=%q", code, data)
	}
}

func TestWriter_PreservesANSIAndUnicode(t *testing.T) {
	var buf bytes.Buffer
	start := time.Now()

	w, err := NewWriter(&buf, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// ANSI color escape + cursor movement + Unicode.
	payload := "\x1b[31mred\x1b[0m \x1b[2J\x1b[H日本語 \U0001F600"
	if err := w.Output(start.Add(time.Millisecond), []byte(payload)); err != nil {
		t.Fatalf("Output: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var ev []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	var data string
	if err := json.Unmarshal(ev[2], &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data != payload {
		t.Fatalf("payload not preserved byte-for-byte:\n got: %q\nwant: %q", data, payload)
	}
}

func TestWriter_NeverBuffersFullSession(t *testing.T) {
	fw := &failAfterN{n: 1}
	start := time.Now()

	w, err := NewWriter(fw, 80, 24, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Output(start.Add(time.Millisecond), []byte("x")); err == nil {
		t.Fatal("expected write error to surface immediately, got nil")
	}
}

func (f *failAfterN) Write(p []byte) (int, error) {
	f.calls++
	if f.calls > f.n {
		return 0, bytes.ErrTooLarge
	}
	return len(p), nil
}
