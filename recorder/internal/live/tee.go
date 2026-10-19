package live

import "bytes"

type TeeWriter struct {
	Hub       *Hub
	SessionID string
}

// Write implements io.Writer, stripping asciicast's trailing newline since each WebSocket message is already one event.
func (t *TeeWriter) Write(p []byte) (int, error) {
	t.Hub.Publish(t.SessionID, bytes.TrimSuffix(p, []byte("\n")))
	return len(p), nil
}
