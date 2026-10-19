package live

import "sync"

const subscriberBuffer = 256

type Subscriber struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

type Hub struct {
	mu   sync.Mutex
	subs map[string]map[*Subscriber]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[*Subscriber]struct{})}
}

func (s *Subscriber) Events() <-chan []byte { return s.ch }

func (s *Subscriber) Done() <-chan struct{} { return s.closed }

func (s *Subscriber) close() {
	s.once.Do(func() { close(s.closed) })
}

// Subscribe adds a viewer for sessionID, queuing header first so late
// joiners get the terminal size. Live viewing is a tail; earlier events aren't replayed.
func (h *Hub) Subscribe(sessionID string, header []byte) *Subscriber {
	sub := &Subscriber{ch: make(chan []byte, subscriberBuffer), closed: make(chan struct{})}
	sub.ch <- append([]byte(nil), header...)

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[sessionID] == nil {
		h.subs[sessionID] = make(map[*Subscriber]struct{})
	}
	h.subs[sessionID][sub] = struct{}{}
	return sub
}

func (h *Hub) Unsubscribe(sessionID string, sub *Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeLocked(sessionID, sub)
}

func (h *Hub) removeLocked(sessionID string, sub *Subscriber) {
	delete(h.subs[sessionID], sub)
	if len(h.subs[sessionID]) == 0 {
		delete(h.subs, sessionID)
	}
}

// Publish sends line to all viewers of sessionID without blocking; viewers
// with full buffers are dropped so they can't stall recording.
func (h *Hub) Publish(sessionID string, line []byte) {
	h.mu.Lock()
	var slow []*Subscriber
	for sub := range h.subs[sessionID] {
		select {
		case sub.ch <- line:
		default:
			slow = append(slow, sub)
		}
	}
	for _, sub := range slow {
		h.removeLocked(sessionID, sub)
	}
	h.mu.Unlock()

	for _, sub := range slow {
		sub.close()
	}
}

func (h *Hub) End(sessionID string) {
	h.mu.Lock()
	subs := h.subs[sessionID]
	delete(h.subs, sessionID)
	h.mu.Unlock()

	for sub := range subs {
		sub.close()
	}
}
