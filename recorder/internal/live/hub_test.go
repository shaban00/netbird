package live

import (
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

func recvOrTimeout(t *testing.T, sub *Subscriber) []byte {
	t.Helper()
	select {
	case line := <-sub.Events():
		return line
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for an event")
		return nil
	}
}

func TestHub_SubscribeReceivesHeaderFirst(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe("sess-1", []byte(`{"version":3}`))

	got := recvOrTimeout(t, sub)
	if string(got) != `{"version":3}` {
		t.Fatalf("got %q, want the header as the first queued event", got)
	}
}

func TestHub_PublishReachesSubscriber(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe("sess-1", []byte("header"))
	recvOrTimeout(t, sub) // drain the header

	h.Publish("sess-1", []byte(`[0.1,"o","hi"]`))

	got := recvOrTimeout(t, sub)
	if string(got) != `[0.1,"o","hi"]` {
		t.Fatalf("got %q, want the published event", got)
	}
}

func TestHub_PublishDoesNotCrossSessions(t *testing.T) {
	h := NewHub()
	subA := h.Subscribe("sess-a", []byte("header-a"))
	subB := h.Subscribe("sess-b", []byte("header-b"))
	recvOrTimeout(t, subA)
	recvOrTimeout(t, subB)

	h.Publish("sess-a", []byte("only-for-a"))

	if got := recvOrTimeout(t, subA); string(got) != "only-for-a" {
		t.Fatalf("sess-a got %q", got)
	}
	select {
	case line := <-subB.Events():
		t.Fatalf("sess-b subscriber received sess-a's event: %q", line)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHub_PublishWithNoSubscribersIsNoop(t *testing.T) {
	h := NewHub()
	h.Publish("nobody-watching", []byte("ignored"))
}

func TestHub_UnsubscribeStopsDelivery(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe("sess-1", []byte("header"))
	recvOrTimeout(t, sub)

	h.Unsubscribe("sess-1", sub)
	h.Publish("sess-1", []byte("after-unsubscribe"))

	select {
	case line := <-sub.Events():
		t.Fatalf("received event after unsubscribe: %q", line)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHub_UnsubscribeIsIdempotent(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe("sess-1", []byte("header"))
	h.Unsubscribe("sess-1", sub)
	h.Unsubscribe("sess-1", sub)
}

func TestHub_EndClosesAllSubscribersForThatSession(t *testing.T) {
	h := NewHub()
	subA := h.Subscribe("sess-1", []byte("header"))
	subB := h.Subscribe("sess-1", []byte("header"))
	other := h.Subscribe("sess-2", []byte("header"))

	h.End("sess-1")

	for name, sub := range map[string]*Subscriber{"a": subA, "b": subB} {
		select {
		case <-sub.Done():
		case <-time.After(testTimeout):
			t.Fatalf("subscriber %s: Done was not closed after End", name)
		}
	}

	select {
	case <-other.Done():
		t.Fatal("sess-2's subscriber was dropped by sess-1's End")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHub_EndOnUnknownSessionIsNoop(t *testing.T) {
	h := NewHub()
	h.End("never-subscribed")
}

func TestHub_SlowSubscriberIsDroppedNotBlocking(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe("sess-1", []byte("header"))
	recvOrTimeout(t, sub)

	// Overflow the buffer without ever reading it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < subscriberBuffer+10; i++ {
			h.Publish("sess-1", []byte("x"))
		}
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Publish blocked on a slow subscriber instead of dropping it")
	}

	select {
	case <-sub.Done():
	case <-time.After(testTimeout):
		t.Fatal("slow subscriber was never dropped")
	}
}
