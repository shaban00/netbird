package birddrop

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/ipcauth"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/stretchr/testify/require"
)

type failingWriter struct {
	remaining int
	err       error
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func waitReady(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 250; i++ {
		if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("endpoint on %d not ready", port)
}

func pair(t *testing.T) (sender, receiver *Manager, rPort int) {
	t.Helper()
	sPort, rPort := freePort(t), freePort(t)
	s, err := NewManager("sender.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewManager("receiver.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve([]string{"127.0.0.1"}, sPort) }()
	go func() { _ = r.Serve([]string{"127.0.0.1"}, rPort) }()
	waitReady(t, sPort)
	waitReady(t, rPort)
	t.Cleanup(func() { _ = s.Shutdown(); _ = r.Shutdown() })
	return s, r, rPort
}

func collectSendEvents(evc <-chan SendEvent) <-chan SendEvent {
	out := make(chan SendEvent, 1)
	go func() {
		var last SendEvent
		for ev := range evc {
			last = ev
		}
		out <- last
	}()
	return out
}

func authenticatedContext(t *testing.T) context.Context {
	t.Helper()

	id, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		t.Fatalf("get current process identity: %v", err)
	}

	return peer.NewContext(
		context.Background(),
		&peer.Peer{
			AuthInfo: ipcauth.AuthInfo{
				CommonAuthInfo: credentials.CommonAuthInfo{
					SecurityLevel: credentials.NoSecurity,
				},
				Identity: id,
			},
		},
	)
}

func sendTestFile(
	m *Manager,
	ctx context.Context,
	targetIP string,
	targetPort int,
	targetFQDN string,
	path string,
	timeout time.Duration,
) (<-chan SendEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	evc, err := m.SendFile(
		ctx,
		targetIP,
		targetPort,
		targetFQDN,
		f,
		timeout,
	)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return evc, nil
}

func TestSelectItemsAcceptsUniquePrefixAndRejectsAmbiguity(t *testing.T) {
	m := &Manager{incoming: map[string]*Item{
		"0123456789abcdef0123456789abcdef": {ID: "0123456789abcdef0123456789abcdef"},
		"fedcba9876543210fedcba9876543210": {ID: "fedcba9876543210fedcba9876543210"},
		"aaaaaaaaaaaa11111111111111111111": {ID: "aaaaaaaaaaaa11111111111111111111"},
		"aaaaaaaaaaaa22222222222222222222": {ID: "aaaaaaaaaaaa22222222222222222222"},
	}}

	items, err := m.selectItems([]string{"0123456789ab"})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "0123456789abcdef0123456789abcdef", items[0].ID)

	_, err = m.selectItems([]string{"0123456789a"})
	require.ErrorContains(t, err, "too short")

	_, err = m.selectItems([]string{"aaaaaaaaaaaa"})
	require.ErrorContains(t, err, "ambiguous")
}

func TestOfferReceiveFile(t *testing.T) {
	s, r, rPort := pair(t)

	src := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(src, []byte("quarterly numbers"), 0o644); err != nil {
		t.Fatal(err)
	}

	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver.netbird.cloud", src, 10*time.Second)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	final := collectSendEvents(evc)

	items := r.List()
	if len(items) != 1 || items[0].Name != "report.pdf" || items[0].IsDir {
		t.Fatalf("unexpected offer list: %+v", items)
	}

	dest := t.TempDir()
	res, err := r.Receive(context.Background(), []string{items[0].ID}, dest, testRoot(t, dest), -1, -1, nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	got, err := os.ReadFile(filepath.Join(dest, "report.pdf"))
	if err != nil || string(got) != "quarterly numbers" {
		t.Fatalf("content mismatch: %v %q", err, got)
	}

	select {
	case ev := <-final:
		if ev.State != StateDelivered || ev.Transferred != int64(len("quarterly numbers")) {
			t.Fatalf("sender terminal event = %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sender never reached a terminal state")
	}
	if len(r.List()) != 0 {
		t.Fatal("offer should be gone after receive")
	}
}

func TestOfferReceiveFolder(t *testing.T) {
	s, r, rPort := pair(t)

	dir := filepath.Join(t.TempDir(), "project")
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644)

	evc, err := s.Send(
		authenticatedContext(t),
		"127.0.0.1",
		rPort,
		"receiver",
		dir,
		10*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	final := collectSendEvents(evc)

	items := r.List()
	if len(items) != 1 || !items[0].IsDir {
		t.Fatalf("expected 1 dir offer, got %+v", items)
	}
	dest := t.TempDir()
	if _, err := r.Receive(context.Background(), nil, dest, testRoot(t, dest), -1, -1, nil); err != nil { // nil = all
		t.Fatalf("Receive all: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "project", "sub", "b.txt")); err != nil || string(b) != "bbb" {
		t.Fatalf("folder not extracted: %v %q", err, b)
	}
	if ev := <-final; ev.State != StateDelivered || !ev.IsDir {
		t.Fatalf("terminal = %+v", ev)
	}
}

func TestReject(t *testing.T) {
	s, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "junk.bin")
	_ = os.WriteFile(src, []byte("nope"), 0o644)

	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver", src, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	final := collectSendEvents(evc)

	items := r.List()
	if _, err := r.Reject([]string{items[0].ID}); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if ev := <-final; ev.State != StateDeclined {
		t.Fatalf("expected declined, got %+v", ev)
	}
	if len(r.List()) != 0 {
		t.Fatal("offer should be gone after reject")
	}
}

func TestSendTimeout(t *testing.T) {
	s, _, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "slow.bin")
	_ = os.WriteFile(src, []byte("data"), 0o644)

	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver", src, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	final := collectSendEvents(evc)
	select {
	case ev := <-final:
		if ev.State != StateTimedOut {
			t.Fatalf("expected timed_out, got %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("send did not time out")
	}
}

func TestSendTimeoutDoesNotExpireDuringActiveFetch(t *testing.T) {
	s, r, rPort := pair(t)

	src := filepath.Join(t.TempDir(), "large.bin")

	f, err := os.Create(src)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(64<<20))
	require.NoError(t, f.Close())

	evc, err := sendTestFile(
		s,
		context.Background(),
		"127.0.0.1",
		rPort,
		"receiver.netbird.cloud",
		src,
		200*time.Millisecond,
	)
	require.NoError(t, err)

	final := collectSendEvents(evc)

	items := r.List()
	require.Len(t, items, 1)

	id := items[0].ID

	s.mu.Lock()
	o := s.outgoing[id]
	s.mu.Unlock()
	require.NotNil(t, o)

	fetchURL := birddropURL(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(s.selfPort)),
		pathFetch,
		id,
	)

	resp, err := newHTTPClient(0).Get(fetchURL)
	require.NoError(t, err)

	buf := make([]byte, 1)
	_, err = resp.Body.Read(buf)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()

		return o.fetching
	}, time.Second, 10*time.Millisecond)

	time.Sleep(300 * time.Millisecond)

	select {
	case ev := <-final:
		t.Fatalf("active transfer unexpectedly reached terminal state: %+v", ev)
	default:
	}

	require.NoError(t, resp.Body.Close())
}

func TestUntarTraversalGuard(t *testing.T) {
	spool := t.TempDir()
	evil := filepath.Join(spool, "evil.tar")
	f, _ := os.Create(evil)
	tw := tar.NewWriter(f)
	body := []byte("pwned")
	_ = tw.WriteHeader(&tar.Header{Name: "../../escape.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = f.Close()

	dest := t.TempDir()
	if _, _, err := untarFile(t, evil, testRoot(t, dest)); err == nil {
		t.Fatal("expected traversal to be refused")
	}
	// The entry climbs two levels; check both, not just the parent.
	for _, dir := range []string{filepath.Dir(dest), filepath.Dir(filepath.Dir(dest))} {
		if _, err := os.Stat(filepath.Join(dir, "escape.txt")); err == nil {
			t.Fatalf("traversal escaped the destination into %s", dir)
		}
	}
}

func TestCancelWithdrawsOffer(t *testing.T) {
	s, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	_ = os.WriteFile(src, []byte("payload"), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	evc, err := sendTestFile(s, ctx, "127.0.0.1", rPort, "receiver", src, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	final := collectSendEvents(evc)

	if len(r.List()) != 1 {
		t.Fatalf("expected 1 pending offer, got %d", len(r.List()))
	}

	cancel()
	if ev := <-final; ev.State != StateCanceled {
		t.Fatalf("expected canceled, got %+v", ev)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(r.List()) == 0 {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("offer still pending on receiver after cancel: %+v", r.List())
}

func TestReceiveEmitsProgress(t *testing.T) {
	s, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, make([]byte, 3<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver", src, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = collectSendEvents(evc)

	items := r.List()
	var ticks int
	var lastTotal int64
	dest := t.TempDir()
	_, err = r.Receive(context.Background(), []string{items[0].ID}, dest, testRoot(t, dest), -1, -1, func(p ReceiveProgress) {
		ticks++
		lastTotal = p.Total
	})
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if lastTotal != int64(3<<20) {
		t.Fatalf("progress Total = %d, want %d", lastTotal, 3<<20)
	}
	if fi, err := os.Stat(filepath.Join(dest, "big.bin")); err != nil || fi.Size() != int64(3<<20) {
		t.Fatalf("received file wrong: %v", err)
	}
}

func TestSafeTarNameRejectsEscapes(t *testing.T) {
	bad := []string{"../evil", "a/../../evil", "/etc/passwd", "", "sub/../../out"}
	for _, n := range bad {
		if err := safeTarName(n); err == nil {
			t.Fatalf("safeTarName(%q) = nil, want error", n)
		}
	}
	good := []string{"file.txt", "sub/file.txt", "a/b/c.bin", "./ok.txt"}
	for _, n := range good {
		if err := safeTarName(n); err != nil {
			t.Fatalf("safeTarName(%q) = %v, want nil", n, err)
		}
	}
}

func TestRejectAllPending(t *testing.T) {
	s1, r, rPort := pair(t)
	dir := t.TempDir()
	for _, n := range []string{"a.bin", "b.bin"} {
		p := filepath.Join(dir, n)
		_ = os.WriteFile(p, []byte(n), 0o644)
		evc, err := sendTestFile(s1, context.Background(), "127.0.0.1", rPort, "receiver", p, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = collectSendEvents(evc)
	}
	if len(r.List()) != 2 {
		t.Fatalf("want 2 pending, got %d", len(r.List()))
	}
	n, err := r.Reject(nil) // nil == all
	if err != nil {
		t.Fatalf("Reject(all): %v", err)
	}
	if n != 2 {
		t.Fatalf("rejected %d, want 2", n)
	}
	if len(r.List()) != 0 {
		t.Fatalf("queue should be empty, got %+v", r.List())
	}
}

func TestUnreachableSenderKeepsOffer(t *testing.T) {
	s1, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "x.bin")
	_ = os.WriteFile(src, []byte("data"), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evc, err := sendTestFile(s1, ctx, "127.0.0.1", rPort, "receiver", src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = collectSendEvents(evc)
	items := r.List()
	if len(items) != 1 {
		t.Fatalf("want 1 pending offer")
	}

	_ = s1.Shutdown()

	if _, err := r.Receive(context.Background(), []string{items[0].ID}, "", testRoot(t, t.TempDir()), -1, -1, nil); err == nil {
		t.Fatal("expected an error when the sender is unreachable")
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "unreachable") {
			t.Fatalf("error should name the likely cause, got: %s", msg)
		}
		for _, leak := range []string{"http://", "dial tcp", "connection refused", "Get \""} {
			if strings.Contains(msg, leak) {
				t.Fatalf("error leaks transport detail %q: %s", leak, msg)
			}
		}
	}

	if len(r.List()) != 1 {
		t.Fatalf("offer was evicted on an unreachable sender; queue = %+v", r.List())
	}
}

func TestWithdrawn404EvictsOffer(t *testing.T) {
	s1, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "y.bin")
	_ = os.WriteFile(src, []byte("data"), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evc, err := sendTestFile(s1, ctx, "127.0.0.1", rPort, "receiver", src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = collectSendEvents(evc)
	id := r.List()[0].ID

	s1.dropOffer(id)

	if _, err := r.Receive(context.Background(), []string{id}, "", testRoot(t, t.TempDir()), -1, -1, nil); err == nil {
		t.Fatal("expected an error fetching a withdrawn offer")
	}
	if len(r.List()) != 0 {
		t.Fatalf("a 404'd offer should be evicted; queue = %+v", r.List())
	}
}

func TestSendToPeerNotAcceptingFiles(t *testing.T) {
	s1, err := NewManager("sender.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "f.bin")
	_ = os.WriteFile(src, []byte("x"), 0o644)

	_, err = sendTestFile(s1, context.Background(), "127.0.0.1", 1, "peer.netbird.cloud", src, 5*time.Second)
	if err == nil {
		t.Fatal("expected an error sending to a peer that is not accepting files")
	}
	var na *NotAcceptingError
	if !errors.As(err, &na) {
		t.Fatalf("want NotAcceptingError, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "allow-birddrop") {
		t.Fatalf("message should tell the user how to fix it, got: %s", msg)
	}
	if strings.Contains(msg, "http://") || strings.Contains(msg, "dial tcp") {
		t.Fatalf("message should not leak transport details, got: %s", msg)
	}
}

func TestReceiveEmptyQueueIsAnError(t *testing.T) {
	_, r, _ := pair(t)
	_, err := r.Receive(context.Background(), nil, "", testRoot(t, t.TempDir()), -1, -1, nil)
	if err == nil {
		t.Fatal("expected an error when there is nothing pending")
	}
	if !strings.Contains(err.Error(), "no pending files") {
		t.Fatalf("error should explain the empty queue, got: %v", err)
	}
}

// Same for reject.
func TestRejectEmptyQueueIsAnError(t *testing.T) {
	_, r, _ := pair(t)
	n, err := r.Reject(nil)
	if err == nil {
		t.Fatal("expected an error when there is nothing pending")
	}
	if n != 0 {
		t.Fatalf("rejected %d, want 0", n)
	}
}

func TestReceiverCancelStopsSender(t *testing.T) {
	s1, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, make([]byte, 32<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	evc, err := sendTestFile(s1, context.Background(), "127.0.0.1", rPort, "receiver", src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sendDone := collectSendEvents(evc)
	id := r.List()[0].ID

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(15 * time.Millisecond); cancel() }()

	_, err = r.Receive(ctx, []string{id}, "", testRoot(t, t.TempDir()), -1, -1, nil)
	if err == nil {
		t.Fatal("expected the receive to fail when canceled mid-transfer")
	}

	select {
	case ev := <-sendDone:
		if ev.State != StateCanceled {
			t.Fatalf("sender ended in %v, want StateCanceled", ev.State)
		}
		if !strings.Contains(ev.Message, "receiver canceled") {
			t.Fatalf("sender message = %q, want it to mention the receiver canceling", ev.Message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sender did not stop after the receiver canceled")
	}
}

func TestSenderCancelStopsReceiver(t *testing.T) {
	s1, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, make([]byte, 32<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	sendCtx, cancelSend := context.WithCancel(context.Background())
	evc, err := sendTestFile(s1, sendCtx, "127.0.0.1", rPort, "receiver", src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = collectSendEvents(evc)
	id := r.List()[0].ID

	go func() { time.Sleep(15 * time.Millisecond); cancelSend() }()

	done := make(chan error, 1)
	go func() {
		_, e := r.Receive(context.Background(), []string{id}, "", testRoot(t, t.TempDir()), -1, -1, nil)
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("expected receive to fail when the sender canceled mid-transfer")
		}
		if !strings.Contains(e.Error(), "canceled") {
			t.Fatalf("receiver error = %q, want it to mention cancellation", e.Error())
		}
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("receiver did not stop PROMPTLY after the sender canceled")
	}
}

func TestServeSurvivesPartialBindFailure(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	port := freePort(t)

	go func() {
		_ = m.Serve([]string{"127.0.0.1", "203.0.113.1"}, port)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.BoundAddrs()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	bound := m.BoundAddrs()
	if len(bound) != 1 {
		t.Fatalf("expected exactly 1 bound addr (the loopback), got %v", bound)
	}
	if !strings.Contains(bound[0], "127.0.0.1") {
		t.Fatalf("expected loopback to be the bound addr, got %v", bound)
	}
}

func TestCaptureWriteErrRecordsFirstFailure(t *testing.T) {
	want := errors.New("no space left on device")
	c := &captureWriteErr{w: &failingWriter{remaining: 4, err: want}}

	if _, err := c.Write([]byte("abcd")); err != nil {
		t.Fatalf("unexpected error on first write: %v", err)
	}
	if c.err != nil {
		t.Fatalf("no error expected yet, got %v", c.err)
	}

	if _, err := c.Write([]byte("efgh")); !errors.Is(err, want) {
		t.Fatalf("expected %v to be returned, got %v", want, err)
	}
	if !errors.Is(c.err, want) {
		t.Fatalf("expected %v to be recorded, got %v", want, c.err)
	}

	c.w = &failingWriter{remaining: 0, err: errors.New("some later error")}
	_, _ = c.Write([]byte("x"))
	if !errors.Is(c.err, want) {
		t.Fatalf("first error should be retained, got %v", c.err)
	}
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, f.err
	}
	if len(p) <= f.remaining {
		f.remaining -= len(p)
		return len(p), nil
	}
	n := f.remaining
	f.remaining = 0
	return n, f.err
}

func TestRemoteWriteReasonHidesReceiverPaths(t *testing.T) {
	err := &fs.PathError{
		Op:   "write",
		Path: "/home/manjaro/Downloads/.recv-3018979196.part",
		Err:  errors.New("no space left on device"),
	}
	got := remoteWriteReason(err)

	if !strings.Contains(got, "no space left on device") {
		t.Fatalf("reason lost, got %q", got)
	}
	for _, leak := range []string{"/home", "manjaro", "Downloads", ".recv-", ".part"} {
		if strings.Contains(got, leak) {
			t.Fatalf("message leaks receiver detail %q: %s", leak, got)
		}
	}

	generic := remoteWriteReason(errors.New("/home/manjaro/secret failed"))
	if strings.Contains(generic, "/home") {
		t.Fatalf("non-PathError leaked a path: %s", generic)
	}
}

func TestAddListenerAttachesAfterServeStarted(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })

	port := freePort(t)
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port) }()
	waitReady(t, port)

	if got := len(m.BoundAddrs()); got != 1 {
		t.Fatalf("expected 1 bound addr at start, got %v", m.BoundAddrs())
	}

	if err := m.AddListener("127.0.0.2"); err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	bound := m.BoundAddrs()
	if len(bound) != 2 {
		t.Fatalf("expected 2 bound addrs after attach, got %v", bound)
	}

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("late listener not reachable: %v", err)
	}
	_ = c.Close()
}

func TestAddListenerIsIdempotent(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })

	port := freePort(t)
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port) }()
	waitReady(t, port)

	for i := 0; i < 5; i++ {
		if err := m.AddListener("127.0.0.1"); err != nil {
			t.Fatalf("repeat AddListener %d: %v", i, err)
		}
	}
	if got := m.BoundAddrs(); len(got) != 1 {
		t.Fatalf("repeated attach duplicated listeners: %v", got)
	}
}

func TestAddListenerRefusedWhenNotServing(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Never served.
	if err := m.AddListener("127.0.0.1"); err == nil {
		t.Fatal("expected an error attaching to an endpoint that never served")
	}

	// And after shutdown.
	port := freePort(t)
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port) }()
	waitReady(t, port)
	_ = m.Shutdown()
	if err := m.AddListener("127.0.0.2"); err == nil {
		t.Fatal("expected an error attaching after shutdown")
	}
}

func TestServeReturnsOnShutdown(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	done := make(chan struct{})
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port); close(done) }()
	waitReady(t, port)

	_ = m.Shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestServeRetryOnSameManager(t *testing.T) {
	m, err := NewManager("host.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })

	if err := m.Serve([]string{"203.0.113.1"}, 0); err == nil {
		t.Fatal("expected first Serve to fail with nothing bindable")
	}
	if len(m.BoundAddrs()) != 0 {
		t.Fatalf("nothing should be bound after a failed Serve, got %v", m.BoundAddrs())
	}

	port := freePort(t)
	done := make(chan struct{})
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port); close(done) }()
	waitReady(t, port)
	if len(m.BoundAddrs()) != 1 {
		t.Fatalf("retry Serve should have bound 1 addr, got %v", m.BoundAddrs())
	}

	_ = m.Shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry Serve did not return after Shutdown")
	}
}

func TestShutdownReleasesEveryListener(t *testing.T) {
	m, err := NewManager("h.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	go func() { _ = m.Serve([]string{"127.0.0.1"}, port) }()
	waitReady(t, port)
	if err := m.AddListener("127.0.0.2"); err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	_ = m.Shutdown()

	time.Sleep(100 * time.Millisecond)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("%s:%d still held after Shutdown: %v", ip, port, err)
		}
		_ = ln.Close()
	}
}

func TestAddListenerRacingShutdownLeavesNoOrphan(t *testing.T) {
	for i := 0; i < 20; i++ {
		m, err := NewManager("h.netbird.cloud", nil)
		if err != nil {
			t.Fatal(err)
		}
		port := freePort(t)
		go func() { _ = m.Serve([]string{"127.0.0.1"}, port) }()
		waitReady(t, port)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.AddListener("127.0.0.2") }()
		go func() { defer wg.Done(); _ = m.Shutdown() }()
		wg.Wait()
		_ = m.Shutdown() // ensure a late-attached listener is also closed

		time.Sleep(30 * time.Millisecond)
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("iteration %d: orphaned listener on 127.0.0.2:%d: %v", i, port, err)
		}
		_ = ln.Close()
	}
}

func TestWriteFailureStripsStagingPath(t *testing.T) {
	want := errors.New("no space left on device")
	got := writeFailure(&fs.PathError{
		Op:   "write",
		Path: "/home/manjaro/Downloads/.recv-2807747101.part",
		Err:  want,
	})
	if !errors.Is(got, want) {
		t.Fatalf("reason lost: %v", got)
	}
	if s := got.Error(); s != "no space left on device" {
		t.Fatalf("expected the bare reason, got %q", s)
	}
	for _, leak := range []string{"/home", ".recv-", ".part", "write "} {
		if strings.Contains(got.Error(), leak) {
			t.Fatalf("still exposes %q: %s", leak, got.Error())
		}
	}

	plain := errors.New("some other failure")
	if got := writeFailure(plain); !errors.Is(got, plain) {
		t.Fatalf("plain error was altered: %v", got)
	}
}

func TestFailedReceiveEvictsTheDeadOffer(t *testing.T) {
	s, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "big.bin")

	if err := os.WriteFile(src, make([]byte, 256<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver", src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = collectSendEvents(evc)

	if len(r.List()) != 1 {
		t.Fatalf("expected 1 pending offer, got %d", len(r.List()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var once sync.Once
	go func() {
		<-started
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = r.Receive(ctx, nil, "", testRoot(t, t.TempDir()), -1, -1, func(ReceiveProgress) {
		once.Do(func() { close(started) })
	})
	if err == nil {
		t.Fatal("expected the canceled receive to fail")
	}

	if got := r.List(); len(got) != 0 {
		t.Fatalf("dead offer left in the queue: %+v", got)
	}
}

func TestReceiveAllClearsEveryDeadOffer(t *testing.T) {
	r, err := NewManager("receiver.netbird.cloud", nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "source unavailable: permission denied", http.StatusInternalServerError)
	}))
	defer srv.Close()

	now := time.Now()
	r.incoming["a"] = &Item{
		ID:       "a",
		Name:     "a.bin",
		From:     "sender",
		Size:     1,
		Received: now,
		fetchURL: srv.URL,
	}
	r.incoming["b"] = &Item{
		ID:       "b",
		Name:     "b.bin",
		From:     "sender",
		Size:     1,
		Received: now.Add(time.Millisecond),
		fetchURL: srv.URL,
	}

	if len(r.List()) != 2 {
		t.Fatalf("expected 2 pending offers, got %d", len(r.List()))
	}

	if _, err := r.Receive(context.Background(), nil, "", testRoot(t, t.TempDir()), -1, -1, nil); err == nil {
		t.Fatal("expected an error when every offer is dead")
	}

	if got := r.List(); len(got) != 0 {
		t.Fatalf("--all left dead offers behind: %+v", got)
	}
}

func TestReceiveRejectsSizeMismatch(t *testing.T) {
	body := []byte("X")
	sum := sha256.Sum256(body)

	m, it := fakeSenderOffer(t, "size-mismatch-test", "size-mismatch.txt", 100, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)

		_, err := w.Write(body)
		require.NoError(t, err)

		w.Header().Set(hdrSha256, hex.EncodeToString(sum[:]))
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	_, statErr := os.Stat(filepath.Join(dest, "size-mismatch.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestReceiveRejectsMissingChecksum(t *testing.T) {
	body := []byte("hello")

	m, it := fakeSenderOffer(t, "missing-checksum-test", "missing-checksum.txt", int64(len(body)), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		require.NoError(t, err)
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	_, statErr := os.Stat(filepath.Join(dest, "missing-checksum.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestReceiveRejectsChecksumMismatch(t *testing.T) {
	body := []byte("hello")

	m, it := fakeSenderOffer(t, "checksum-mismatch-test", "checksum-mismatch.txt", int64(len(body)), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)

		_, err := w.Write(body)
		require.NoError(t, err)

		w.Header().Set(
			hdrSha256,
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	_, statErr := os.Stat(filepath.Join(dest, "checksum-mismatch.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestReceiveDoesNotFollowFetchRedirect(t *testing.T) {
	var redirected bool

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	sender := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, pathStatus):
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(r.URL.Path, pathFetch):
			http.Redirect(w, r, target.URL, http.StatusFound)

		default:
			http.NotFound(w, r)
		}
	}))
	defer sender.Close()

	u, err := url.Parse(sender.URL)
	require.NoError(t, err)

	m, err := NewManager("receiver.test", nil)
	require.NoError(t, err)

	dest := t.TempDir()

	it := &Item{
		ID:       "redirect-test",
		Name:     "redirect.txt",
		From:     "sender.test",
		Size:     1,
		IsDir:    false,
		fetchURL: sender.URL + pathFetch + "?id=redirect-test",
		senderIP: u.Hostname(),
		expires:  time.Now().Add(time.Minute),
	}

	m.mu.Lock()
	m.incoming[it.ID] = it
	m.mu.Unlock()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)
	require.False(t, redirected, "Birddrop must not follow redirects away from the original peer")
}

func TestReceiveRejectsTruncatedBody(t *testing.T) {
	body := []byte("X")

	m, it := fakeSenderOffer(t, "truncated-body-test", "truncated.txt", 100, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)

		_, err := w.Write(body)
		require.NoError(t, err)
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	_, statErr := os.Stat(filepath.Join(dest, "truncated.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestReceiveRejectsDuplicateChecksumTrailer(t *testing.T) {
	body := []byte("hello")
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])

	m, it := fakeSenderOffer(t, "duplicate-checksum-test", "duplicate-checksum.txt", int64(len(body)), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)

		_, err := w.Write(body)
		require.NoError(t, err)

		w.Header().Add(hdrSha256, good)
		w.Header().Add(
			hdrSha256,
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	_, statErr := os.Stat(filepath.Join(dest, "duplicate-checksum.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestReceiveStopsAfterAdvertisedSize(t *testing.T) {
	body := bytes.Repeat([]byte("X"), 1<<20) // 1 MiB

	m, it := fakeSenderOffer(t, "oversized-body-test", "oversized.txt", 1, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(body)
	})
	dest := t.TempDir()

	results, err := m.Receive(
		context.Background(),
		[]string{it.ID},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)

	require.ErrorContains(t, err, "expected 1 bytes, received 2")

	_, statErr := os.Stat(filepath.Join(dest, "oversized.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestValidateOfferMetaRejectsInvalidOffers(t *testing.T) {
	const okID = "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name    string
		meta    offerMeta
		wantErr string
	}{
		{"oversized size", offerMeta{ID: okID, Name: "large.bin", Size: maxOfferSize + 1}, "offer size too large"},
		{"oversized clipboard", offerMeta{ID: okID, Name: "clipboard", Size: maxClipboardSize + 1, Type: PayloadClipboard}, "clipboard offer too large"},
		{"unknown payload type", offerMeta{ID: okID, Name: "payload", Size: 1, Type: PayloadType("unknown")}, "invalid offer type"},
		{"missing payload type", offerMeta{ID: okID, Name: "item", Size: 1}, "invalid offer type"},
		{"file marked directory", offerMeta{ID: okID, Name: "item", Size: 1, Type: PayloadFile, IsDir: true}, "file offer cannot be a directory"},
		{"directory not marked directory", offerMeta{ID: okID, Name: "item", Size: 1, Type: PayloadDirectory}, "directory offer must set is_dir"},
		{"clipboard marked directory", offerMeta{ID: okID, Name: "item", Size: 1, Type: PayloadClipboard, IsDir: true}, "clipboard offer cannot be a directory"},
		{"special characters in id", offerMeta{ID: "0123456789abcdef0123456789abcde!", Name: "file.txt", Size: 1}, "invalid offer id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := tt.meta
			require.ErrorContains(t, validateOfferMeta(&meta), tt.wantErr)
		})
	}
}

func TestNewIDProduces128BitHexID(t *testing.T) {
	id, err := newID()
	require.NoError(t, err)

	require.Len(t, id, 32)

	decoded, err := hex.DecodeString(id)
	require.NoError(t, err)
	require.Len(t, decoded, 16)
}

func TestDecodeOfferRejectsDuplicateFields(t *testing.T) {
	body := strings.NewReader(`{
		"id":"good",
		"id":"evil",
		"name":"file.txt",
		"size":1
	}`)

	var meta offerMeta
	err := decodeOffer(body, &meta)

	require.Error(t, err)
}

func TestDecodeOfferRejectsUnknownFields(t *testing.T) {
	body := strings.NewReader(`{
		"id":"test",
		"name":"file.txt",
		"size":1,
		"unexpected":"value"
	}`)

	var meta offerMeta
	err := decodeOffer(body, &meta)

	require.Error(t, err)
}

func TestReceiveRejectsStalledBody(t *testing.T) {
	started := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, pathStatus):
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(r.URL.Path, pathFetch):
			w.Header().Set("Trailer", hdrSha256)
			w.WriteHeader(http.StatusOK)

			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

			close(started)

			<-r.Context().Done()

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	m, err := NewManager("receiver.test", nil)
	require.NoError(t, err)

	m.receiveIdleTimeout = 100 * time.Millisecond

	dest := t.TempDir()

	it := &Item{
		ID:       "stalled-body-test",
		Name:     "stalled.txt",
		From:     "sender.test",
		Size:     1,
		IsDir:    false,
		fetchURL: srv.URL + pathFetch + "?id=stalled-body-test",
		senderIP: u.Hostname(),
		expires:  time.Now().Add(time.Minute),
	}

	m.mu.Lock()
	m.incoming[it.ID] = it
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := m.Receive(
			context.Background(),
			[]string{it.ID},
			dest,
			testRoot(t, dest),
			-1,
			-1,
			nil,
		)
		done <- err
	}()

	<-started

	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorContains(t, err, "transfer stalled")

	case <-time.After(2 * time.Second):
		t.Fatal("stalled transfer was not aborted")
	}

	_, statErr := os.Stat(filepath.Join(dest, "stalled.txt"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestOfferRequestBodyCanStall(t *testing.T) {
	m, err := NewManager("receiver.test", nil)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	srv := &http.Server{
		Handler:           http.HandlerFunc(m.handleOffer),
		ReadHeaderTimeout: 100 * time.Millisecond,
		ReadTimeout:       100 * time.Millisecond,
	}

	go func() {
		_ = srv.Serve(ln)
	}()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(
		conn,
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
		pathOffer,
		ln.Addr().String(),
	)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	var netErr net.Error
	if errors.As(err, &netErr) {
		require.False(t, netErr.Timeout(), "server should terminate the stalled request")
	}
}

func TestReceiveRejectsDirectoryChangedAfterOffer(t *testing.T) {
	s, r, rPort := pair(t)

	dir := filepath.Join(t.TempDir(), "project")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	file := filepath.Join(dir, "data.txt")
	require.NoError(t, os.WriteFile(file, []byte("small"), 0o644))

	evc, err := s.Send(
		authenticatedContext(t),
		"127.0.0.1",
		rPort,
		"receiver",
		dir,
		10*time.Second,
	)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		file,
		bytes.Repeat([]byte("X"), 64<<10),
		0o644,
	))

	dest := t.TempDir()

	results, err := r.Receive(
		context.Background(),
		nil,
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Empty(t, results)
	require.ErrorContains(t, err, "size mismatch")

	_, statErr := os.Stat(filepath.Join(dest, "project"))
	require.ErrorIs(t, statErr, os.ErrNotExist)

	for range evc {
	}
}

func TestReceiveRetriesCompleteAck(t *testing.T) {
	body := []byte("hello")
	sum := sha256.Sum256(body)

	var (
		mu            sync.Mutex
		completeCalls int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pathFetch:
			w.Header().Set("Trailer", hdrSha256)
			w.WriteHeader(http.StatusOK)

			_, err := w.Write(body)
			require.NoError(t, err)

			w.Header().Set(hdrSha256, hex.EncodeToString(sum[:]))

		case pathStatus:
			w.WriteHeader(http.StatusOK)

		case pathComplete:
			mu.Lock()
			completeCalls++
			call := completeCalls
			mu.Unlock()

			if call == 1 {
				http.Error(w, "temporary failure", http.StatusServiceUnavailable)
				return
			}

			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	r, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Shutdown() })

	r.incoming["ack-test-0001"] = &Item{
		ID:       "ack-test-0001",
		Name:     "ack-test.txt",
		From:     "sender.netbird.cloud",
		Size:     int64(len(body)),
		senderIP: u.Hostname(),
		fetchURL: srv.URL + pathFetch + "?id=ack-test",
		expires:  time.Now().Add(time.Minute),
	}

	dest := t.TempDir()

	results, err := r.Receive(
		context.Background(),
		[]string{"ack-test-0001"},
		dest,
		testRoot(t, dest),
		-1,
		-1,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, results, 1)

	mu.Lock()
	calls := completeCalls
	mu.Unlock()

	require.Equal(t, 2, calls)
}

func TestReceiveFailsWhenCompleteAckCannotBeDelivered(t *testing.T) {
	body := []byte("hello")
	sum := sha256.Sum256(body)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pathFetch:
			w.Header().Set("Trailer", hdrSha256)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			w.Header().Set(hdrSha256, hex.EncodeToString(sum[:]))

		case pathStatus:
			w.WriteHeader(http.StatusOK)

		case pathComplete:
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	r, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Shutdown() })

	r.incoming["ack-test-0001"] = &Item{
		ID:       "ack-test-0001",
		Name:     "ack-test.txt",
		From:     "sender.netbird.cloud",
		Size:     int64(len(body)),
		senderIP: u.Hostname(),
		fetchURL: srv.URL + pathFetch + "?id=ack-test",
		expires:  time.Now().Add(time.Minute),
	}

	_, err = r.Receive(
		context.Background(),
		[]string{"ack-test-0001"},
		"",
		testRoot(t, t.TempDir()), -1,
		-1,
		nil,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "could not confirm delivery to sender")

	items := r.List()
	require.Empty(
		t,
		items,
		"successfully committed receives must not remain queued when only the completion acknowledgement fails",
	)
}

func TestFailEndsSenderWithError(t *testing.T) {
	s, r, rPort := pair(t)

	src := filepath.Join(t.TempDir(), "failure.bin")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o644))

	evc, err := sendTestFile(
		s,
		context.Background(),
		"127.0.0.1",
		rPort,
		"receiver.netbird.cloud",
		src,
		10*time.Second,
	)
	require.NoError(t, err)

	final := collectSendEvents(evc)

	items := r.List()
	require.Len(t, items, 1)

	failURL := birddropURL(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(s.selfPort)),
		pathFail,
		items[0].ID,
	)

	req, err := http.NewRequest(
		http.MethodPost,
		failURL,
		strings.NewReader("receiver stopped the transfer because it stalled"),
	)
	require.NoError(t, err)

	resp, err := newHTTPClient(5 * time.Second).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case ev := <-final:
		require.Equal(t, StateError, ev.State)
		require.Contains(t, ev.Message, "stalled")

	case <-time.After(3 * time.Second):
		t.Fatal("sender did not reach StateError after receiver failure")
	}
}

func TestCompleteUnknownOfferIsRejected(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		birddropURL("127.0.0.1", pathComplete, "0123456789abcdef0123456789abcdef"),
		nil,
	)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()

	m.handleComplete(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCompleteRetryUsesTombstone(t *testing.T) {
	s, r, rPort := pair(t)

	src := filepath.Join(t.TempDir(), "complete-retry.txt")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o644))

	evc, err := sendTestFile(
		s,
		context.Background(),
		"127.0.0.1",
		rPort,
		"receiver.netbird.cloud",
		src,
		10*time.Second,
	)
	require.NoError(t, err)

	final := collectSendEvents(evc)

	items := r.List()
	require.Len(t, items, 1)

	addrs := s.BoundAddrs()
	require.Len(t, addrs, 1)

	completeURL := birddropURL(addrs[0], pathComplete, items[0].ID)

	postComplete := func() int {
		req, err := http.NewRequest(http.MethodPost, completeURL, nil)
		require.NoError(t, err)

		resp, err := newHTTPClient(5 * time.Second).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		return resp.StatusCode
	}

	require.Equal(t, http.StatusOK, postComplete())

	select {
	case ev := <-final:
		require.Equal(t, StateDelivered, ev.State)
	case <-time.After(3 * time.Second):
		t.Fatal("sender did not reach StateDelivered")
	}

	require.Equal(t, http.StatusOK, postComplete())
}

func TestCompleteTombstoneRejectsWrongPeer(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	id := "0123456789abcdef0123456789abcdef"

	m.mu.Lock()
	m.completed[id] = completionTombstone{
		targetIP: "127.0.0.1",
		expires:  time.Now().Add(completionTombstoneTTL),
	}
	m.mu.Unlock()

	req := httptest.NewRequest(
		http.MethodPost,
		birddropURL("127.0.0.1", pathComplete, id),
		nil,
	)
	req.RemoteAddr = "127.0.0.2:12345"

	rec := httptest.NewRecorder()

	m.handleComplete(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDuplicateOfferID(t *testing.T) {
	original := offerMeta{ID: "0123456789abcdef0123456789abcdef", Name: "original.txt", Size: 10, Type: PayloadFile, Port: DefaultPort}
	changed := original
	changed.Name, changed.Size = "changed.txt", 20

	tests := []struct {
		name     string
		remoteIP string
		meta     offerMeta
		wantCode int
	}{
		{"identical retry from the same peer is idempotent", "127.0.0.1", original, http.StatusOK},
		{"same id from a different peer", "127.0.0.2", changed, http.StatusConflict},
		{"same id from the same peer with changed metadata", "127.0.0.1", changed, http.StatusConflict},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewManager("receiver.netbird.cloud", nil)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, postOffer(t, m, "127.0.0.1", original).Code)
			require.Equal(t, tc.wantCode, postOffer(t, m, tc.remoteIP, tc.meta).Code)

			items := m.List()
			require.Len(t, items, 1)
			require.Equal(t, "original.txt", items[0].Name)
			require.Equal(t, "127.0.0.1", items[0].senderIP)
			require.Equal(t, int64(10), items[0].Size)
		})
	}
}

func TestSweepExpiredRemovesCompletionTombstones(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	now := time.Now()

	m.completed["expired"] = completionTombstone{
		targetIP: "127.0.0.1",
		expires:  now.Add(-time.Second),
	}
	m.completed["live"] = completionTombstone{
		targetIP: "127.0.0.1",
		expires:  now.Add(time.Minute),
	}

	m.sweepExpired(now)

	m.mu.Lock()
	defer m.mu.Unlock()

	require.NotContains(t, m.completed, "expired")
	require.Contains(t, m.completed, "live")
}

func TestOfferRejectedWhenIncomingQueueIsFull(t *testing.T) {
	m, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	now := time.Now()

	m.mu.Lock()
	for i := 0; i < maxIncomingOffers; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.incoming[id] = &Item{
			ID:       id,
			Name:     "pending.txt",
			Size:     1,
			Received: now,
			senderIP: fmt.Sprintf("100.64.%d.%d", i/250, i%250+1),
			expires:  now.Add(time.Hour),
		}
	}
	m.mu.Unlock()

	rec := postOffer(t, m, "127.0.0.1", offerMeta{
		ID:   "ffffffffffffffffffffffffffffffff",
		Name: "overflow.txt",
		Size: 1,
		Type: PayloadFile,
		Port: DefaultPort,
	})

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "too many pending offers\n", rec.Body.String(), "the global limit must be what refused it")
	require.Len(t, m.List(), maxIncomingOffers)
}

func TestOfferRejectedWhenPeerQueueIsFull(t *testing.T) {
	m, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	now := time.Now()
	peerIP := "127.0.0.1"

	m.mu.Lock()
	for i := 0; i < maxIncomingOffersPerPeer; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.incoming[id] = &Item{
			ID:       id,
			Name:     "pending.txt",
			Size:     1,
			Received: now,
			senderIP: peerIP,
			expires:  now.Add(time.Hour),
		}
	}
	m.mu.Unlock()

	rec := postOffer(t, m, peerIP, offerMeta{
		ID:   "ffffffffffffffffffffffffffffffff",
		Name: "overflow.txt",
		Size: 1,
		Type: PayloadFile,
		Port: DefaultPort,
	})

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Contains(t, rec.Body.String(), "from this peer", "the per-peer limit must be what refused it")
	require.Len(t, m.List(), maxIncomingOffersPerPeer)
}

func TestPeerQueueLimitDoesNotBlockOtherPeers(t *testing.T) {
	m, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	now := time.Now()

	m.mu.Lock()
	for i := 0; i < maxIncomingOffersPerPeer; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.incoming[id] = &Item{
			ID:       id,
			Name:     "pending.txt",
			Size:     1,
			Received: now,
			senderIP: "127.0.0.1",
			expires:  now.Add(time.Hour),
		}
	}
	m.mu.Unlock()

	rec := postOffer(t, m, "127.0.0.2", offerMeta{
		ID:   "ffffffffffffffffffffffffffffffff",
		Name: "other-peer.txt",
		Size: 1,
		Type: PayloadFile,
		Port: DefaultPort,
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, m.List(), maxIncomingOffersPerPeer+1)
}

func TestConcurrentFetchesForSameOfferRejectSecondFetch(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	src := filepath.Join(t.TempDir(), "file.bin")
	require.NoError(t, os.WriteFile(src, bytes.Repeat([]byte("x"), 1024), 0o644))

	f, err := os.Open(src)
	require.NoError(t, err)

	id := "0123456789abcdef0123456789abcdef"

	o := &outOffer{
		id:          id,
		file:        f,
		name:        "file.bin",
		size:        1024,
		targetIP:    "127.0.0.1",
		pub:         make(chan SendEvent, 16),
		terminated:  make(chan struct{}),
		serveCancel: make(chan struct{}),
	}
	t.Cleanup(func() { m.cleanupOffer(o) })

	m.mu.Lock()
	m.outgoing[id] = o
	m.mu.Unlock()

	o.mu.Lock()
	o.fetching = true
	o.mu.Unlock()

	req := httptest.NewRequest(
		http.MethodGet,
		birddropURL("sender", pathFetch, id),
		nil,
	)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	m.handleFetch(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
}

func TestFetchGuardIsReleasedAfterRequest(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	src := filepath.Join(t.TempDir(), "file.bin")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))

	f, err := os.Open(src)
	require.NoError(t, err)

	id := "0123456789abcdef0123456789abcdef"

	o := &outOffer{
		id:          id,
		file:        f,
		name:        "file.bin",
		size:        5,
		targetIP:    "127.0.0.1",
		pub:         make(chan SendEvent, 16),
		terminated:  make(chan struct{}),
		serveCancel: make(chan struct{}),
	}
	t.Cleanup(func() { m.cleanupOffer(o) })

	m.mu.Lock()
	m.outgoing[id] = o
	m.mu.Unlock()

	fetch := func() int {
		req := httptest.NewRequest(
			http.MethodGet,
			birddropURL("sender", pathFetch, id),
			nil,
		)
		req.RemoteAddr = "127.0.0.1:12345"

		rec := httptest.NewRecorder()
		m.handleFetch(rec, req)

		return rec.Code
	}

	require.Equal(t, http.StatusOK, fetch())
	require.Equal(t, http.StatusOK, fetch())
}

func TestSendClipboardRejectsEmptyText(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	events, err := m.SendClipboard(
		context.Background(),
		"127.0.0.1",
		DefaultPort,
		"receiver.netbird.cloud",
		"",
		time.Minute,
	)

	require.Nil(t, events)
	require.ErrorContains(t, err, "clipboard is empty")
}

func TestSendClipboardRejectsOversizedText(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	text := strings.Repeat("a", int(maxClipboardSize)+1)

	events, err := m.SendClipboard(
		context.Background(),
		"127.0.0.1",
		DefaultPort,
		"receiver.netbird.cloud",
		text,
		time.Minute,
	)

	require.Nil(t, events)
	require.ErrorContains(t, err, "clipboard is too large")
}

func TestClipboardTransfer(t *testing.T) {
	sender, receiver, receiverPort := pair(t)

	const text = "hello from clipboard\nsecond line"

	events, err := sender.SendClipboard(
		context.Background(),
		"127.0.0.1",
		receiverPort,
		"receiver.netbird.cloud",
		text,
		time.Minute,
	)
	require.NoError(t, err)

	var waiting SendEvent
	select {
	case waiting = <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for clipboard offer")
	}

	require.Equal(t, StateWaiting, waiting.State)
	require.Equal(t, PayloadClipboard, waiting.Type)
	require.Equal(t, "clipboard", waiting.Name)
	require.Equal(t, int64(len(text)), waiting.Total)
	require.False(t, waiting.IsDir)

	items := receiver.List()
	require.Len(t, items, 1)

	item := items[0]
	require.Equal(t, PayloadClipboard, item.Type)
	require.False(t, item.IsDir)
	require.Equal(t, int64(len(text)), item.Size)

	results, err := receiver.Receive(
		context.Background(),
		[]string{item.ID},
		"",
		nil,
		-1,
		-1,
		nil,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	require.Equal(t, item.ID, result.ID)
	require.Equal(t, PayloadClipboard, result.Type)
	require.Equal(t, text, result.ClipboardText)
	require.Equal(t, int64(len(text)), result.Bytes)
	require.Empty(t, result.SavedAs)
	require.False(t, result.IsDir)

	var final SendEvent
	for ev := range events {
		final = ev
	}

	require.Equal(t, StateDelivered, final.State)
	require.Equal(t, PayloadClipboard, final.Type)
	require.False(t, final.IsDir)
}

func TestSendFileRejectsWhenPeerOutgoingLimitReached(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	targetIP := "127.0.0.1"

	m.mu.Lock()
	for i := 0; i < maxOutgoingOffersPerPeer; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.outgoing[id] = &outOffer{
			id:       id,
			targetIP: targetIP,
		}
	}
	m.mu.Unlock()

	path := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o644))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	_, err = m.SendFile(
		context.Background(),
		targetIP,
		DefaultPort,
		"peer.netbird.cloud",
		f,
		time.Minute,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "too many pending sends to peer")
}

func TestSendFileRejectsWhenGlobalOutgoingLimitReached(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	m.mu.Lock()
	for i := 0; i < maxOutgoingOffers; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.outgoing[id] = &outOffer{
			id:       id,
			targetIP: fmt.Sprintf("10.0.%d.%d", i/254, i%254+1),
		}
	}
	m.mu.Unlock()

	path := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o644))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	_, err = m.SendFile(
		context.Background(),
		"192.0.2.1",
		DefaultPort,
		"peer.netbird.cloud",
		f,
		time.Minute,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "too many pending outgoing offers")
}

func TestSendDirectoryRejectsWhenPeerOutgoingLimitReached(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	targetIP := "127.0.0.1"

	m.mu.Lock()
	for i := 0; i < maxOutgoingOffersPerPeer; i++ {
		id := fmt.Sprintf("%032x", i+1)
		m.outgoing[id] = &outOffer{
			id:       id,
			targetIP: targetIP,
		}
	}
	m.mu.Unlock()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "file.txt"),
		[]byte("hello"),
		0o644,
	))

	_, err = m.Send(
		context.Background(),
		targetIP,
		DefaultPort,
		"peer.netbird.cloud",
		dir,
		time.Minute,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "too many pending sends to peer")
}

func TestFetchStopsWhenReceiverStopsReading(t *testing.T) {
	m, err := NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	m.sendIdleTimeout = 100 * time.Millisecond

	const fileSize = 32 << 20

	path := filepath.Join(t.TempDir(), "large.bin")
	require.NoError(t, os.WriteFile(path, make([]byte, fileSize), 0o644))

	f, err := os.Open(path)
	require.NoError(t, err)

	id := "0123456789abcdef0123456789abcdef"

	o := &outOffer{
		id:          id,
		file:        f,
		name:        "large.bin",
		size:        fileSize,
		targetIP:    "127.0.0.1",
		pub:         make(chan SendEvent, 16),
		terminated:  make(chan struct{}),
		serveCancel: make(chan struct{}),
	}

	m.mu.Lock()
	m.outgoing[id] = o
	m.mu.Unlock()

	t.Cleanup(func() {
		o.stopServing()
		m.dropOffer(id)
		m.cleanupOffer(o)
	})

	srv := httptest.NewUnstartedServer(http.HandlerFunc(m.handleFetch))
	srv.Start()
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	require.NoError(t, tcpConn.SetReadBuffer(1024))

	_, err = fmt.Fprintf(
		conn,
		"GET /birddrop/fetch?id=%s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
		id,
	)
	require.NoError(t, err)

	reader := bufio.NewReader(conn)

	resp, err := http.ReadResponse(
		reader,
		&http.Request{Method: http.MethodGet},
	)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Eventually(t, func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		return !o.fetching
	}, 2*time.Second, 10*time.Millisecond)

	m.mu.Lock()
	_, exists := m.outgoing[id]
	m.mu.Unlock()

	require.False(t, exists, "stalled fetch should remove the outgoing offer")

	require.NoError(t, conn.Close())
	_ = resp.Body.Close()
}

func TestHTTPHandlerPerPeerConcurrencyLimit(t *testing.T) {
	entered := make(chan struct{}, maxConcurrentHTTPHandlersPerPeer)
	release := make(chan struct{})

	var releaseOnce sync.Once
	unblock := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}

	allowPeer := func(string) (string, bool) {
		entered <- struct{}{}
		<-release
		return "peer.netbird.cloud", true
	}

	m, err := NewManager("receiver.netbird.cloud", allowPeer)
	require.NoError(t, err)

	handler := m.limitHTTP(http.HandlerFunc(m.handleOffer))
	srv := httptest.NewServer(handler)

	defer func() {
		unblock()
		srv.Close()
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	var wg sync.WaitGroup

	for i := 0; i < maxConcurrentHTTPHandlersPerPeer; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			req, err := http.NewRequest(
				http.MethodPost,
				srv.URL+pathOffer,
				strings.NewReader(`{}`),
			)
			if err != nil {
				return
			}

			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}

	for i := 0; i < maxConcurrentHTTPHandlersPerPeer; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatalf(
				"only %d of %d handlers entered",
				i,
				maxConcurrentHTTPHandlersPerPeer,
			)
		}
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+pathOffer,
		strings.NewReader(`{}`),
	)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

	unblock()
	wg.Wait()
}

func TestHTTPHandlerGlobalConcurrencyLimit(t *testing.T) {
	entered := make(chan struct{}, maxConcurrentHTTPHandlers)
	release := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	m, err := NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	limited := m.limitHTTP(handler)

	var wg sync.WaitGroup

	for i := 0; i < maxConcurrentHTTPHandlers; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodGet, "/birddrop/ping", nil)
			req.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", i+1)

			rec := httptest.NewRecorder()
			limited.ServeHTTP(rec, req)
		}(i)
	}

	for i := 0; i < maxConcurrentHTTPHandlers; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			wg.Wait()
			t.Fatalf(
				"only %d of %d handlers entered",
				i,
				maxConcurrentHTTPHandlers,
			)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/birddrop/ping", nil)
	req.RemoteAddr = "10.0.1.1:12345"

	rec := httptest.NewRecorder()
	limited.ServeHTTP(rec, req)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	close(release)
	wg.Wait()
}

func TestUntarIntoRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	tarPath := filepath.Join(t.TempDir(), "payload.tar")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	tw := tar.NewWriter(f)

	data := []byte("escaped through symlink")

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "link/escaped.txt",
		Mode: 0o644,
		Size: int64(len(data)),
	}))

	_, err = tw.Write(data)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	_, _, err = untarFile(t, tarPath, testRoot(t, root))
	require.Error(t, err)

	_, err = os.Stat(filepath.Join(outside, "escaped.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestUntarIntoExtractsExplicitDirectories(t *testing.T) {
	dest := t.TempDir()
	tarPath := filepath.Join(t.TempDir(), "payload.tar")

	f, err := os.Create(tarPath)
	require.NoError(t, err)

	tw := tar.NewWriter(f)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "parent/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}))

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "parent/child/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}))

	data := []byte("nested")

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "parent/child/file.txt",
		Mode: 0o644,
		Size: int64(len(data)),
	}))

	_, err = tw.Write(data)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	files, written, err := untarFile(t, tarPath, testRoot(t, dest))
	require.NoError(t, err)

	require.Equal(t, 1, files)
	require.Equal(t, int64(len(data)), written)

	got, err := os.ReadFile(
		filepath.Join(dest, "parent", "child", "file.txt"),
	)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

func TestCommitPartDirDoesNotFollowExistingSymlink(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(parent, "received")))

	parentRoot := testRoot(t, parent)
	hidden, dir, err := createPartDir(parentRoot, "0123456789abcdef")
	require.NoError(t, err)
	require.NoError(t, dir.WriteFile("file.txt", []byte("safe"), 0o644))

	path, err := commitPartDir(parentRoot, dir, hidden, parent, "received", owner{uid: -1, gid: -1})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(parent, "received (1)"), path)

	_, err = os.Stat(filepath.Join(outside, "file.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
	got, err := os.ReadFile(filepath.Join(path, "file.txt"))
	require.NoError(t, err)
	require.Equal(t, "safe", string(got))
}
func TestCommitPartFileDoesNotOverwriteExistingFile(t *testing.T) {
	destDir := t.TempDir()
	existingPath := filepath.Join(destDir, "document.txt")
	require.NoError(t, os.WriteFile(existingPath, []byte("important existing file"), 0o644))

	out := receiveIntoPart(t, testRoot(t, destDir), destDir, "document.txt", "received from birddrop")
	require.Equal(t, filepath.Join(destDir, "document (1).txt"), out)

	got, err := os.ReadFile(existingPath)
	require.NoError(t, err)
	require.Equal(t, "important existing file", string(got))
	got, err = os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, "received from birddrop", string(got))
}

// receiveIntoPart writes data to a new part file and commits it as name.
func receiveIntoPart(t *testing.T, root *os.Root, destDir, name, data string) string {
	t.Helper()
	f, hidden, err := createPartFile(root, "0123456789abcdef")
	require.NoError(t, err)
	_, err = f.WriteString(data)
	require.NoError(t, err)
	out, err := commitPartFile(root, f, hidden, destDir, name, owner{uid: -1, gid: -1})
	require.NoError(t, err)
	return out
}
func TestCommitPartFileConcurrentClaimsAreUnique(t *testing.T) {
	destDir := t.TempDir()

	destRoot, err := os.OpenRoot(destDir)
	require.NoError(t, err)
	defer destRoot.Close()

	data := []byte("received from birddrop")

	const workers = 32

	results := make(chan string, workers)
	errs := make(chan error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()

			f, hidden, err := createPartFile(destRoot, "0123456789abcdef")
			if err == nil {
				_, err = f.Write(data)
			}
			if err != nil {
				errs <- err
				return
			}
			out, err := commitPartFile(destRoot, f, hidden, destDir, "document.txt", owner{uid: -1, gid: -1})
			if err != nil {
				errs <- err
				return
			}

			results <- out
		}()
	}

	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	seen := make(map[string]struct{}, workers)

	for out := range results {
		_, exists := seen[out]
		require.False(
			t,
			exists,
			"destination filename was claimed twice: %s",
			out,
		)

		seen[out] = struct{}{}

		got, err := os.ReadFile(out)
		require.NoError(t, err)
		require.Equal(t, data, got)
	}

	require.Len(t, seen, workers)
}

func TestDirectoryReceiveCleansPartialExtractionOnError(t *testing.T) {
	destDir := t.TempDir()

	tarPath := filepath.Join(t.TempDir(), "payload.tar")

	f, err := os.Create(tarPath)
	require.NoError(t, err)

	tw := tar.NewWriter(f)

	first := []byte("partial file")

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "good.txt",
		Mode: 0o644,
		Size: int64(len(first)),
	}))

	_, err = tw.Write(first)
	require.NoError(t, err)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "../escape.txt",
		Mode: 0o644,
		Size: 0,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	destRoot, err := os.OpenRoot(destDir)
	require.NoError(t, err)
	defer destRoot.Close()

	hidden, root, err := createPartDir(destRoot, "0123456789abcdef")
	require.NoError(t, err)
	outDir := filepath.Join(destDir, hidden)

	_, _, extractErr := untarFile(t, tarPath, root)
	require.Error(t, extractErr)

	require.NoError(t, clearRoot(root))
	require.NoError(t, root.Close())

	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	require.Empty(t, entries)

	_, err = os.Stat(filepath.Join(destDir, "escape.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRootedCleanupDoesNotDeleteReplacementDirectory(t *testing.T) {
	parent := t.TempDir()

	parentRoot, err := os.OpenRoot(parent)
	require.NoError(t, err)
	defer parentRoot.Close()

	hidden, root, err := createPartDir(parentRoot, "0123456789abcdef")
	require.NoError(t, err)
	outDir := filepath.Join(parent, hidden)

	require.NoError(
		t,
		root.WriteFile("partial.txt", []byte("partial"), 0o644),
	)

	moved := filepath.Join(parent, "moved-received")
	require.NoError(t, os.Rename(outDir, moved))

	require.NoError(t, os.Mkdir(outDir, 0o755))

	victim := filepath.Join(outDir, "important.txt")
	require.NoError(
		t,
		os.WriteFile(victim, []byte("important local data"), 0o644),
	)

	require.NoError(t, clearRoot(root))
	require.NoError(t, root.Close())

	got, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, []byte("important local data"), got)

	entries, err := os.ReadDir(moved)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestValidWindowsNameRejectsReservedNames(t *testing.T) {
	bad := []string{
		"CON",
		"con",
		"CON.txt",
		"PRN",
		"AUX.log",
		"NUL",
		"COM1",
		"COM9.txt",
		"LPT1",
		"LPT9.log",
		"file.txt:stream",
		"name:",
		"file. ",
	}

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			require.False(t, validWindowsName(name))
		})
	}
}

func TestValidWindowsNameAcceptsNormalNames(t *testing.T) {
	good := []string{
		"document.txt",
		"console.txt",
		"com10.txt",
		"lpt10",
		"photo.jpg",
		"folder",
	}

	for _, name := range good {
		t.Run(name, func(t *testing.T) {
			require.True(t, validWindowsName(name))
		})
	}
}

func TestSafeTarNameRejectsWindowsInvalidComponents(t *testing.T) {
	bad := []string{
		"CON",
		"folder/NUL.txt",
		"folder/COM1/data.txt",
		"folder/file.txt:stream",
	}

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			require.Error(t, safeTarName(name))
		})
	}
}

func TestSafeTarNameRejectsWindowsBackslashTraversal(t *testing.T) {
	bad := []string{
		`..\escape.txt`,
		`folder\..\escape.txt`,
		`folder\sub\..\..\escape.txt`,
		`\absolute.txt`,
	}

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			require.Error(t, safeTarName(name))
		})
	}
}

func TestUntarRejectsCaseInsensitiveNameCollision(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "collision.tar")

	f, err := os.Create(tarPath)
	require.NoError(t, err)

	tw := tar.NewWriter(f)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "File.txt",
		Mode: 0o644,
		Size: int64(len("first")),
	}))
	_, err = tw.Write([]byte("first"))
	require.NoError(t, err)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "file.txt",
		Mode: 0o644,
		Size: int64(len("second")),
	}))
	_, err = tw.Write([]byte("second"))
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	dest := t.TempDir()

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	_, _, err = untarFile(t, tarPath, root)
	require.Error(t, err)
	require.Contains(t, err.Error(), "case-insensitive filename collision")
}

func TestHTTPRoutesRejectWrongMethod(t *testing.T) {
	m := &Manager{}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{
			name:    "offer",
			handler: m.handleOffer,
			method:  http.MethodGet,
		},
		{
			name:    "fetch",
			handler: m.handleFetch,
			method:  http.MethodPost,
		},
		{
			name:    "reject",
			handler: m.handleReject,
			method:  http.MethodGet,
		},
		{
			name:    "withdraw",
			handler: m.handleWithdraw,
			method:  http.MethodGet,
		},
		{
			name:    "complete",
			handler: m.handleComplete,
			method:  http.MethodGet,
		},
		{
			name:    "fail",
			handler: m.handleFail,
			method:  http.MethodGet,
		},
		{
			name:    "status",
			handler: m.handleStatus,
			method:  http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/birddrop/"+tt.name, nil)
			req.RemoteAddr = "127.0.0.2:12345"

			rec := httptest.NewRecorder()
			tt.handler(rec, req)

			require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

func TestOfferHandlersRejectWrongPeer(t *testing.T) {
	const (
		id       = "0123456789abcdef0123456789abcdef"
		targetIP = "127.0.0.2"
		wrongIP  = "127.0.0.3"
	)

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(*Manager) http.HandlerFunc
	}{
		{"status", http.MethodGet, "/birddrop/status", "", func(m *Manager) http.HandlerFunc { return m.handleStatus }},
		{"reject", http.MethodPost, "/birddrop/reject", "", func(m *Manager) http.HandlerFunc { return m.handleReject }},
		{"fail", http.MethodPost, "/birddrop/fail", "fake failure", func(m *Manager) http.HandlerFunc { return m.handleFail }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &outOffer{targetIP: targetIP}
			m := &Manager{outgoing: map[string]*outOffer{id: o}}

			req := httptest.NewRequest(tc.method, tc.path+"?id="+id, strings.NewReader(tc.body))
			req.RemoteAddr = wrongIP + ":12345"
			rec := httptest.NewRecorder()
			tc.handler(m)(rec, req)

			require.Equal(t, http.StatusForbidden, rec.Code)
			m.mu.Lock()
			got := m.outgoing[id]
			m.mu.Unlock()
			require.Same(t, o, got, "a wrong peer must not affect the outgoing offer")
		})
	}
}

func TestWithdrawFromWrongPeerDoesNotRemoveOffer(t *testing.T) {
	const (
		id       = "0123456789abcdef0123456789abcdef"
		senderIP = "127.0.0.2"
		wrongIP  = "127.0.0.3"
	)

	item := &Item{
		ID:       id,
		senderIP: senderIP,
	}

	m := &Manager{
		incoming: map[string]*Item{
			id: item,
		},
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/birddrop/withdraw?id="+id,
		nil,
	)
	req.RemoteAddr = wrongIP + ":12345"

	rec := httptest.NewRecorder()
	m.handleWithdraw(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	m.mu.Lock()
	got := m.incoming[id]
	m.mu.Unlock()

	require.Same(t, item, got, "wrong peer must not withdraw the offer")
}

func testRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestReceiveRefusesUnauthorizedDestination(t *testing.T) {
	s, r, rPort := pair(t)

	src := filepath.Join(t.TempDir(), "ld.so.preload")
	require.NoError(t, os.WriteFile(src, []byte("/tmp/evil.so"), 0o644))

	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver.netbird.cloud", src, 10*time.Second)
	require.NoError(t, err)
	go collectSendEvents(evc)

	victim := t.TempDir()
	_, err = r.Receive(context.Background(), nil, victim, nil, -1, -1, nil)
	require.ErrorContains(t, err, "not authorized")

	entries, err := os.ReadDir(victim)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing may be written without an authorized root")
	require.Len(t, r.List(), 1, "the offer must stay pending")
}

func rawTarHeader(name string, typ byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:], name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	b[156] = typ
	copy(b[257:], "ustar\x0000")
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var sum int64
	for _, c := range b {
		sum += int64(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func paxRecord(k, v string) string {
	rec := " " + k + "=" + v + "\n"
	n := len(rec) + 1
	for len(strconv.Itoa(n))+len(rec) != n {
		n = len(strconv.Itoa(n)) + len(rec)
	}
	return strconv.Itoa(n) + rec
}

func padBlock(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

func TestUntarRejectsSparseBomb(t *testing.T) {
	pax := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", "bomb.bin") + paxRecord("GNU.sparse.realsize", "1073741824")
	var buf bytes.Buffer
	buf.Write(rawTarHeader("PaxHeaders/bomb.bin", 'x', int64(len(pax))))
	buf.Write(padBlock([]byte(pax)))
	data := append(padBlock([]byte("1\n0\n1\n")), 'x')
	buf.Write(rawTarHeader("bomb.bin", '0', int64(len(data))))
	buf.Write(padBlock(data))
	buf.Write(make([]byte, 1024))

	tarPath := filepath.Join(t.TempDir(), "bomb.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0o600))

	dest := t.TempDir()
	root := testRoot(t, dest)
	_, written, err := untarFile(t, tarPath, root)
	require.Error(t, err)
	require.Zero(t, written)
	_, statErr := os.Stat(filepath.Join(dest, "bomb.bin"))
	require.True(t, os.IsNotExist(statErr), "nothing may be extracted")
}

func writeTestTar(t *testing.T, entries func(tw *tar.Writer)) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.tar")
	f, err := os.Create(p)
	require.NoError(t, err)
	tw := tar.NewWriter(f)
	entries(tw)
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())
	return p
}

func TestUntarLimitsEntryCountAndNames(t *testing.T) {
	orig := maxArchiveEntries
	maxArchiveEntries = 3
	t.Cleanup(func() { maxArchiveEntries = orig })

	tooMany := writeTestTar(t, func(tw *tar.Writer) {
		for i := 0; i < 4; i++ {
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir, Mode: 0o755}))
		}
	})
	_, _, err := untarFile(t, tooMany, testRoot(t, t.TempDir()))
	require.ErrorContains(t, err, "more than 3 entries")

	longName := writeTestTar(t, func(tw *tar.Writer) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: strings.Repeat("a", maxArchiveNameLen+1) + "/", Typeflag: tar.TypeDir, Mode: 0o755}))
	})
	_, _, err = untarFile(t, longName, testRoot(t, t.TempDir()))
	require.ErrorContains(t, err, "name longer than")
}

func TestUntarDoesNotOverwriteExistingEntry(t *testing.T) {
	tarPath := writeTestTar(t, func(tw *tar.Writer) {
		body := []byte("from peer")
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "f.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	})

	dest := t.TempDir()
	planted := filepath.Join(dest, "f.txt")
	require.NoError(t, os.WriteFile(planted, []byte("precious"), 0o600))

	_, _, err := untarFile(t, tarPath, testRoot(t, dest))
	require.Error(t, err)
	got, err := os.ReadFile(planted)
	require.NoError(t, err)
	require.Equal(t, "precious", string(got))
}

func TestDiscardIncomingClearsOffersAndNotifiesSenders(t *testing.T) {
	rejected := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathReject {
			rejected <- r.URL.Query().Get("id")
		}
	}))
	t.Cleanup(srv.Close)

	m := &Manager{incoming: map[string]*Item{
		"a": {ID: "a", fetchURL: srv.URL + pathFetch + "?id=a"},
		"b": {ID: "b", fetchURL: srv.URL + pathFetch + "?id=b"},
	}}

	require.Equal(t, 2, m.DiscardIncoming())
	require.Empty(t, m.List())

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-rejected:
			got[id] = true
		case <-time.After(5 * time.Second):
			t.Fatal("sender was not notified")
		}
	}
	require.Equal(t, map[string]bool{"a": true, "b": true}, got)
}

func TestRemoteTextCannotDriveTerminal(t *testing.T) {
	osc52 := "\x1b]52;c;ZXZpbA==\x07"
	csi := "\u009b2J"

	require.Equal(t, "?]52;c;ZXZpbA==? refused", SanitizeRemoteText(osc52+" refused"))
	require.Equal(t, "?2J", SanitizeRemoteText(csi))
	require.Equal(t, "invoice?fdp.exe", SanitizeRemoteText("invoice\u202efdp.exe"))
	require.Equal(t, "bad?utf8", SanitizeRemoteText("bad\xffutf8"))

	escaped := EscapeForTerminal("line1\n\tx" + osc52 + "\u202e\xff")
	require.NotContains(t, escaped, "\x1b")
	require.NotContains(t, escaped, "\a")
	require.NotContains(t, escaped, "\u202e")
	require.Contains(t, escaped, "line1\n\tx", "newlines and tabs stay readable")
	require.Contains(t, escaped, `\x1b`)
	require.Contains(t, escaped, `\u202e`)
	require.Contains(t, escaped, `\xff`)
}

func TestSanitizeNameDropsDisplayTricks(t *testing.T) {
	require.Equal(t, "invoicefdp.exe", sanitizeName("invoice\u202efdp.exe"))
	require.Equal(t, "a2Jb", sanitizeName("a\u009b2Jb"))
	require.Equal(t, "zerowidth", sanitizeName("zero\u200bwidth"))
}

func TestPeerClientGivesUpOnSilentPeer(t *testing.T) {
	orig := peerResponseHeaderTimeout
	peerResponseHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { peerResponseHeaderTimeout = orig })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	start := time.Now()
	resp, err := newHTTPClient(0).Get(srv.URL + pathFetch)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestOfferPeerKeySharedAcrossAddresses(t *testing.T) {
	v4 := &Item{From: "laptop.netbird.cloud", senderIP: "100.64.0.5"}
	v6 := &Item{From: "laptop.netbird.cloud", senderIP: "fd00::5"}
	other := &Item{From: "phone.netbird.cloud", senderIP: "100.64.0.9"}
	require.Equal(t, offerPeerKey(v4), offerPeerKey(v6))
	require.NotEqual(t, offerPeerKey(v4), offerPeerKey(other))
}

func TestCountingWriterStopsAtLimit(t *testing.T) {
	w := &countingWriter{limit: 10}
	n, err := w.Write(make([]byte, 8))
	require.NoError(t, err)
	require.Equal(t, 8, n)
	_, err = w.Write(make([]byte, 8))
	require.ErrorIs(t, err, errArchiveTooLarge)

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "big"), make([]byte, 1<<20), 0o600))
	counter := &countingWriter{limit: 4096}
	err = tarDir(authenticatedContext(t), src, counter)
	require.ErrorIs(t, err, errArchiveTooLarge)
	require.Less(t, counter.n, int64(1<<20), "must stop before reading the whole file")
}

func TestDefaultPortAvoidsNetBirdServices(t *testing.T) {
	for _, p := range []int{33073, 10000, 3478, 5349, 51820, 22022, 44338, 80, 443} {
		require.NotEqual(t, p, DefaultPort)
	}
}

func fakeSenderOffer(t *testing.T, id, name string, size int64, fetch http.HandlerFunc) (*Manager, *Item) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, pathStatus):
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, pathFetch):
			fetch(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	m, err := NewManager("receiver.test", nil)
	require.NoError(t, err)

	it := &Item{
		ID:       id,
		Name:     name,
		From:     "sender.test",
		Size:     size,
		fetchURL: srv.URL + pathFetch + "?id=" + id,
		senderIP: u.Hostname(),
		expires:  time.Now().Add(time.Minute),
	}
	m.mu.Lock()
	m.incoming[it.ID] = it
	m.mu.Unlock()
	return m, it
}

func postOffer(t *testing.T, m *Manager, remoteIP string, meta offerMeta) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(meta)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://receiver"+pathOffer, bytes.NewReader(body))
	req.RemoteAddr = net.JoinHostPort(remoteIP, "12345")
	rec := httptest.NewRecorder()
	m.handleOffer(rec, req)
	return rec
}

func untarFile(t *testing.T, path string, root *os.Root) (int, int64, error) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	info, err := f.Stat()
	require.NoError(t, err)
	return untarIntoRoot(f, info.Size(), root)
}

func TestReceiveWritesOnlyIntoDestination(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	s, r, rPort := pair(t)
	srcDir := t.TempDir()
	file := filepath.Join(srcDir, "report.pdf")
	require.NoError(t, os.WriteFile(file, []byte("quarterly numbers"), 0o644))
	folder := filepath.Join(srcDir, "photos")
	require.NoError(t, os.MkdirAll(filepath.Join(folder, "2026"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(folder, "2026", "a.jpg"), []byte("jpeg"), 0o644))

	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver.netbird.cloud", file, 10*time.Second)
	require.NoError(t, err)
	go collectSendEvents(evc)
	devc, err := s.Send(authenticatedContext(t), "127.0.0.1", rPort, "receiver.netbird.cloud", folder, 10*time.Second)
	require.NoError(t, err)
	go collectSendEvents(devc)

	dest := t.TempDir()
	res, err := r.Receive(context.Background(), nil, dest, testRoot(t, dest), -1, -1, nil)
	require.NoError(t, err)
	require.Len(t, res, 2)

	got, err := os.ReadFile(filepath.Join(dest, "report.pdf"))
	require.NoError(t, err)
	require.Equal(t, "quarterly numbers", string(got))
	got, err = os.ReadFile(filepath.Join(dest, "photos", "2026", "a.jpg"))
	require.NoError(t, err)
	require.Equal(t, "jpeg", string(got))

	requireNoPartEntries(t, dest)
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing may be written to the temporary directory")
}

func TestFailedReceiveLeavesNoPartFile(t *testing.T) {
	m, it := fakeSenderOffer(t, "bad-sum-test", "bad.txt", 5, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", hdrSha256)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
		w.Header().Set(hdrSha256, strings.Repeat("0", 64))
	})
	dest := t.TempDir()
	_, err := m.Receive(context.Background(), []string{it.ID}, dest, testRoot(t, dest), -1, -1, nil)
	require.ErrorContains(t, err, "integrity")

	entries, err := os.ReadDir(dest)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestCommitPartFileWithoutHardLinks(t *testing.T) {
	orig := linkEntry
	linkEntry = func(*os.Root, string, string) error { return errors.ErrUnsupported }
	t.Cleanup(func() { linkEntry = orig })

	destDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(destDir, "a.txt"), []byte("existing"), 0o644))
	out := receiveIntoPart(t, testRoot(t, destDir), destDir, "a.txt", "new")
	require.Equal(t, filepath.Join(destDir, "a (1).txt"), out)

	got, err := os.ReadFile(filepath.Join(destDir, "a.txt"))
	require.NoError(t, err)
	require.Equal(t, "existing", string(got))
	requireNoPartEntries(t, destDir)
}

func TestCommitPartRefusesReplacedEntry(t *testing.T) {
	destDir := t.TempDir()
	root := testRoot(t, destDir)
	f, hidden, err := createPartFile(root, "0123456789abcdef")
	require.NoError(t, err)
	info, err := f.Stat()
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, os.Remove(filepath.Join(destDir, hidden)))
	require.NoError(t, os.WriteFile(filepath.Join(destDir, hidden), []byte("swapped in"), 0o644))

	_, err = commitPart(root, hidden, destDir, "doc.txt", false, info)
	require.ErrorIs(t, err, errPartReplaced)
	_, err = os.Stat(filepath.Join(destDir, "doc.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func requireNoPartEntries(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasSuffix(e.Name(), ".part"), "left a part entry behind: %s", e.Name())
	}
}
