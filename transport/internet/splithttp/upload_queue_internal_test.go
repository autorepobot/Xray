package splithttp

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

func TestReaderPushDoesNotBlockBehindFullPacketChannel(t *testing.T) {
	queue := NewUploadQueue(1)
	if err := queue.Push(Packet{Seq: 0, Payload: []byte("packet")}); err != nil {
		t.Fatal(err)
	}
	stream := &httpServerConn{Instance: done.New(), Reader: strings.NewReader("stream")}

	result := make(chan error, 1)
	go func() {
		result <- queue.Push(Packet{Reader: stream})
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reader Push blocked behind a full packet channel")
	}

	buffer := make([]byte, len("stream"))
	if n, err := queue.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "stream" {
		t.Fatalf("Read = %q, %d, %v; want stream", buffer, n, err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNonPositiveBufferedPostCapacityUsesSafeDefault(t *testing.T) {
	for _, capacity := range []int64{-1, 0} {
		config := &Config{ScMaxBufferedPosts: capacity}
		if got := config.GetNormalizedScMaxBufferedPosts(); got != defaultScMaxBufferedPosts {
			t.Fatalf("normalized scMaxBufferedPosts(%d) = %d, want %d", capacity, got, defaultScMaxBufferedPosts)
		}
		queue := NewUploadQueue(int(capacity))
		if got := cap(queue.pushedPackets); got != defaultScMaxBufferedPosts {
			t.Fatalf("upload queue capacity(%d) = %d, want %d", capacity, got, defaultScMaxBufferedPosts)
		}
		if err := queue.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPacketPushBackpressuresAndResumesAtCapacity(t *testing.T) {
	queue := NewUploadQueue(1)
	defer queue.Close()
	if err := queue.Push(Packet{Seq: 0, Payload: []byte("first")}); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- queue.Push(Packet{Seq: 1, Payload: []byte("second")})
	}()
	select {
	case err := <-result:
		t.Fatalf("packet beyond queue capacity returned before backpressure was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	buffer := make([]byte, len("first"))
	if n, err := queue.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "first" {
		t.Fatalf("first Read = %q, %d, %v", buffer, n, err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet Push did not resume after a queue slot became available")
	}
	buffer = make([]byte, len("second"))
	if n, err := queue.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "second" {
		t.Fatalf("second Read = %q, %d, %v", buffer, n, err)
	}
}

func TestReaderPushCancelsPacketWaitingForCapacity(t *testing.T) {
	queue := NewUploadQueue(1)
	defer queue.Close()
	if err := queue.Push(Packet{Seq: 0, Payload: []byte("packet")}); err != nil {
		t.Fatal(err)
	}

	packetResult := make(chan error, 1)
	go func() {
		packetResult <- queue.Push(Packet{Seq: 1, Payload: []byte("blocked")})
	}()
	select {
	case err := <-packetResult:
		t.Fatalf("packet Push returned before Reader takeover: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	stream := &httpServerConn{Instance: done.New(), Reader: strings.NewReader("stream")}
	readerResult := make(chan error, 1)
	go func() {
		readerResult <- queue.Push(Packet{Reader: stream})
	}()
	select {
	case err := <-readerResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reader Push blocked behind a packet waiting for capacity")
	}
	select {
	case err := <-packetResult:
		if err == nil || !strings.Contains(err.Error(), "reader") {
			t.Fatalf("blocked packet Push error = %v, want Reader takeover", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reader takeover did not cancel the blocked packet Push")
	}

	buffer := make([]byte, len("stream"))
	if n, err := queue.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "stream" {
		t.Fatalf("Read = %q, %d, %v; want stream", buffer, n, err)
	}
}

func TestCloseCancelsPacketWaitingForCapacity(t *testing.T) {
	queue := NewUploadQueue(1)
	if err := queue.Push(Packet{Seq: 0, Payload: []byte("packet")}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- queue.Push(Packet{Seq: 1, Payload: []byte("blocked")})
	}()
	select {
	case err := <-result:
		t.Fatalf("packet Push returned before Close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "closed") {
			t.Fatalf("blocked packet Push error = %v, want closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the blocked packet Push")
	}
}

func TestPacketBackpressureBroadcastDoesNotLoseWaiters(t *testing.T) {
	queue := NewUploadQueue(1)
	defer queue.Close()
	if err := queue.Push(Packet{Seq: 0, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}

	const waiters = 8
	results := make(chan error, waiters)
	for seq := 1; seq <= waiters; seq++ {
		go func(seq int) {
			results <- queue.Push(Packet{Seq: uint64(seq), Payload: []byte{byte(seq)}})
		}(seq)
	}
	select {
	case err := <-results:
		t.Fatalf("packet waiter returned while the queue was full: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	seen := make(map[byte]bool, waiters+1)
	for range waiters + 1 {
		select {
		case packet := <-queue.pushedPackets:
			seen[packet.Payload[0]] = true
			queue.signalPacketDequeued()
		case <-time.After(time.Second):
			t.Fatal("packet waiters lost a space-available notification")
		}
	}
	if len(seen) != waiters+1 {
		t.Fatalf("dequeued %d distinct packets, want %d", len(seen), waiters+1)
	}
	for range waiters {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("packet waiter did not finish after its packet was consumed")
		}
	}
}

func TestConnectedSessionCannotLoseReaperTie(t *testing.T) {
	handler := &requestHandler{sessionMu: &sync.Mutex{}}
	session := &httpSession{
		uploadQueue:      NewUploadQueue(1),
		isFullyConnected: done.New(),
	}
	handler.sessions.Store("session", session)
	if !handler.connectSession("session", session) {
		t.Fatal("failed to connect pending session")
	}

	if handler.reapSessionIfUnconnected("session", session) {
		t.Fatal("reaper won after the session connected")
	}
	if current, ok := handler.sessions.Load("session"); !ok || current != session {
		t.Fatal("fully connected session was reaped")
	}
	if session.uploadQueue.closed.Done() {
		t.Fatal("fully connected session queue was closed")
	}
}

func TestSessionReaperCannotDeleteReplacement(t *testing.T) {
	handler := &requestHandler{sessionMu: &sync.Mutex{}}
	oldSession := &httpSession{uploadQueue: NewUploadQueue(1), isFullyConnected: done.New()}
	newSession := &httpSession{uploadQueue: NewUploadQueue(1), isFullyConnected: done.New()}
	handler.sessions.Store("session", newSession)

	if handler.reapSessionIfUnconnected("session", oldSession) {
		t.Fatal("old reaper reported deleting a replacement session")
	}
	if current, ok := handler.sessions.Load("session"); !ok || current != newSession {
		t.Fatal("old reaper deleted a replacement session")
	}
	if newSession.uploadQueue.closed.Done() {
		t.Fatal("old reaper closed the replacement session queue")
	}
}

func TestSessionConnectAndReaperAreLinearized(t *testing.T) {
	for range 1000 {
		handler := &requestHandler{sessionMu: &sync.Mutex{}}
		session := &httpSession{uploadQueue: NewUploadQueue(1), isFullyConnected: done.New()}
		handler.sessions.Store("session", session)

		start := make(chan struct{})
		connected := make(chan bool, 1)
		reaped := make(chan bool, 1)
		go func() {
			<-start
			connected <- handler.connectSession("session", session)
		}()
		go func() {
			<-start
			reaped <- handler.reapSessionIfUnconnected("session", session)
		}()
		close(start)

		connectWon, reapWon := <-connected, <-reaped
		if connectWon == reapWon {
			t.Fatalf("connect=%v reap=%v; exactly one transition must win", connectWon, reapWon)
		}
		_, remains := handler.sessions.Load("session")
		if remains != connectWon {
			t.Fatalf("session remains=%v, connect won=%v", remains, connectWon)
		}
		if session.uploadQueue.closed.Done() != reapWon {
			t.Fatalf("queue closed=%v, reap won=%v", session.uploadQueue.closed.Done(), reapWon)
		}
	}
}

func TestUploadQueueReadAfterCloseDoesNotEnterStreamReader(t *testing.T) {
	queue := NewUploadQueue(1)
	stream := &httpServerConn{Instance: done.New(), Reader: strings.NewReader("x")}
	if err := queue.Push(Packet{Reader: stream}); err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 1)
	if n, err := queue.Read(buffer); n != 0 || err != io.EOF {
		t.Fatalf("Read after Close = %q, %d, %v; want empty, 0, io.EOF", buffer, n, err)
	}
}

func TestReaderPushWakesPacketReorderWait(t *testing.T) {
	queue := NewUploadQueue(1)
	if err := queue.Push(Packet{Seq: 1, Payload: []byte("future")}); err != nil {
		t.Fatal(err)
	}

	result := make(chan string, 1)
	resultErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, len("stream"))
		n, err := queue.Read(buffer)
		if err != nil {
			resultErr <- err
			return
		}
		result <- string(buffer[:n])
	}()

	deadline := time.Now().Add(time.Second)
	for len(queue.pushedPackets) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stream := &httpServerConn{Instance: done.New(), Reader: strings.NewReader("stream")}
	if err := queue.Push(Packet{Reader: stream}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-result:
		if got != "stream" {
			t.Fatalf("Read = %q, want stream", got)
		}
	case err := <-resultErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Reader Push did not wake a packet reorder wait")
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
}
