package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/done"
)

type Packet struct {
	Reader  *httpServerConn
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	reader         atomic.Pointer[httpServerConn]
	pushedPackets  chan Packet
	pushMu         sync.Mutex
	readMu         sync.Mutex
	heap           uploadHeap
	currentPayload []byte
	nextSeq        uint64
	maxPackets     int
	readerReady    *done.Instance
	spaceReady     chan struct{}
	closed         *done.Instance
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	if maxPackets <= 0 {
		maxPackets = defaultScMaxBufferedPosts
	}
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		readerReady:   done.New(),
		spaceReady:    make(chan struct{}),
		closed:        done.New(),
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) Push(p Packet) error {
	// Make Reader publication and packet admission linearizable. In particular,
	// a packet must not pass the reader check and enter the channel after a
	// concurrent stream-up Reader has taken over the session.
	if p.Reader != nil {
		h.pushMu.Lock()
		if h.closed.Done() {
			h.pushMu.Unlock()
			p.Reader.Close()
			return errors.New("packet queue closed")
		}
		if !h.reader.CompareAndSwap(nil, p.Reader) {
			h.pushMu.Unlock()
			return errors.New("h.reader already exists")
		}

		// Wake Reads that already passed the atomic check without competing for
		// space in the bounded packet channel. A best-effort sentinel in that
		// channel can be lost when it is full and leave a reorder wait asleep.
		h.readerReady.Close()
		h.pushMu.Unlock()
		return nil
	}

	for {
		h.pushMu.Lock()
		if h.reader.Load() != nil {
			h.pushMu.Unlock()
			return errors.New("h.reader already exists")
		}
		if h.closed.Done() {
			h.pushMu.Unlock()
			return errors.New("packet queue closed")
		}
		select {
		case h.pushedPackets <- p:
			h.pushMu.Unlock()
			return nil
		default:
			// Preserve upstream backpressure without holding pushMu: a stream-up
			// Reader must still be able to take over a full packet queue. Reads
			// rotate spaceReady after removing a packet, then contenders retry the
			// admission check under the same lock as Reader publication.
			spaceReady := h.spaceReady
			h.pushMu.Unlock()
			select {
			case <-spaceReady:
			case <-h.readerReady.Wait():
			case <-h.closed.Wait():
			}
		}
	}
}

func (h *uploadQueue) signalPacketDequeued() {
	h.pushMu.Lock()
	close(h.spaceReady)
	h.spaceReady = make(chan struct{})
	h.pushMu.Unlock()
}

func (h *uploadQueue) Close() error {
	h.pushMu.Lock()
	h.closed.Close()
	reader := h.reader.Load()
	h.pushMu.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	h.readMu.Lock()
	defer h.readMu.Unlock()

	for {
		if h.closed.Done() {
			return 0, io.EOF
		}

		if reader := h.reader.Load(); reader != nil {
			return reader.Read(b)
		}

		if len(h.currentPayload) > 0 {
			n := copy(b, h.currentPayload)
			h.currentPayload = h.currentPayload[n:]
			if len(h.currentPayload) == 0 {
				h.nextSeq++
			}
			return n, nil
		}

		if len(h.heap) == 0 {
			select {
			case p := <-h.pushedPackets:
				h.signalPacketDequeued()
				if p.Reader != nil {
					if h.closed.Done() {
						return 0, io.EOF
					}
					return p.Reader.Read(b)
				}
				heap.Push(&h.heap, p)
			case <-h.readerReady.Wait():
				continue
			case <-h.closed.Wait():
				return 0, io.EOF
			}
		}

		for len(h.heap) > 0 {
			packet := heap.Pop(&h.heap).(Packet)
			n := 0

			if packet.Seq == h.nextSeq {
				if len(packet.Payload) == 0 {
					h.nextSeq = packet.Seq + 1
					continue
				}
				copy(b, packet.Payload)
				n = min(len(b), len(packet.Payload))

				if n < len(packet.Payload) {
					// Keep the in-progress packet outside the reorder heap. Equal
					// sequence numbers are not stable in a heap; putting this remainder
					// back could let a replayed full packet repeat an already-read prefix.
					h.currentPayload = packet.Payload[n:]
				} else {
					h.nextSeq = packet.Seq + 1
				}

				return n, nil
			}

			// misordered packet
			if packet.Seq > h.nextSeq {
				if len(h.heap) > h.maxPackets {
					// the "reassembly buffer" is too large, and we want to
					// constrain memory usage somehow. let's tear down the
					// connection, and hope the application retries.
					return 0, errors.New("packet queue is too large")
				}
				heap.Push(&h.heap, packet)
				// A stream-up Reader may have been published while this Read was
				// reordering packet uploads. Recheck immediately before blocking.
				if reader := h.reader.Load(); reader != nil {
					if h.closed.Done() {
						return 0, io.EOF
					}
					return reader.Read(b)
				}
				select {
				case p := <-h.pushedPackets:
					h.signalPacketDequeued()
					if p.Reader != nil {
						if h.closed.Done() {
							return 0, io.EOF
						}
						return p.Reader.Read(b)
					}
					heap.Push(&h.heap, p)
				case <-h.readerReady.Wait():
					continue
				case <-h.closed.Wait():
					return 0, io.EOF
				}
			}
		}
		// All queued packets were stale duplicates. Wait for another packet
		// instead of returning (0, nil), which violates io.Reader progress for a
		// non-empty destination and can make callers spin or abort a healthy flow.
	}
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
