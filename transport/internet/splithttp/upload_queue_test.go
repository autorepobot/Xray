package splithttp_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_regression_readzero(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{
		Payload: []byte("x"),
		Seq:     0,
	})
	buf := make([]byte, 20)
	n, err := q.Read(buf)
	common.Must(err)
	if n != 1 {
		t.Error("n=", n)
	}
}

func TestUploadQueueSkipsDuplicateWithoutEmptyRead(t *testing.T) {
	q := NewUploadQueue(10)
	for _, packet := range []Packet{
		{Payload: []byte("A"), Seq: 0},
		{Payload: []byte("A"), Seq: 0},
		{Payload: []byte("B"), Seq: 1},
	} {
		if err := q.Push(packet); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, 1)
	if n, err := q.Read(buf); err != nil || n != 1 || string(buf) != "A" {
		t.Fatalf("first read = %q, %d, %v; want A, 1, nil", buf, n, err)
	}
	if n, err := q.Read(buf); err != nil || n != 1 || string(buf) != "B" {
		t.Fatalf("read after duplicate = %q, %d, %v; want B, 1, nil", buf, n, err)
	}
}

func TestUploadQueueSkipsEmptyPacketWithoutEmptyRead(t *testing.T) {
	q := NewUploadQueue(10)
	for _, packet := range []Packet{
		{Seq: 0},
		{Payload: []byte("B"), Seq: 1},
	} {
		if err := q.Push(packet); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, 1)
	if n, err := q.Read(buf); err != nil || n != 1 || string(buf) != "B" {
		t.Fatalf("read after empty packet = %q, %d, %v; want B, 1, nil", buf, n, err)
	}
}

func TestUploadQueueDoesNotReplayPrefixDuringPartialRead(t *testing.T) {
	q := NewUploadQueue(10)
	for _, packet := range []Packet{
		// Buffer two equal future packets before filling the gap. Once seq 1 is
		// partially read, its duplicate and remainder would share an unstable heap
		// key if the in-progress remainder were pushed back into the reorder heap.
		{Payload: []byte("CDEF"), Seq: 1},
		{Payload: []byte("CDEF"), Seq: 1},
		{Payload: []byte("AB"), Seq: 0},
		{Payload: []byte("GH"), Seq: 2},
	} {
		if err := q.Push(packet); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, 2)
	for i, want := range []string{"AB", "CD", "EF", "GH"} {
		if n, err := q.Read(buf); err != nil || n != len(buf) || string(buf) != want {
			t.Fatalf("read %d = %q, %d, %v; want %q", i, buf, n, err, want)
		}
	}
}
