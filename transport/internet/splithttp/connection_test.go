package splithttp

import (
	stderrors "errors"
	"io"
	"testing"
)

type closeErrorWriter struct{}

func (closeErrorWriter) Write(p []byte) (int, error) { return len(p), nil }
func (closeErrorWriter) Close() error                { return nil }

type closeErrorReader struct {
	err error
}

func (closeErrorReader) Read([]byte) (int, error) { return 0, io.EOF }
func (r closeErrorReader) Close() error           { return r.err }

func TestSplitConnCloseReturnsReaderError(t *testing.T) {
	wantErr := stderrors.New("reader close failed")
	conn := &splitConn{writer: closeErrorWriter{}, reader: closeErrorReader{err: wantErr}}
	if err := conn.Close(); !stderrors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
}
