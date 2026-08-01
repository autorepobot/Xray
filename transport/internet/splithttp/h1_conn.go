package splithttp

import (
	"bufio"
	"net"
)

// H1Conn is retained for source compatibility with integrations that used the
// former raw H1 upload pool. The built-in client now uses net/http.Transport.
type H1Conn struct {
	UnreadedResponsesCount int
	RespBufReader          *bufio.Reader
	net.Conn
}

// NewH1Conn wraps conn using the legacy exported representation.
func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
	}
}
