package splithttp

import (
	"context"
	"io"
	"net/http"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// BrowserDialerClient implements splithttp.DialerClient in terms of browser dialer
type BrowserDialerClient struct {
	transportConfig *Config
}

func (c *BrowserDialerClient) IsClosed() bool {
	// Browser clients do not own a transport, but they still implement the
	// public DialerClient/XmuxConn contract. Report the availability of the
	// shared browser bridge instead of panicking if a generic caller probes it.
	return !browser_dialer.HasBrowserDialer()
}

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("bidirectional streaming for browser dialer not implemented yet")
	}

	request, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	c.transportConfig.FillStreamRequest(request, sessionId, "")

	conn, err := browser_dialer.DialGetContext(ctx, request.URL.String(), request.Header, request.Cookies())
	dummyAddr := &net.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	request, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}

	err = c.transportConfig.FillPacketRequest(request, sessionId, seqStr, payload)
	if err != nil {
		if request.Body != nil {
			request.Body.Close()
		}
		return err
	}
	if request.Body != nil && (method == http.MethodGet || method == http.MethodHead) {
		request.Body.Close()
		return errors.New("browser dialer cannot send a request body with ", method)
	}

	var bytes []byte
	if request.Body != nil {
		defer request.Body.Close()
		bytes, err = io.ReadAll(request.Body)
		if err != nil {
			return err
		}
	}

	err = browser_dialer.DialPacketContext(ctx, method, request.URL.String(), request.Header, request.Cookies(), bytes)
	if err != nil {
		return err
	}

	return nil
}
