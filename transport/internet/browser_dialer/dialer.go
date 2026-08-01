package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	stdnet "net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

type task struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Extra          any    `json:"extra,omitempty"`
	StreamResponse bool   `json:"streamResponse"`
}

var (
	conns           chan *websocket.Conn
	server          *http.Server
	browserListener stdnet.Listener
	currentAddr     string
	mu              sync.Mutex
)

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(*http.Request) bool {
		return true
	},
}

// Used by external projects when using xray as a go module
func Reload() {
	addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	mu.Lock()
	defer mu.Unlock()

	if addr == currentAddr && (addr == "" || server != nil) {
		return
	}

	if server != nil {
		_ = server.Close()
		server = nil
	}
	if browserListener != nil {
		// http.Server only tracks a listener after Serve has started. Retain and
		// close our own reference as well so an immediate reload can't strand the
		// socket in the gap between net.Listen and Serve registration.
		_ = browserListener.Close()
		browserListener = nil
	}
	if conns != nil {
		connections := conns
		conns = nil
		for len(connections) > 0 {
			select {
			case c := <-connections:
				c.Close()
			default:
			}
		}
		close(connections)
	}
	currentAddr = addr
	if addr != "" {
		token := uuid.New()
		csrfToken := token.String()
		webpage := bytes.ReplaceAll(webpage, []byte("csrfToken"), []byte(csrfToken))
		connections := make(chan *websocket.Conn, 256)
		conns = connections
		newServer := &http.Server{
			Addr: addr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/websocket" {
					if r.URL.Query().Get("token") != csrfToken {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
						mu.Lock()
						if conns != connections {
							mu.Unlock()
							conn.Close()
							return
						}
						select {
						case connections <- conn:
							mu.Unlock()
						default:
							mu.Unlock()
							conn.Close()
						}
					} else {
						errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error")
					}
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					_, _ = w.Write(webpage)
				}
			}),
		}
		listener, err := stdnet.Listen("tcp", addr)
		if err != nil {
			conns = nil
			close(connections)
			errors.LogErrorInner(context.Background(), err, "Browser dialer failed to listen on ", addr)
			return
		}
		server = newServer
		browserListener = listener
		go func() {
			err := newServer.Serve(listener)
			_ = listener.Close()
			if err == nil || stderrors.Is(err, http.ErrServerClosed) {
				return
			}
			errors.LogErrorInner(context.Background(), err, "Browser dialer server stopped unexpectedly")

			mu.Lock()
			defer mu.Unlock()
			if server != newServer || browserListener != listener || conns != connections {
				return
			}
			server = nil
			browserListener = nil
			conns = nil
			for len(connections) > 0 {
				select {
				case conn := <-connections:
					conn.Close()
				default:
				}
			}
			close(connections)
		}()
	}
}

func HasBrowserDialer() bool {
	mu.Lock()
	defer mu.Unlock()
	return conns != nil
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	return DialWSContext(context.Background(), uri, ed)
}

// DialWSContext uses ctx to cancel browser assignment and the upstream
// WebSocket handshake. As with net.Dialer, cancellation stops setup only; a
// successfully returned connection is owned by its caller.
func DialWSContext(ctx context.Context, uri string, ed []byte) (*websocket.Conn, error) {
	task := task{
		Method:         "WS",
		URL:            uri,
		StreamResponse: true,
	}

	task.Extra = webSocketExtra{
		Protocol: base64.RawURLEncoding.EncodeToString(ed),
	}

	conn, err := dialTaskContext(ctx, task)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type httpExtra struct {
	Referrer string            `json:"referrer,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
}

func httpExtraFromHeadersAndCookies(headers http.Header, cookies []*http.Cookie) *httpExtra {
	if len(headers) == 0 && len(cookies) == 0 {
		return nil
	}

	extra := httpExtra{}
	if referrer := headers.Get("Referer"); referrer != "" {
		extra.Referrer = referrer
		headers.Del("Referer")
	}

	if len(headers) > 0 {
		extra.Headers = make(map[string]string)
		for header := range headers {
			extra.Headers[header] = headers.Get(header)
		}
	}

	if len(cookies) > 0 {
		extra.Cookies = make(map[string]string)
		for _, cookie := range cookies {
			extra.Cookies[cookie.Name] = cookie.Value
		}
	}

	return &extra
}

func DialGet(uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	return DialGetContext(context.Background(), uri, headers, cookies)
}

func DialGetContext(ctx context.Context, uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	task := task{
		Method:         "GET",
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: true,
	}

	conn, err := dialTaskContext(ctx, task)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	// A streaming fetch belongs to the returned logical connection. Keep
	// cancellation attached after the task handshake so closing that logical
	// connection aborts both the websocket and the browser-side fetch.
	context.AfterFunc(ctx, func() { conn.Close() })
	return conn, nil
}

func DialPacket(method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	return DialPacketContext(context.Background(), method, uri, headers, cookies, payload)
}

func DialPacketContext(ctx context.Context, method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	task := task{
		Method:         method,
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: false,
	}

	conn, err := dialTaskContext(ctx, task)
	if err != nil {
		return err
	}
	stopCancellation := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopCancellation()
	defer conn.Close()

	err = conn.WriteMessage(websocket.BinaryMessage, payload)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	err = CheckOK(conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	return nil
}

func dialTaskContext(ctx context.Context, task task) (*websocket.Conn, error) {
	for {
		mu.Lock()
		connections := conns
		mu.Unlock()
		if connections == nil {
			return nil, errors.New("browser dialer is not available")
		}

		var conn *websocket.Conn
		select {
		case conn = <-connections:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		// Reload closes the old queue while publishing a new generation. Validate
		// after receiving so an idle websocket removed from the old queue cannot
		// escape its drain and be assigned after the reload linearizes.
		mu.Lock()
		currentGeneration := conns == connections
		mu.Unlock()
		if !currentGeneration {
			if conn != nil {
				conn.Close()
			}
			continue
		}
		if conn == nil {
			return nil, errors.New("browser dialer connection queue closed")
		}
		data, err := json.Marshal(task)
		if err != nil {
			conn.Close()
			return nil, err
		}

		stopCancellation := context.AfterFunc(ctx, func() { conn.Close() })
		if conn.WriteMessage(websocket.TextMessage, data) != nil {
			stopCancellation()
			conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		} else {
			err = CheckOK(conn)
			stopCancellation()
			if ctx.Err() != nil {
				conn.Close()
				return nil, ctx.Err()
			}
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
}

func CheckOK(conn *websocket.Conn) error {
	if _, p, err := conn.ReadMessage(); err != nil {
		conn.Close()
		return err
	} else if s := string(p); s != "ok" {
		conn.Close()
		return errors.New(s)
	}

	return nil
}

func init() {
	platform.RegisterEnvReload(func() error {
		Reload()
		return nil
	})
}
