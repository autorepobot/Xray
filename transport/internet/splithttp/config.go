package splithttp

import (
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]

	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	if c.GetNormalizedSessionPlacement() == PlacementPath ||
		c.GetNormalizedSeqPlacement() == PlacementPath {
		if path[len(path)-1] != '/' {
			path = path + "/"
		}
	}

	return path
}

func (c *Config) GetNormalizedQuery() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	query := ""

	if len(pathAndQuery) > 1 {
		query = pathAndQuery[1]
	}

	/*
		if query != "" {
			query += "&"
		}
		query += "x_version=" + core.Version()
	*/

	return query
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Headers {
		header.Add(k, v)
	}
	utils.TryDefaultHeadersWith(header, "fetch")
	return header
}

func (c *Config) GetRequestHeaderWithPayload(payload []byte) http.Header {
	header := c.GetRequestHeader()

	key := c.UplinkDataKey
	encodedData := base64.RawURLEncoding.EncodeToString(payload)

	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := min(int(c.GetNormalizedUplinkChunkSize().rand()), len(encodedData))
		chunk := encodedData[:chunkSize]
		encodedData = encodedData[chunkSize:]
		headerKey := fmt.Sprintf("%s-%d", key, i)
		header.Set(headerKey, chunk)
	}

	return header
}

func (c *Config) GetRequestCookiesWithPayload(payload []byte) []*http.Cookie {
	cookies := []*http.Cookie{}

	key := c.UplinkDataKey
	encodedData := base64.RawURLEncoding.EncodeToString(payload)

	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := min(int(c.GetNormalizedUplinkChunkSize().rand()), len(encodedData))
		chunk := encodedData[:chunkSize]
		encodedData = encodedData[chunkSize:]
		cookieName := fmt.Sprintf("%s_%d", key, i)
		cookies = append(cookies, &http.Cookie{Name: cookieName, Value: chunk})
	}

	return cookies
}

func (c *Config) WriteResponseHeader(writer http.ResponseWriter, requestMethod string, requestHeader http.Header) {
	// CORS headers for the browser dialer
	if origin := requestHeader.Get("Origin"); origin == "" {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		// Chrome says: The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
		writer.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if c.GetNormalizedSessionPlacement() == PlacementCookie ||
		c.GetNormalizedSeqPlacement() == PlacementCookie ||
		c.XPaddingPlacement == PlacementCookie ||
		c.GetNormalizedUplinkDataPlacement() == PlacementCookie {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if requestMethod == "OPTIONS" {
		requestedMethod := requestHeader.Get("Access-Control-Request-Method")
		if requestedMethod != "" {
			writer.Header().Set("Access-Control-Allow-Methods", requestedMethod)
		} else {
			writer.Header().Set("Access-Control-Allow-Methods", "*")
		}

		requestedHeaders := requestHeader.Get("Access-Control-Request-Headers")
		if requestedHeaders == "" {
			writer.Header().Set("Access-Control-Allow-Headers", "*")
		} else {
			writer.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
		}
	}
}

func (c *Config) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}

	return c.UplinkHTTPMethod
}

const defaultScMaxEachPostBytes int32 = 1000000

func (c *Config) GetNormalizedScMaxEachPostBytes() *RangeConfig {
	configured := c.ScMaxEachPostBytes
	if configured == nil || configured.From <= 0 || configured.To <= 0 || configured.From > configured.To {
		return &RangeConfig{
			From: defaultScMaxEachPostBytes,
			To:   defaultScMaxEachPostBytes,
		}
	}

	return configured
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() *RangeConfig {
	if c.ScMinPostsIntervalMs == nil || c.ScMinPostsIntervalMs.To == 0 {
		return &RangeConfig{
			From: 30,
			To:   30,
		}
	}

	return c.ScMinPostsIntervalMs
}

const defaultScMaxBufferedPosts = 30

func (c *Config) GetNormalizedScMaxBufferedPosts() int {
	// JSON validation rejects negative and platform-sized overflow values. Keep
	// direct protobuf/API construction defensive as well: neither case may be
	// allowed to reach make(chan, capacity) and panic the server.
	if c.ScMaxBufferedPosts <= 0 || uint64(c.ScMaxBufferedPosts) > uint64(^uint(0)>>1) {
		return defaultScMaxBufferedPosts
	}

	return int(c.ScMaxBufferedPosts)
}

func (c *Config) GetNormalizedScStreamUpServerSecs() *RangeConfig {
	configured := c.ScStreamUpServerSecs
	if configured == nil || (configured.From == 0 && configured.To == 0) || configured.From > configured.To || (configured.From <= 0 && configured.To > 0) {
		return &RangeConfig{
			From: 20,
			To:   80,
		}
	}

	return configured
}

func (c *Config) GetNormalizedUplinkChunkSize() *RangeConfig {
	if c.UplinkChunkSize == nil || (c.UplinkChunkSize.From == 0 && c.UplinkChunkSize.To == 0) {
		switch c.UplinkDataPlacement {
		case PlacementCookie:
			return &RangeConfig{
				From: 2 * 1024, // 2 KiB
				To:   3 * 1024, // 3 KiB
			}
		case PlacementHeader:
			return &RangeConfig{
				From: 3 * 1000, // 3 KB
				To:   4 * 1000, // 4 KB
			}
		default:
			return c.GetNormalizedScMaxEachPostBytes()
		}
	}

	from, to := c.UplinkChunkSize.From, c.UplinkChunkSize.To
	if from > to {
		from, to = to, from
	}
	return &RangeConfig{From: max(64, from), To: max(64, to)}
}

func (c *Config) GetNormalizedServerMaxHeaderBytes() int {
	if c.ServerMaxHeaderBytes <= 0 {
		return 8192
	} else {
		return int(c.ServerMaxHeaderBytes)
	}
}

func (c *Config) GetNormalizedSessionPlacement() string {
	if c.SessionIDPlacement == "" {
		return PlacementPath
	}
	return c.SessionIDPlacement
}

func (c *Config) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return PlacementPath
	}
	return c.SeqPlacement
}

func (c *Config) GetNormalizedUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return PlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *Config) GetNormalizedSessionKey() string {
	if c.SessionIDKey != "" {
		return c.SessionIDKey
	}
	switch c.GetNormalizedSessionPlacement() {
	case PlacementHeader:
		return "X-Session"
	case PlacementCookie, PlacementQuery:
		return "x_session"
	default:
		return ""
	}
}

func (c *Config) GetNormalizedSeqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	switch c.GetNormalizedSeqPlacement() {
	case PlacementHeader:
		return "X-Seq"
	case PlacementCookie, PlacementQuery:
		return "x_seq"
	default:
		return ""
	}
}

func (c *Config) ApplyMetaToRequest(req *http.Request, sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	if sessionId != "" {
		switch sessionPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(sessionKey, sessionId)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sessionKey, Value: sessionId})
		}
	}

	if seqStr != "" {
		switch seqPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(seqKey, seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: seqKey, Value: seqStr})
		}
	}
}

func (c *Config) FillStreamRequest(request *http.Request, sessionId string, seqStr string) {
	request.Header = c.GetRequestHeader()
	length := int(c.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    request.URL.String(),
		}
		config.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    request.URL.String(),
		}
	}

	c.ApplyXPaddingToRequest(request, config)
	c.ApplyMetaToRequest(request, sessionId, "")

	if request.Body != nil && !c.NoGRPCHeader { // stream-up/one
		request.Header.Set("Content-Type", "application/grpc")
	}
}

func (c *Config) FillPacketRequest(request *http.Request, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	dataPlacement := c.GetNormalizedUplinkDataPlacement()

	if dataPlacement == PlacementBody || dataPlacement == PlacementAuto {
		request.Header = c.GetRequestHeader()
		request.Body = io.NopCloser(&buf.MultiBufferContainer{MultiBuffer: payload})
		request.ContentLength = int64(payload.Len())
	} else {
		data := make([]byte, payload.Len())
		payload.Copy(data)
		buf.ReleaseMulti(payload)
		switch dataPlacement {
		case PlacementHeader:
			request.Header = c.GetRequestHeaderWithPayload(data)
		case PlacementCookie:
			request.Header = c.GetRequestHeader()
			for _, cookie := range c.GetRequestCookiesWithPayload(data) {
				request.AddCookie(cookie)
			}
		}
	}

	length := int(c.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    request.URL.String(),
		}
		config.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    request.URL.String(),
		}
	}

	c.ApplyXPaddingToRequest(request, config)
	c.ApplyMetaToRequest(request, sessionId, seqStr)

	return nil
}

func (c *Config) ExtractMetaFromRequest(req *http.Request, path string) (sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	var subpath []string
	pathPart := 0
	if sessionPlacement == PlacementPath || seqPlacement == PlacementPath {
		subpath = strings.Split(req.URL.Path[len(path):], "/")
	}

	switch sessionPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			sessionId = subpath[pathPart]
			pathPart += 1
		}
	case PlacementQuery:
		sessionId = req.URL.Query().Get(sessionKey)
	case PlacementHeader:
		sessionId = req.Header.Get(sessionKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(sessionKey); e == nil {
			sessionId = cookie.Value
		}
	}

	switch seqPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			seqStr = subpath[pathPart]
			pathPart += 1
		}
	case PlacementQuery:
		seqStr = req.URL.Query().Get(seqKey)
	case PlacementHeader:
		seqStr = req.Header.Get(seqKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(seqKey); e == nil {
			seqStr = cookie.Value
		}
	}

	return sessionId, seqStr
}

func (m *XmuxConfig) GetNormalizedMaxConcurrency() *RangeConfig {
	if m.MaxConcurrency == nil {
		return &RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return m.MaxConcurrency
}

func (m *XmuxConfig) GetNormalizedMaxConnections() *RangeConfig {
	if m.MaxConnections == nil {
		return &RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return m.MaxConnections
}

func (m *XmuxConfig) GetNormalizedCMaxReuseTimes() *RangeConfig {
	if m.CMaxReuseTimes == nil {
		return &RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return m.CMaxReuseTimes
}

func (m *XmuxConfig) GetNormalizedHMaxRequestTimes() *RangeConfig {
	if m.HMaxRequestTimes == nil {
		return &RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return m.HMaxRequestTimes
}

func (m *XmuxConfig) GetNormalizedHMaxReusableSecs() *RangeConfig {
	if m.HMaxReusableSecs == nil {
		return &RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return m.HMaxReusableSecs
}

func cloneRangeConfig(value *RangeConfig) *RangeConfig {
	if value == nil {
		return nil
	}
	return &RangeConfig{From: value.From, To: value.To}
}

func xmuxRangeBounds(value *RangeConfig) (int32, int32) {
	from, to := value.From, value.To
	if from > to {
		from, to = to, from
	}
	return from, to
}

func isAutoRange(value *RangeConfig) bool {
	if value == nil {
		return true
	}
	from, to := xmuxRangeBounds(value)
	// RangeConfig.rand samples [from, to), so 0-1 is exactly the auto
	// sentinel rather than a range that can produce a positive limit.
	return from == 0 && to <= 1
}

func isNegativeRange(value *RangeConfig) bool {
	if value == nil {
		return false
	}
	from, to := xmuxRangeBounds(value)
	// A half-open range ending at zero still samples only negative values.
	return from < 0 && to <= 0
}

func isValidXmuxLimit(value *RangeConfig) bool {
	if isAutoRange(value) {
		return true
	}
	if isNegativeRange(value) {
		return true
	}
	from, _ := xmuxRangeBounds(value)
	return from > 0
}

func xmuxDefaultsForHTTPVersion(httpVersion string) (*RangeConfig, *RangeConfig) {
	switch httpVersion {
	case "1.1", "http/1.1":
		// An H1 XmuxClient is a transport/pool wrapper, not a TCP connection.
		// Keep one wrapper and control packet uploads in the H1 socket pool.
		return &RangeConfig{From: -1, To: -1}, &RangeConfig{From: 1, To: 1}
	case "3", "h3":
		return &RangeConfig{From: 64, To: 96}, &RangeConfig{From: 2, To: 2}
	default: // H2, REALITY, and unknown future callers use the conservative H2 policy.
		return &RangeConfig{From: 32, To: 64}, &RangeConfig{From: 3, To: 3}
	}
}

func resolveXmuxLimit(value, fallback *RangeConfig) *RangeConfig {
	if isAutoRange(value) {
		return cloneRangeConfig(fallback)
	}
	// The documented off value is -1. Older XHTTP accepted any wholly negative
	// scalar/range and all such samples followed the same non-positive branch;
	// canonicalize those legacy aliases without changing their behavior.
	if isNegativeRange(value) {
		return &RangeConfig{From: -1, To: -1}
	}
	if !isValidXmuxLimit(value) {
		return cloneRangeConfig(fallback)
	}
	return cloneRangeConfig(value)
}

func resolveOptionalXmuxRange(value, fallback *RangeConfig) *RangeConfig {
	if value == nil {
		return cloneRangeConfig(fallback)
	}
	return cloneRangeConfig(value)
}

// resolveXmuxConfig turns the public 0=auto/-1=off representation into the
// effective per-protocol scheduler settings without modifying the shared
// protobuf config. The optional hMax fields resolve independently: an omitted
// message gets its historical default while an explicit zero message retains
// the established unlimited behavior. Positive protobuf values are always
// explicit; an old precompiled config whose builder injected maxConnections=3
// must be rebuilt from JSON to opt into auto defaults because the wire format
// has no field-presence bit that can distinguish it.
func resolveXmuxConfig(value *XmuxConfig, httpVersion string) *XmuxConfig {
	defaultConcurrency, defaultConnections := xmuxDefaultsForHTTPVersion(httpVersion)
	if value == nil {
		value = &XmuxConfig{}
	}
	resolved := &XmuxConfig{
		MaxConcurrency:   resolveXmuxLimit(value.MaxConcurrency, defaultConcurrency),
		MaxConnections:   resolveXmuxLimit(value.MaxConnections, defaultConnections),
		CMaxReuseTimes:   cloneRangeConfig(value.CMaxReuseTimes),
		HMaxRequestTimes: resolveOptionalXmuxRange(value.HMaxRequestTimes, &RangeConfig{From: 600, To: 900}),
		HMaxReusableSecs: resolveOptionalXmuxRange(value.HMaxReusableSecs, &RangeConfig{From: 1800, To: 3000}),
		HKeepAlivePeriod: value.HKeepAlivePeriod,
	}
	return resolved
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c *RangeConfig) rand() int32 {
	if c == nil {
		return 0
	}
	return int32(crypto.RandBetween(int64(c.From), int64(c.To)))
}

// predefined
var PredefinedTable = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

// MaxSessionIDLength is a resource-safety ceiling for locally generated
// identifiers. It matches net/http's default maximum header budget while still
// allowing deployments that explicitly raise XHTTP's legacy 8 KiB H1/H2
// serverMaxHeaderBytes limit (and H3's larger zero-value default).
const MaxSessionIDLength int32 = 1 << 20

func (c *Config) GenerateSessionID() string {
	length := c.SessionIDLength.rand()
	table := c.SessionIDTable
	if predefined, ok := PredefinedTable[table]; ok {
		table = predefined
	}
	if table != "" && length > 0 && length <= MaxSessionIDLength {
		id := make([]byte, length)
		for i := range id {
			id[i] = table[rand.N(len(table))]
		}
		return string(id)
	} else {
		uuid := uuid.New()
		return uuid.String()
	}
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}
