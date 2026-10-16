// ws-audio-test exercises Janus AudioBridge plain-RTP and core RTP-over-WebSocket (rtpws).
//
// Usage:
//
//	go run . signaling --janus-http http://127.0.0.1:8088/janus --token '...' --room demo
//	go run . plain-rtp --janus-http ... --token ... --room demo --local-ip 127.0.0.1 --tone
//	go run . ws-stream --janus-http ... --token ... --room demo --tone --expect-rx 10
//	go run . ws-e2e --janus-http ... --token ... --room demo --local-ip 127.0.0.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/rtp"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "signaling":
		runSignaling(os.Args[2:])
	case "plain-rtp":
		runPlainRTP(os.Args[2:])
	case "ws-stream":
		runWSStream(os.Args[2:])
	case "ws-e2e":
		runWSE2E(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Janus AudioBridge RTP / RTP-over-WebSocket test CLI

Commands:
  signaling   Create room + join, print media URLs
  plain-rtp   Join as plain RTP UDP; send and receive RTP with stats
  ws-stream   Join via media=websocket and stream binary RTP over WS/WSS
  ws-e2e      Plain-RTP feeder + WS media participant (validates outbound mix)

Janus core config (janus.jcfg):
  rtpws: { enable_rtp_ws = true, port = 8190, path = "/rtp-ws", ... }
  AudioBridge room: allow_ws_participants = true

Examples:
  go run . signaling --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --media websocket
  go run . plain-rtp --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --local-ip 127.0.0.1 --tone --expect-rx 50
  go run . ws-stream --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --tone --expect-rx 50
  go run . ws-e2e --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --local-ip 127.0.0.1

Flags (plain-rtp, ws-stream, ws-e2e, signaling):
  --codec          Audio codec for join and tone: opus, pcma, pcmu, l16, or l16-48 (default opus)
  --framing        WS wire framing (ws-stream/ws-e2e): rtp (default) or payload (raw codec payloads)
  --tone           Send 440Hz payload (PT from codec / server call_info)
  --expect-rx N    Exit with error if fewer than N media frames received (default 0)
  --stats-interval Print tx/rx counters periodically (default 2s)

Examples with G.711 / L16 / payload framing:
  go run . ws-stream --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --codec pcma --tone
  go run . ws-stream --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --codec l16 --tone
  go run . ws-stream --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --codec pcmu --framing payload --tone
  go run . plain-rtp --janus-http http://127.0.0.1:8088/janus --token "$TOKEN" --room test1 --codec pcmu --local-ip 127.0.0.1 --tone

`)
}

type mediaFormat struct {
	codec         string
	payloadType   uint8
	sampleRate    uint32
	timestampStep uint32
	payloadSize   int
}

func mediaFormatFromName(name string) (mediaFormat, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "opus":
		return mediaFormat{
			codec:         "opus",
			payloadType:   100,
			sampleRate:    48000,
			timestampStep: 960,
			payloadSize:   160,
		}, nil
	case "pcma":
		return mediaFormat{
			codec:         "pcma",
			payloadType:   8,
			sampleRate:    8000,
			timestampStep: 160,
			payloadSize:   160,
		}, nil
	case "pcmu":
		return mediaFormat{
			codec:         "pcmu",
			payloadType:   0,
			sampleRate:    8000,
			timestampStep: 160,
			payloadSize:   160,
		}, nil
	case "l16":
		// L16/16000: 16-bit linear PCM, 20ms => 320 samples => 640 bytes.
		return mediaFormat{
			codec:         "l16",
			payloadType:   100,
			sampleRate:    16000,
			timestampStep: 320,
			payloadSize:   640,
		}, nil
	case "l16-48":
		// L16/48000: 16-bit linear PCM, 20ms => 960 samples => 1920 bytes.
		return mediaFormat{
			codec:         "l16-48",
			payloadType:   100,
			sampleRate:    48000,
			timestampStep: 960,
			payloadSize:   1920,
		}, nil
	default:
		return mediaFormat{}, fmt.Errorf("unsupported codec %q (use opus, pcma, pcmu, l16, or l16-48)", name)
	}
}

// codecPayloadBytes returns the RTP payload size in bytes for a number of samples.
func codecPayloadBytes(codec string, samples uint32) int {
	switch codec {
	case "opus":
		return 160
	case "l16", "l16-48":
		return int(samples) * 2 // 16-bit samples
	default:
		return int(samples) // 1 byte/sample for G.711
	}
}

func mediaFormatFromCallInfo(raw []byte) (mediaFormat, error) {
	var info struct {
		Type        string  `json:"type"`
		Codec       string  `json:"codec"`
		SampleRate  float64 `json:"sample_rate"`
		PayloadType float64 `json:"payload_type"`
		PtimeMs     float64 `json:"ptime_ms"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return mediaFormat{}, err
	}
	if info.Type != "" && info.Type != "call_info" {
		return mediaFormat{}, fmt.Errorf("unexpected call_info type %q", info.Type)
	}
	base, err := mediaFormatFromName(info.Codec)
	if err != nil {
		return mediaFormat{}, err
	}
	if info.SampleRate > 0 {
		base.sampleRate = uint32(info.SampleRate)
	}
	if info.PayloadType >= 0 && info.PayloadType <= 127 {
		base.payloadType = uint8(info.PayloadType)
	}
	ptimeMs := info.PtimeMs
	if ptimeMs <= 0 {
		ptimeMs = 20
	}
	samplesPerPacket := uint32(float64(base.sampleRate) * ptimeMs / 1000.0)
	if samplesPerPacket == 0 {
		samplesPerPacket = base.timestampStep
	}
	base.timestampStep = samplesPerPacket
	base.payloadSize = codecPayloadBytes(base.codec, samplesPerPacket)
	return base, nil
}

func parseCodecFlag(fs *flag.FlagSet) *string {
	return fs.String("codec", envOr("CODEC", "opus"), "Audio codec: opus, pcma, pcmu, l16, or l16-48 (env: CODEC)")
}

type rtpCounters struct {
	txPkts  atomic.Uint64
	txBytes atomic.Uint64
	rxPkts  atomic.Uint64
	rxBytes atomic.Uint64
	rxBad   atomic.Uint64
}

func (c *rtpCounters) logSnapshot(label string) {
	log.Printf("[%s] tx=%d pkts (%d B) | rx=%d pkts (%d B) | rx_bad=%d",
		label, c.txPkts.Load(), c.txBytes.Load(), c.rxPkts.Load(), c.rxBytes.Load(), c.rxBad.Load())
}

func watchStats(ctx context.Context, c *rtpCounters, label string, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.logSnapshot(label)
		}
	}
}

func checkExpectRX(c *rtpCounters, expect uint64, label string) error {
	if expect == 0 {
		return nil
	}
	got := c.rxPkts.Load()
	if got < expect {
		return fmt.Errorf("[%s] expected >= %d inbound RTP packets, got %d", label, expect, got)
	}
	log.Printf("[%s] inbound RTP OK (%d >= %d)", label, got, expect)
	return nil
}

type janusClient struct {
	base       string
	token      string
	client     *http.Client
	pollClient *http.Client
	tx         atomic.Uint64
}

func newJanus(base, token string) *janusClient {
	return &janusClient{
		base:       base,
		token:      token,
		client:     &http.Client{Timeout: 20 * time.Second},
		pollClient: &http.Client{Timeout: 70 * time.Second},
	}
}

func (j *janusClient) nextTx() string {
	return fmt.Sprintf("tx-%d", j.tx.Add(1))
}

func (j *janusClient) post(url string, body map[string]any) (map[string]any, error) {
	body["transaction"] = j.nextTx()
	if j.token != "" {
		body["token"] = j.token
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", string(raw), err)
	}
	if janus, _ := out["janus"].(string); janus == "error" {
		return nil, fmt.Errorf("janus error: %v", out["error"])
	}
	return out, nil
}

func (j *janusClient) poll(sessionURL string) (any, error) {
	req, err := http.NewRequest(http.MethodGet, sessionURL, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("maxev", "1")
	if j.token != "" {
		q.Set("token", j.token)
	}
	req.URL.RawQuery = q.Encode()
	res, err := j.pollClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode poll %s: %w", string(raw), err)
	}
	return out, nil
}

func pluginEventFromPollItem(item map[string]any, transaction string) map[string]any {
	if janus, _ := item["janus"].(string); janus == "keepalive" {
		return nil
	}
	ev := extractPluginEvent(item)
	if ev == nil {
		return nil
	}
	if transaction != "" {
		if tx, _ := item["transaction"].(string); tx != transaction {
			return nil
		}
	}
	ab, _ := ev["audiobridge"].(string)
	if ab != "joined" && ab != "event" {
		return nil
	}
	return ev
}

func (j *janusClient) resolvePluginEvent(postResp map[string]any, sessionURL string) (map[string]any, error) {
	if ev := extractPluginEvent(postResp); ev != nil {
		return ev, nil
	}
	if janus, _ := postResp["janus"].(string); janus != "ack" {
		return nil, fmt.Errorf("no plugin data: %s", mustJSON(postResp))
	}
	transaction, _ := postResp["transaction"].(string)
	for i := 0; i < 5; i++ {
		payload, err := j.poll(sessionURL)
		if err != nil {
			return nil, err
		}
		items := []map[string]any{}
		switch v := payload.(type) {
		case map[string]any:
			items = append(items, v)
		case []any:
			for _, raw := range v {
				if item, ok := raw.(map[string]any); ok {
					items = append(items, item)
				}
			}
		}
		for _, item := range items {
			if ev := pluginEventFromPollItem(item, transaction); ev != nil {
				return ev, nil
			}
		}
	}
	return nil, fmt.Errorf("join response missing plugin data after long-poll")
}

type session struct {
	j        *janusClient
	id       int64
	handle   int64
	room     string
	media    string
	codec    string
	framing  string // "rtp" (default) or "payload"
	localIP  string
	useTone  bool
	duration time.Duration
}

func (s *session) payloadFraming() bool {
	return strings.EqualFold(s.framing, "payload")
}

func (s *session) joinCodec() string {
	if s.codec == "" {
		return "opus"
	}
	return s.codec
}

func (s *session) joinBody(display string, extra map[string]any) map[string]any {
	body := map[string]any{
		"request": "join",
		"room":    s.room,
		"display": display,
		"codec":   s.joinCodec(),
		"muted":   false,
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func (s *session) setup() error {
	create, err := s.j.post(s.j.base, map[string]any{"janus": "create"})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	s.id = int64(create["data"].(map[string]any)["id"].(float64))

	attach, err := s.j.post(fmt.Sprintf("%s/%d", s.j.base, s.id), map[string]any{
		"janus":  "attach",
		"plugin": "janus.plugin.audiobridge",
	})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	s.handle = int64(attach["data"].(map[string]any)["id"].(float64))

	handleURL := fmt.Sprintf("%s/%d/%d", s.j.base, s.id, s.handle)

	_, err = s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body": map[string]any{
			"request":                "create",
			"room":                   s.room,
			"permanent":              false,
			"allow_rtp_participants": true,
			"allow_ws_participants":  true,
		},
	})
	if err != nil {
		log.Printf("create room (may exist): %v", err)
	}

	joinBody := s.joinBody("ws-audio-test", nil)
	if s.media == "websocket" {
		joinBody["media"] = "websocket"
	}

	joinResp, err := s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body":  joinBody,
	})
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	log.Printf("join response: %s", mustJSON(joinResp))

	sessionURL := fmt.Sprintf("%s/%d", s.j.base, s.id)
	ev, err := s.j.resolvePluginEvent(joinResp, sessionURL)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	printMediaInfo(ev)
	return nil
}

func (s *session) joinWebSocket() (string, error) {
	create, err := s.j.post(s.j.base, map[string]any{"janus": "create"})
	if err != nil {
		return "", err
	}
	s.id = int64(create["data"].(map[string]any)["id"].(float64))
	attach, err := s.j.post(fmt.Sprintf("%s/%d", s.j.base, s.id), map[string]any{
		"janus": "attach", "plugin": "janus.plugin.audiobridge",
	})
	if err != nil {
		return "", err
	}
	s.handle = int64(attach["data"].(map[string]any)["id"].(float64))
	handleURL := fmt.Sprintf("%s/%d/%d", s.j.base, s.id, s.handle)

	_, _ = s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body": map[string]any{
			"request":               "create",
			"room":                  s.room,
			"allow_rtp_participants": true,
			"allow_ws_participants":  true,
		},
	})

	wsExtra := map[string]any{"media": "websocket"}
	if s.payloadFraming() {
		wsExtra["ws_framing"] = "payload"
	}
	joinResp, err := s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body":  s.joinBody("ws-media-test", wsExtra),
	})
	if err != nil {
		return "", err
	}
	sessionURL := fmt.Sprintf("%s/%d", s.j.base, s.id)
	ev, err := s.j.resolvePluginEvent(joinResp, sessionURL)
	if err != nil {
		return "", fmt.Errorf("join: %w", err)
	}
	ws, ok := ev["websocket_media"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("joined without websocket_media — enable rtpws::enable_rtp_ws in janus.jcfg and allow_ws_participants on room")
	}
	url, _ := ws["url"].(string)
	if url == "" {
		return "", fmt.Errorf("empty websocket_media.url")
	}
	log.Printf("websocket_media.url = %s", url)
	return url, nil
}

func extractPluginEvent(resp map[string]any) map[string]any {
	plug, ok := resp["plugindata"].(map[string]any)
	if !ok {
		return nil
	}
	data, ok := plug["data"].(map[string]any)
	if !ok {
		return nil
	}
	return data
}

func printMediaInfo(ev map[string]any) {
	if ws, ok := ev["websocket_media"].(map[string]any); ok {
		log.Printf("websocket_media.url = %v", ws["url"])
	}
	if rtpObj, ok := ev["rtp"].(map[string]any); ok {
		log.Printf("rtp ip=%v port=%v pt=%v", rtpObj["ip"], rtpObj["port"], rtpObj["payload_type"])
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func runSignaling(args []string) {
	fs := flag.NewFlagSet("signaling", flag.ExitOnError)
	janusHTTP := fs.String("janus-http", envOr("JANUS_HTTP", "http://127.0.0.1:8088/janus"), "Janus HTTP base URL (env: JANUS_HTTP)")
	token := fs.String("token", envOr("TOKEN", ""), "HMAC Janus token (env: TOKEN)")
	room := fs.String("room", envOr("ROOM", "ws-audio-test"), "AudioBridge room id (env: ROOM)")
	media := fs.String("media", "websocket", "join media: websocket or webrtc")
	codec := parseCodecFlag(fs)
	_ = fs.Parse(args)

	format, err := mediaFormatFromName(*codec)
	if err != nil {
		log.Fatal(err)
	}

	s := &session{j: newJanus(*janusHTTP, *token), room: *room, media: *media, codec: format.codec}
	if err := s.setup(); err != nil {
		log.Fatal(err)
	}
}

func runPlainRTP(args []string) {
	fs := flag.NewFlagSet("plain-rtp", flag.ExitOnError)
	janusHTTP := fs.String("janus-http", envOr("JANUS_HTTP", "http://127.0.0.1:8088/janus"), "Janus HTTP base URL (env: JANUS_HTTP)")
	token := fs.String("token", envOr("TOKEN", ""), "HMAC Janus token (env: TOKEN)")
	room := fs.String("room", envOr("ROOM", "ws-audio-test"), "AudioBridge room id (env: ROOM)")
	localIP := fs.String("local-ip", envOr("LOCAL_IP", "127.0.0.1"), "Local IP Janus sends RTP to (env: LOCAL_IP)")
	codec := parseCodecFlag(fs)
	tone := fs.Bool("tone", false, "Send 440Hz tone as RTP")
	duration := fs.Duration("duration", 30*time.Second, "Stream duration")
	expectRX := fs.Uint64("expect-rx", 0, "Fail if fewer inbound RTP packets received")
	statsInterval := fs.Duration("stats-interval", 2*time.Second, "Stats log interval")
	_ = fs.Parse(args)

	format, err := mediaFormatFromName(*codec)
	if err != nil {
		log.Fatal(err)
	}

	s := &session{
		j:        newJanus(*janusHTTP, *token),
		room:     *room,
		codec:    format.codec,
		localIP:  *localIP,
		useTone:  *tone,
		duration: *duration,
	}

	conn, janusRTP, err := s.joinPlainRTP(format)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var counters rtpCounters
	go watchStats(ctx, &counters, "plain-rtp", *statsInterval)
	go readUDPRTP(ctx, conn, &counters, "plain-rtp")

	if *tone {
		go func() {
			if err := writeToneUDPRTP(ctx, conn, janusRTP, &counters, format, *duration); err != nil && ctx.Err() == nil {
				log.Printf("tx error: %v", err)
			}
		}()
	}

	<-ctx.Done()
	time.Sleep(200 * time.Millisecond)
	counters.logSnapshot("plain-rtp")
	if err := checkExpectRX(&counters, *expectRX, "plain-rtp"); err != nil {
		log.Fatal(err)
	}
}

func (s *session) joinPlainRTP(format mediaFormat) (*net.UDPConn, net.UDPAddr, error) {
	create, err := s.j.post(s.j.base, map[string]any{"janus": "create"})
	if err != nil {
		return nil, net.UDPAddr{}, err
	}
	s.id = int64(create["data"].(map[string]any)["id"].(float64))
	attach, err := s.j.post(fmt.Sprintf("%s/%d", s.j.base, s.id), map[string]any{
		"janus": "attach", "plugin": "janus.plugin.audiobridge",
	})
	if err != nil {
		return nil, net.UDPAddr{}, err
	}
	s.handle = int64(attach["data"].(map[string]any)["id"].(float64))
	handleURL := fmt.Sprintf("%s/%d/%d", s.j.base, s.id, s.handle)

	_, _ = s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body": map[string]any{
			"request":                "create",
			"room":                   s.room,
			"allow_rtp_participants": true,
		},
	})

	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, net.UDPAddr{}, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, net.UDPAddr{}, err
	}
	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("local UDP %s:%d", s.localIP, localPort)

	joinResp, err := s.j.post(handleURL, map[string]any{
		"janus": "message",
		"body": s.joinBody("plain-rtp-test", map[string]any{
			"rtp": map[string]any{
				"ip":           s.localIP,
				"port":         localPort,
				"payload_type": int(format.payloadType),
			},
		}),
	})
	if err != nil {
		conn.Close()
		return nil, net.UDPAddr{}, err
	}
	sessionURL := fmt.Sprintf("%s/%d", s.j.base, s.id)
	ev, err := s.j.resolvePluginEvent(joinResp, sessionURL)
	if err != nil {
		conn.Close()
		return nil, net.UDPAddr{}, fmt.Errorf("join: %w", err)
	}
	printMediaInfo(ev)
	rtpObj, ok := ev["rtp"].(map[string]any)
	if !ok {
		conn.Close()
		return nil, net.UDPAddr{}, fmt.Errorf("joined without rtp object — enable allow_rtp_participants")
	}
	janusIP := rtpObj["ip"].(string)
	janusPort := int(rtpObj["port"].(float64))
	remote, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", janusIP, janusPort))
	if err != nil {
		conn.Close()
		return nil, net.UDPAddr{}, err
	}
	log.Printf("send RTP to Janus %s", remote.String())
	return conn, *remote, nil
}

func runWSStream(args []string) {
	fs := flag.NewFlagSet("ws-stream", flag.ExitOnError)
	janusHTTP := fs.String("janus-http", envOr("JANUS_HTTP", ""), "Janus HTTP base URL (env: JANUS_HTTP)")
	token := fs.String("token", envOr("TOKEN", ""), "HMAC Janus token (env: TOKEN)")
	room := fs.String("room", envOr("ROOM", "ws-audio-test"), "AudioBridge room id (env: ROOM)")
	codec := parseCodecFlag(fs)
	framing := parseFramingFlag(fs)
	wsURL := fs.String("ws-url", "", "WebSocket media URL (optional if --janus-http is set)")
	tone := fs.Bool("tone", true, "Send tone as binary frames (RTP, or raw payload in payload framing)")
	duration := fs.Duration("duration", 30*time.Second, "Stream duration")
	expectRX := fs.Uint64("expect-rx", 0, "Fail if fewer inbound media frames received")
	statsInterval := fs.Duration("stats-interval", 2*time.Second, "Stats log interval")
	_ = fs.Parse(args)

	format, err := mediaFormatFromName(*codec)
	if err != nil {
		log.Fatal(err)
	}

	url := *wsURL
	if url == "" {
		if *janusHTTP == "" {
			log.Fatal("either --ws-url or --janus-http is required")
		}
		s := &session{j: newJanus(*janusHTTP, *token), room: *room, codec: format.codec, framing: *framing}
		url, err = s.joinWebSocket()
		if err != nil {
			log.Fatal("join:", err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := runWSBidirectional(ctx, url, *tone, format, strings.EqualFold(*framing, "payload"), *duration, *expectRX, *statsInterval, "ws-stream"); err != nil {
		log.Fatal(err)
	}
}

func parseFramingFlag(fs *flag.FlagSet) *string {
	return fs.String("framing", envOr("FRAMING", "rtp"), "WS wire framing: rtp (full RTP packets) or payload (raw codec payloads) (env: FRAMING)")
}

func runWSE2E(args []string) {
	fs := flag.NewFlagSet("ws-e2e", flag.ExitOnError)
	janusHTTP := fs.String("janus-http", envOr("JANUS_HTTP", "http://127.0.0.1:8088/janus"), "Janus HTTP base URL (env: JANUS_HTTP)")
	token := fs.String("token", envOr("TOKEN", ""), "HMAC Janus token (env: TOKEN)")
	room := fs.String("room", envOr("ROOM", "ws-audio-test"), "AudioBridge room id (env: ROOM)")
	localIP := fs.String("local-ip", envOr("LOCAL_IP", "127.0.0.1"), "Local IP for plain-RTP feeder (env: LOCAL_IP)")
	codec := parseCodecFlag(fs)
	framing := parseFramingFlag(fs)
	duration := fs.Duration("duration", 30*time.Second, "Test duration")
	expectRX := fs.Uint64("expect-rx", 50, "Minimum inbound media frames on WS leg (mix from feeder)")
	statsInterval := fs.Duration("stats-interval", 2*time.Second, "Stats log interval")
	_ = fs.Parse(args)

	format, err := mediaFormatFromName(*codec)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	feeder := &session{j: newJanus(*janusHTTP, *token), room: *room, codec: format.codec, localIP: *localIP}
	conn, remote, err := feeder.joinPlainRTP(format)
	if err != nil {
		log.Fatal("feeder:", err)
	}
	defer conn.Close()

	var feederCounters rtpCounters
	go writeToneUDPRTP(ctx, conn, remote, &feederCounters, format, *duration)

	wsSess := &session{j: newJanus(*janusHTTP, *token), room: *room, codec: format.codec, framing: *framing}
	wsURL, err := wsSess.joinWebSocket()
	if err != nil {
		log.Fatal("ws join:", err)
	}

	time.Sleep(500 * time.Millisecond)
	if err := runWSBidirectional(ctx, wsURL, false, format, strings.EqualFold(*framing, "payload"), *duration, *expectRX, *statsInterval, "ws-e2e"); err != nil {
		log.Fatal(err)
	}
}

func runWSBidirectional(ctx context.Context, wsURL string, sendTone bool, joinFormat mediaFormat, payloadFraming bool, dur time.Duration, expectRX uint64, statsInterval time.Duration, label string) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     []string{"janus-rtp-ws"},
	}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("[%s] connected %s", label, wsURL)

	_, msg, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("call_info: %w", err)
	}
	log.Printf("[%s] server: %s", label, string(msg))

	streamFormat, err := mediaFormatFromCallInfo(msg)
	if err != nil {
		return fmt.Errorf("call_info: %w", err)
	}
	if joinFormat.codec != "" && joinFormat.codec != streamFormat.codec {
		log.Printf("[%s] note: joined with codec=%s, server call_info codec=%s",
			label, joinFormat.codec, streamFormat.codec)
	}
	log.Printf("[%s] media codec=%s pt=%d rate=%d step=%d payload=%d B framing=%s",
		label, streamFormat.codec, streamFormat.payloadType, streamFormat.sampleRate,
		streamFormat.timestampStep, streamFormat.payloadSize, framingLabel(payloadFraming))

	var counters rtpCounters
	go watchStats(ctx, &counters, label, statsInterval)
	go readWSRTP(ctx, conn, &counters, label, payloadFraming)

	if sendTone {
		go func() {
			if err := writeToneWS(ctx, conn, &counters, streamFormat, payloadFraming, dur); err != nil && ctx.Err() == nil {
				log.Printf("[%s] tx error: %v", label, err)
			}
		}()
	}

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			counters.logSnapshot(label)
			return checkExpectRX(&counters, expectRX, label)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	counters.logSnapshot(label)
	return checkExpectRX(&counters, expectRX, label)
}

func readUDPRTP(ctx context.Context, conn *net.UDPConn, c *rtpCounters, label string) {
	buf := make([]byte, 1500)
	var lastSeq uint16
	var haveSeq bool
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if !accountRTP(buf[:n], c, &lastSeq, &haveSeq) {
			log.Printf("[%s] invalid RTP %d bytes from %s", label, n, addr)
			continue
		}
		if c.rxPkts.Load()%50 == 1 {
			pkt := &rtp.Packet{}
			if pkt.Unmarshal(buf[:n]) == nil {
				log.Printf("[%s] rx seq=%d ts=%d pt=%d ssrc=%d (%d B) from %s",
					label, pkt.SequenceNumber, pkt.Timestamp, pkt.PayloadType, pkt.SSRC, n, addr)
			}
		}
	}
}

func framingLabel(payloadFraming bool) string {
	if payloadFraming {
		return "payload"
	}
	return "rtp"
}

func readWSRTP(ctx context.Context, conn *websocket.Conn, c *rtpCounters, label string, payloadFraming bool) {
	var lastSeq uint16
	var haveSeq bool
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if mt != websocket.BinaryMessage {
			log.Printf("[%s] rx text: %s", label, string(data))
			continue
		}
		if payloadFraming {
			// Raw codec payload: no RTP header to parse, just count it.
			if len(data) == 0 {
				c.rxBad.Add(1)
				continue
			}
			c.rxPkts.Add(1)
			c.rxBytes.Add(uint64(len(data)))
			if c.rxPkts.Load()%50 == 1 {
				log.Printf("[%s] rx payload %d B", label, len(data))
			}
			continue
		}
		if !accountRTP(data, c, &lastSeq, &haveSeq) {
			log.Printf("[%s] invalid RTP %d bytes on WS", label, len(data))
			continue
		}
		if c.rxPkts.Load()%50 == 1 {
			pkt := &rtp.Packet{}
			if pkt.Unmarshal(data) == nil {
				log.Printf("[%s] rx seq=%d ts=%d pt=%d ssrc=%d (%d B)",
					label, pkt.SequenceNumber, pkt.Timestamp, pkt.PayloadType, pkt.SSRC, len(data))
			}
		}
	}
}

func accountRTP(data []byte, c *rtpCounters, lastSeq *uint16, haveSeq *bool) bool {
	if len(data) < 12 {
		c.rxBad.Add(1)
		return false
	}
	pkt := &rtp.Packet{}
	if err := pkt.Unmarshal(data); err != nil {
		c.rxBad.Add(1)
		return false
	}
	c.rxPkts.Add(1)
	c.rxBytes.Add(uint64(len(data)))
	if *haveSeq {
		exp := *lastSeq + 1
		if pkt.SequenceNumber != exp && c.rxPkts.Load() > 2 {
			log.Printf("rtp seq gap: expected %d got %d", exp, pkt.SequenceNumber)
		}
	}
	*lastSeq = pkt.SequenceNumber
	*haveSeq = true
	return true
}

func writeToneUDPRTP(ctx context.Context, conn *net.UDPConn, remote net.UDPAddr, c *rtpCounters, format mediaFormat, dur time.Duration) error {
	return writeToneRTP(ctx, format, dur, func(pkt *rtp.Packet) error {
		raw, err := pkt.Marshal()
		if err != nil {
			return err
		}
		n, err := conn.WriteToUDP(raw, &remote)
		if err != nil {
			return err
		}
		c.txPkts.Add(1)
		c.txBytes.Add(uint64(n))
		return nil
	})
}

func writeToneWS(ctx context.Context, conn *websocket.Conn, c *rtpCounters, format mediaFormat, payloadFraming bool, dur time.Duration) error {
	return writeToneRTP(ctx, format, dur, func(pkt *rtp.Packet) error {
		// In payload framing the wire carries the raw codec payload only; the
		// gateway synthesizes the RTP header on the way in.
		out := pkt.Payload
		if !payloadFraming {
			raw, err := pkt.Marshal()
			if err != nil {
				return err
			}
			out = raw
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, out); err != nil {
			return err
		}
		c.txPkts.Add(1)
		c.txBytes.Add(uint64(len(out)))
		return nil
	})
}

func writeToneRTP(ctx context.Context, format mediaFormat, dur time.Duration, send func(*rtp.Packet) error) error {
	payloadSize := format.payloadSize
	if payloadSize <= 0 {
		payloadSize = 160
	}
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    format.payloadType,
			SequenceNumber: 1,
			Timestamp:      0,
			SSRC:           0x12345678,
		},
		Payload: make([]byte, payloadSize),
	}
	step := format.timestampStep
	if step == 0 {
		step = 160
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(dur)
	phase := 0.0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil
			}
			fillTonePayload(pkt.Payload, format, &phase)
			pkt.Header.SequenceNumber++
			pkt.Header.Timestamp += step
			if err := send(pkt); err != nil {
				return err
			}
		}
	}
}

func fillTonePayload(payload []byte, format mediaFormat, phase *float64) {
	rate := float64(format.sampleRate)
	if rate <= 0 {
		rate = 8000
	}
	switch format.codec {
	case "pcma":
		for i := range payload {
			pcm := int16(math.Sin(*phase) * 3000)
			payload[i] = linearToAlaw(pcm)
			*phase += 2 * math.Pi * 440 / rate
		}
	case "pcmu":
		for i := range payload {
			pcm := int16(math.Sin(*phase) * 3000)
			payload[i] = linearToMulaw(pcm)
			*phase += 2 * math.Pi * 440 / rate
		}
	case "l16", "l16-48":
		// 16-bit big-endian PCM samples (RFC 3551 L16 is network byte order).
		for i := 0; i+1 < len(payload); i += 2 {
			pcm := int16(math.Sin(*phase) * 3000)
			payload[i] = byte(uint16(pcm) >> 8)
			payload[i+1] = byte(uint16(pcm))
			*phase += 2 * math.Pi * 440 / rate
		}
	default:
		for i := range payload {
			payload[i] = byte(int(math.Sin(*phase)*3000) + 128)
			*phase += 2 * math.Pi * 440 / rate
		}
	}
}

func linearToAlaw(sample int16) byte {
	sign := byte(0)
	if sample < 0 {
		sign = 0x80
		sample = -sample
	}
	if sample > 32635 {
		sample = 32635
	}
	if sample >= 256 {
		exponent := 7
		for expMask := int16(0x4000); (sample&expMask) == 0 && exponent > 0; expMask >>= 1 {
			exponent--
		}
		mantissa := (sample >> (uint(exponent) + 4)) & 0x0F
		return sign | byte(exponent<<4) | byte(mantissa)
	}
	return sign | byte(sample>>4)
}

func linearToMulaw(sample int16) byte {
	const bias = 0x84
	sign := byte(0)
	if sample < 0 {
		sign = 0x80
		sample = -sample
	}
	if sample > 32635 {
		sample = 32635
	}
	sample += bias
	exponent := 7
	for expMask := int16(0x4000); (sample&expMask) == 0 && exponent > 0; expMask >>= 1 {
		exponent--
	}
	mantissa := (sample >> (uint(exponent) + 3)) & 0x0F
	return ^(sign | byte(exponent<<4) | byte(mantissa))
}
