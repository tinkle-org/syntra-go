package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

const maxHeaders = 16 * 1024
const maxFields = 64

func endpoint(raw string, secure bool) (tlsstream.Authority, error) {
	if len(raw) > 4096 {
		return tlsstream.Authority{}, securechannel.ErrConfig
	}
	u, err := url.Parse(raw)
	scheme, port := "ws", uint16(80)
	if secure {
		scheme, port = "wss", 443
	}
	if err != nil || u.Scheme != scheme || u.User != nil || u.Opaque != "" || u.Host == "" || u.Path != EndpointPath || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return tlsstream.Authority{}, securechannel.ErrConfig
	}
	if u.Port() != "" {
		n, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || n == 0 {
			return tlsstream.Authority{}, securechannel.ErrConfig
		}
		port = uint16(n)
	} else if strings.HasSuffix(u.Host, ":") {
		return tlsstream.Authority{}, securechannel.ErrConfig
	}
	a, err := tlsstream.NewAuthority(u.Hostname(), port)
	if err != nil || !secure && !loopbackHost(a.Host()) {
		return tlsstream.Authority{}, securechannel.ErrConfig
	}
	return a, nil
}
func loopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}
func loopbackPeer(conn net.Conn) bool {
	if conn == nil || conn.RemoteAddr() == nil {
		return false
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// readHeaders caps bytes and fields before parsing or allocating field values.
// The reader is retained because a peer may coalesce its first frame with HTTP.
func readHeaders(r *bufio.Reader) (string, map[string]string, error) {
	var bytes [maxHeaders]byte
	n := 0
	for {
		if n == len(bytes) {
			return "", nil, securechannel.ErrConfig
		}
		b, err := r.ReadByte()
		if err != nil {
			return "", nil, err
		}
		bytes[n] = b
		n++
		if b == '\n' && (n < 2 || bytes[n-2] != '\r') || n > 1 && bytes[n-2] == '\r' && b != '\n' {
			return "", nil, securechannel.ErrConfig
		}
		if n >= 4 && string(bytes[n-4:n]) == "\r\n\r\n" {
			break
		}
	}
	block := string(bytes[:n-4])
	if strings.Count(block, "\r\n") > maxFields {
		return "", nil, securechannel.ErrConfig
	}
	lines := strings.Split(block, "\r\n")
	for _, c := range []byte(lines[0]) {
		if c < 32 || c == 127 {
			return "", nil, securechannel.ErrConfig
		}
	}
	fields := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return "", nil, securechannel.ErrConfig
		}
		for _, c := range []byte(name) {
			if !token(c) {
				return "", nil, securechannel.ErrConfig
			}
		}
		for _, c := range []byte(value) {
			if c < 32 && c != '\t' || c == 127 {
				return "", nil, securechannel.ErrConfig
			}
		}
		name = strings.ToLower(name)
		if _, duplicate := fields[name]; duplicate {
			return "", nil, securechannel.ErrConfig
		}
		fields[name] = strings.Trim(value, " \t")
	}
	for _, forbidden := range []string{"authorization", "proxy-authorization", "cookie", "set-cookie", "origin", "sec-websocket-extensions", "transfer-encoding", "content-length"} {
		if _, present := fields[forbidden]; present {
			return "", nil, securechannel.ErrConfig
		}
	}
	if !strings.EqualFold(fields["upgrade"], "websocket") || fields["sec-websocket-protocol"] != Subprotocol {
		return "", nil, securechannel.ErrConfig
	}
	upgrade := false
	for _, item := range strings.Split(fields["connection"], ",") {
		item = strings.Trim(item, " \t")
		if item == "" {
			return "", nil, securechannel.ErrConfig
		}
		for _, c := range []byte(item) {
			if !token(c) {
				return "", nil, securechannel.ErrConfig
			}
		}
		upgrade = upgrade || strings.EqualFold(item, "upgrade")
	}
	if !upgrade {
		return "", nil, securechannel.ErrConfig
	}
	return lines[0], fields, nil
}
func token(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

func upgrade(ctx context.Context, raw net.Conn, a tlsstream.Authority, client bool, b *ordered.EstablishmentBudget) (ordered.MessageIO, error) {
	conn := stream.New(raw, b)
	if raw == nil || b == nil {
		_ = conn.Close()
		return nil, securechannel.ErrConfig
	}
	attempt, cancel := b.Context(ctx)
	defer cancel()
	r := &records{conn: conn, reader: bufio.NewReaderSize(conn, 4096), client: client, writer: make(chan struct{}, 1)}
	err := stream.Do(attempt, conn, true, true, func() error {
		if err := stream.Check(b); err != nil {
			return err
		}
		if client {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return ordered.ErrIO
			}
			key := base64.StdEncoding.EncodeToString(nonce[:])
			request := "GET " + EndpointPath + " HTTP/1.1\r\nHost: " + a.String() + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: " + Subprotocol + "\r\n\r\n"
			if err := stream.WriteAll(conn, []byte(request)); err != nil {
				return err
			}
			line, h, err := readHeaders(r.reader)
			if err != nil {
				return err
			}
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 || parts[0] != "HTTP/1.1" || parts[1] != "101" || h["sec-websocket-accept"] != acceptKey(key) {
				return securechannel.ErrConfig
			}
		} else {
			line, h, err := readHeaders(r.reader)
			if err != nil {
				return err
			}
			if len(h["sec-websocket-key"]) != 24 {
				return securechannel.ErrConfig
			}
			key, err := base64.StdEncoding.Strict().DecodeString(h["sec-websocket-key"])
			if line != "GET "+EndpointPath+" HTTP/1.1" || h["host"] == "" || h["sec-websocket-version"] != "13" || err != nil || len(key) != 16 {
				return securechannel.ErrConfig
			}
			// Host is routing input, never a substitute for the TLS proof.
			if a.Port() != 0 {
				parsed, err := endpoint("wss://"+h["host"]+EndpointPath, true)
				if err != nil || parsed != a {
					return securechannel.ErrConfig
				}
			} else {
				if _, err := endpoint("ws://"+h["host"]+EndpointPath, false); err != nil {
					return err
				}
			}
			response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(h["sec-websocket-key"]) + "\r\nSec-WebSocket-Protocol: " + Subprotocol + "\r\n\r\n"
			if err := stream.WriteAll(conn, []byte(response)); err != nil {
				return err
			}
		}
		return stream.Check(b)
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return r, nil
}
