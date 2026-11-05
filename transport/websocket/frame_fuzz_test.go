package websocket

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

type fuzzConn struct{ *bytes.Reader }

func (*fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*fuzzConn) Close() error                     { return nil }
func (*fuzzConn) LocalAddr() net.Addr              { return nil }
func (*fuzzConn) RemoteAddr() net.Addr             { return nil }
func (*fuzzConn) SetDeadline(time.Time) error      { return nil }
func (*fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (*fuzzConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*fuzzConn)(nil)
var _ io.Writer = (*fuzzConn)(nil)

func FuzzRecordFrames(f *testing.F) {
	f.Add(append([]byte{0x82, 17}, make([]byte, 17)...), true)
	f.Add(append([]byte{0x82, 0x91, 1, 2, 3, 4}, make([]byte, 17)...), false)
	f.Add([]byte{0x89, 0, 0x82, 0x7f}, true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, raw []byte, client bool) {
		if len(raw) > 2*securechannel.MaxCiphertext {
			return
		}
		conn := &fuzzConn{bytes.NewReader(raw)}
		r := &records{conn: conn, reader: bufio.NewReader(conn), client: client, writer: make(chan struct{}, 1)}
		frame, err := r.ReadMessage(context.Background(), make([]byte, 0, securechannel.MaxCiphertext))
		if err == nil && (len(frame) < 17 || len(frame) > securechannel.MaxCiphertext) {
			t.Fatal("accepted record exceeds wire bounds")
		}
	})
}
