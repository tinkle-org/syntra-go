// Package websocket carries one encrypted Syntra record per binary message.
package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
	"unicode/utf8"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

const (
	Subprotocol  = "syntra.1.0"
	EndpointPath = "/syntra/1.0/ws"
	maxFrames    = 128
)

type records struct {
	conn   net.Conn
	reader *bufio.Reader
	client bool
	writer chan struct{}
}

func (r *records) Close() error { return stream.Error(r.conn.Close()) }

func (r *records) ReadMessage(ctx context.Context, dst []byte) (out []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = stream.Do(ctx, r.conn, true, false, func() error {
		out = dst[:0]
		fragmented := false
		for count := 0; count < maxFrames; count++ {
			var head [2]byte
			if _, err := io.ReadFull(r.reader, head[:]); err != nil {
				return err
			}
			fin, opcode, masked := head[0]&0x80 != 0, head[0]&15, head[1]&0x80 != 0
			if head[0]&0x70 != 0 || masked == r.client {
				return ordered.ErrProtocol
			}
			n := uint64(head[1] & 127)
			switch n {
			case 126:
				var ext [2]byte
				if _, err := io.ReadFull(r.reader, ext[:]); err != nil {
					return err
				}
				n = uint64(binary.BigEndian.Uint16(ext[:]))
				if n < 126 {
					return ordered.ErrProtocol
				}
			case 127:
				// No valid record or control frame needs a 64-bit length.
				return ordered.ErrProtocol
			}
			control := opcode&8 != 0
			if control {
				if !fin || n > 125 || (opcode != 8 && opcode != 9 && opcode != 10) {
					return ordered.ErrProtocol
				}
			} else {
				if (opcode != 2 && opcode != 0) || (opcode == 0) != fragmented || n > uint64(min(cap(dst), securechannel.MaxCiphertext)-len(out)) {
					return ordered.ErrProtocol
				}
			}
			var mask [4]byte
			if masked {
				if _, err := io.ReadFull(r.reader, mask[:]); err != nil {
					return err
				}
			}
			var scratch [125]byte
			var payload []byte
			if control {
				payload = scratch[:int(n)]
			} else {
				start := len(out)
				out = dst[:start+int(n)]
				payload = out[start:]
			}
			if _, err := io.ReadFull(r.reader, payload); err != nil {
				return err
			}
			if masked {
				for i := range payload {
					payload[i] ^= mask[i%4]
				}
			}
			switch opcode {
			case 8:
				if len(payload) == 1 {
					return ordered.ErrProtocol
				}
				if len(payload) >= 2 {
					code := binary.BigEndian.Uint16(payload[:2])
					if !validClose(code) || !utf8.Valid(payload[2:]) {
						return ordered.ErrProtocol
					}
				}
				return ordered.ErrClosed
			case 9:
				if err := r.write(ctx, 10, payload); err != nil {
					return err
				}
			case 10:
			default:
				if fin {
					if len(out) < 17 {
						return ordered.ErrProtocol
					}
					return nil
				}
				fragmented = true
			}
		}
		return ordered.ErrProtocol
	})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return out, nil
}

func validClose(code uint16) bool {
	return code >= 3000 && code <= 4999 || code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006
}

func (r *records) WriteMessage(ctx context.Context, p []byte) error {
	if len(p) < 17 || len(p) > securechannel.MaxCiphertext {
		_ = r.Close()
		return ordered.ErrProtocol
	}
	err := r.write(ctx, 2, p)
	if err != nil {
		_ = r.Close()
	}
	return err
}

func (r *records) write(ctx context.Context, opcode byte, p []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case r.writer <- struct{}{}:
	case <-ctx.Done():
		return stream.ContextError(ctx)
	}
	defer func() { <-r.writer }()
	return stream.Do(ctx, r.conn, false, true, func() error {
		var header [8]byte
		header[0] = 0x80 | opcode
		n := 2
		if len(p) < 126 {
			header[1] = byte(len(p))
		} else {
			header[1] = 126
			binary.BigEndian.PutUint16(header[2:4], uint16(len(p)))
			n = 4
		}
		var mask [4]byte
		if r.client {
			header[1] |= 0x80
			if _, err := rand.Read(mask[:]); err != nil {
				return ordered.ErrIO
			}
			copy(header[n:], mask[:])
			n += 4
		}
		if err := stream.WriteAll(r.conn, header[:n]); err != nil {
			return err
		}
		if !r.client {
			return stream.WriteAll(r.conn, p)
		}
		var scratch [4096]byte
		for offset := 0; offset < len(p); {
			n := min(len(scratch), len(p)-offset)
			for i := 0; i < n; i++ {
				scratch[i] = p[offset+i] ^ mask[(offset+i)%4]
			}
			if err := stream.WriteAll(r.conn, scratch[:n]); err != nil {
				return err
			}
			offset += n
		}
		return nil
	})
}
