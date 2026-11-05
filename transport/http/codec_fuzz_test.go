package syntrahttp

import "testing"

func FuzzHTTPHeaders(f *testing.F) {
	authority, _ := NewAuthority("localhost:443")
	route := routeFromRandom([32]byte{1})
	for _, operation := range []Operation{Open, Send, Poll, Close} {
		size := 0
		if operation == Open {
			size = 100
		} else if operation == Send {
			size = 17
		}
		if raw, err := requestHeader(operation, authority, route, 1, size); err == nil {
			f.Add(raw, byte(operation))
		}
		if raw, err := responseHeader(operation, route, 1, size); err == nil {
			f.Add(raw, byte(operation))
		}
	}
	f.Add([]byte("POST /syntra/1.0/http/open HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"), byte(Open))
	f.Add([]byte{}, byte(0))
	f.Fuzz(func(t *testing.T, raw []byte, kind byte) {
		if len(raw) > 2*MaxHeaders {
			return
		}
		if head, err := ParseRequest(raw, authority, OriginPolicy{}); err == nil {
			if head.BodyLen < 0 || head.BodyLen > MaxRecord || head.Operation.Path() == "" {
				t.Fatal("accepted request exceeds codec bounds")
			}
			canonical, err := requestHeader(head.Operation, authority, head.Route, head.Counter, head.BodyLen)
			if err != nil {
				t.Fatal("accepted request cannot be encoded")
			}
			if got, err := ParseRequest(canonical, authority, OriginPolicy{}); err != nil || got != head {
				t.Fatal("canonical request changed its operation")
			}
		}
		operation := Operation(kind%4 + 1)
		if head, err := ParseResponse(raw, operation); err == nil {
			if head.BodyLen < 0 || head.BodyLen > MaxRecord {
				t.Fatal("accepted response exceeds codec bounds")
			}
			canonical, err := responseHeader(operation, head.Route, head.Counter, head.BodyLen)
			if err != nil {
				t.Fatal("accepted response cannot be encoded")
			}
			if got, err := ParseResponse(canonical, operation); err != nil || got != head {
				t.Fatal("canonical response changed its operation")
			}
		}
	})
}
