// File terminal_close_regression_test.go guards serialized cipher retirement
// before admitted terminal operations have released their cleanup ownership.
package ordered

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// TestTerminalRetireSerializesCipherAccessBeforeOperationJoin races the real
// retirement path with both cipher directions. Cipher closure must not wait for
// admitted work, while scratch cleanup must wait; closed state cannot be reused.
func TestTerminalRetireSerializesCipherAccessBeforeOperationJoin(t *testing.T) {
	for round := 0; round < 32; round++ {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			tr, sender, _ := receiver(t, Options{})
			payload := bytes.Repeat([]byte{'x'}, 1024)
			records := make([][]byte, 129)
			for i := range records {
				var err error
				records[i], err = sender.Encrypt(nil, payload)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tr.channel.Decrypt(nil, records[0]); err != nil {
				t.Fatal(err)
			}
			// Retain a real admission charge across Stop and the cipher race, so
			// the supervisor cannot mask removal of early cipher retirement.
			release := terminalRaceAdmission(t, tr)
			var releaseOnce sync.Once
			defer releaseOnce.Do(release)
			start, finished := make(chan struct{}), make(chan struct{}, 2)
			for _, decrypt := range []bool{false, true} {
				go func(decrypt bool) {
					defer func() { finished <- struct{}{} }()
					<-start
					for _, record := range records[1:] {
						var out []byte
						var err error
						if decrypt {
							out, err = tr.channel.Decrypt(nil, record)
						} else {
							out, err = tr.channel.Encrypt(nil, payload)
						}
						if err == securechannel.ErrClosed {
							if out != nil {
								t.Error("closed cipher returned output")
							}
							return
						}
						if err != nil {
							t.Errorf("concurrent cipher operation: %v", err)
							return
						}
					}
				}(decrypt)
			}
			tr.mu.Lock()
			// Presence exercises terminal retirement only; this zero permit
			// intentionally grants no terminal traffic or authority capability.
			tr.terminalPermit = new(syntra.TerminalPermit)
			tr.mu.Unlock()
			stopped := make(chan struct{})
			go func() { <-start; tr.Stop(); close(stopped) }()
			close(start)
			terminalRaceWait(t, stopped)
			terminalRaceWait(t, finished)
			terminalRaceWait(t, finished)
			if err := tr.channel.CheckLive(); err != securechannel.ErrClosed {
				t.Errorf("cipher still live before operation join: %v", err)
			}
			if out, err := tr.channel.Encrypt(nil, payload); err != securechannel.ErrClosed || out != nil {
				t.Errorf("post-retirement Encrypt = %d bytes, %v", len(out), err)
			}
			if out, err := tr.channel.Decrypt(nil, records[1]); err != securechannel.ErrClosed || out != nil {
				t.Errorf("post-retirement Decrypt = %d bytes, %v", len(out), err)
			}
			select {
			case <-tr.Stopped():
				t.Fatal("cleanup completed before admitted operation released")
			default:
			}
			if len(tr.sendPlain) == 0 || len(tr.recvPlain) == 0 {
				t.Fatal("scratch released before operation join")
			}
			if _, err := tr.Recv(context.Background()); err != ErrClosed {
				t.Errorf("retired transport admitted a new operation: %v", err)
			}
			releaseOnce.Do(release)
			terminalRaceWait(t, tr.Stopped())
		})
	}
}
