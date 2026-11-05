package ordered

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

func terminalRaceWait[T any](t *testing.T, done <-chan T) T {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("terminal race did not join")
		var zero T
		return zero
	}
}

// Hold real operation admission so teardown cannot clear scratch or retire the
// cipher while a buffered record or an unrecorded decrypt result is retained.
func terminalRaceAdmission(t *testing.T, tr *Transport) func() {
	t.Helper()
	release, err := tr.acquire(context.Background(), tr.recvAdmission, tr.recvGate)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

// Isolate completion from idle observation so only the barrier-controlled reader
// can record the real decrypt failure. Stop and failure recording still use the
// production owner methods, with actual carrier interruption and cipher states.
func terminalRaceCompletion(t *testing.T) (*Transport, *securechannel.Channel) {
	t.Helper()
	sender, channel := channels(t)
	ctx, cancel := context.WithCancel(context.Background())
	tr := &Transport{io: &functionalIO{}, channel: channel, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), carrierStopped: make(chan struct{})}
	t.Cleanup(func() {
		tr.Stop()
		terminalRaceWait(t, tr.carrierStopped)
		channel.Close()
		sender.Close()
	})
	return tr, sender
}

func TestBufferedRecordDecryptAfterLocalStopIsClosed(t *testing.T) {
	for _, priorLoss := range []bool{false, true} {
		t.Run(fmt.Sprint("prior-loss=", priorLoss), func(t *testing.T) {
			tr, sender, _ := receiver(t, Options{})
			record, err := sender.Encrypt(nil, envelope([]byte("buffered")))
			if err != nil {
				t.Fatal(err)
			}
			release := terminalRaceAdmission(t, tr)
			defer release()
			var want error
			if priorLoss {
				want = ErrClosed
				tr.abort(want)
			}
			tr.Stop()
			terminalRaceWait(t, tr.carrierStopped)
			// Model shared cipher retirement before the buffered read resumes.
			tr.channel.Close()
			plain, decryptErr := tr.channel.Decrypt(tr.recvPlain[:0], record)
			if plain != nil || decryptErr != securechannel.ErrClosed {
				t.Fatalf("decrypt = %x, %v", plain, decryptErr)
			}
			if err := tr.cipherFailure(decryptErr); err != ErrClosed {
				t.Errorf("local closed cipher = %v, want ErrClosed", err)
			}
			if err := tr.TerminalError(); err != want {
				t.Errorf("local teardown invented a failure: %v, want %v", err, want)
			}
		})
	}
}

func TestLocalStopKeepsDetectedDecryptFailureTerminal(t *testing.T) {
	for _, invalidTag := range []bool{true, false} {
		name := "short-record"
		if invalidTag {
			name = "invalid-tag"
		}
		t.Run(name, func(t *testing.T) {
			tr, sender := terminalRaceCompletion(t)
			record, err := sender.Encrypt(nil, envelope([]byte("buffered")))
			if err != nil {
				t.Fatal(err)
			}
			if invalidTag {
				record[len(record)-1] ^= 1
			} else {
				record = record[:16]
			}
			detected, resume, result := make(chan error, 1), make(chan struct{}), make(chan error, 1)
			finished := make(chan struct{})
			var unblock sync.Once
			go func() {
				defer close(finished)
				_, err := tr.channel.Decrypt(tr.recvPlain[:0], record)
				detected <- err
				<-resume
				result <- tr.cipherFailure(err)
			}()
			defer func() { unblock.Do(func() { close(resume) }); terminalRaceWait(t, finished) }()
			if err := terminalRaceWait(t, detected); err != securechannel.ErrRecord {
				t.Fatalf("real decrypt failure = %v", err)
			}
			// The other direction records loss before local teardown and before
			// the reader records its already-detected cryptographic failure.
			tr.abort(ErrClosed)
			if err := tr.TerminalError(); err != ErrClosed {
				t.Fatalf("initial loss = %v", err)
			}
			tr.Stop()
			terminalRaceWait(t, tr.carrierStopped)
			unblock.Do(func() { close(resume) })
			if err := terminalRaceWait(t, result); err != ErrProtocol {
				t.Errorf("record failure = %v", err)
			}
			if err := tr.TerminalError(); err != securechannel.ErrRecord {
				t.Errorf("generic loss masked detected decrypt failure: %v", err)
			}
		})
	}
}

func TestClosedCipherWithoutLocalStopIsProtocolFailure(t *testing.T) {
	for _, path := range []string{"recv", "send", "cipher-result"} {
		t.Run(path, func(t *testing.T) {
			tr, sender, m := receiver(t, Options{})
			record, err := sender.Encrypt(nil, envelope([]byte("buffered")))
			if err != nil {
				t.Fatal(err)
			}
			tr.channel.Close()
			switch path {
			case "recv":
				m.in <- record
				_, err = tr.Recv(context.Background())
			case "send":
				err = tr.Send(context.Background(), []byte("outbound"))
			case "cipher-result":
				_, err = tr.channel.Decrypt(nil, record)
				err = tr.cipherFailure(err)
			}
			// An idle observer can retire the unexpected cipher closure before
			// Send/Recv enters; subsequent admission is then ordinarily closed.
			if err != ErrProtocol && !(path != "cipher-result" && err == ErrClosed) {
				t.Errorf("unexpected closed cipher = %v, want ErrProtocol", err)
			}
			terminalRaceWait(t, tr.Stopped())
			if err := tr.TerminalError(); err != ErrProtocol {
				t.Errorf("unexpected closed cipher terminal = %v", err)
			}
		})
	}
}

func TestTerminalSecurityFailureUpgradesLossAndStaysFirst(t *testing.T) {
	for _, loss := range []error{ErrClosed, ErrIO, context.Canceled, context.DeadlineExceeded} {
		for _, security := range []error{securechannel.ErrAuth, securechannel.ErrRecord, ErrProtocol,
			syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "private diagnostic")} {
			t.Run(fmt.Sprint(loss, "/", security), func(t *testing.T) {
				tr, _, _ := receiver(t, Options{})
				tr.abort(loss)
				tr.Stop()
				tr.abort(security)
				first := tr.TerminalError()
				var want, got *syntra.RpcError
				if errors.As(security, &want) {
					if !errors.As(first, &got) || got.Code != want.Code || strings.Contains(first.Error(), "private") {
						t.Fatalf("typed code lost: %v", first)
					}
				} else if first != security {
					t.Fatalf("loss masked security failure: %v", first)
				}
				for _, later := range []error{nil, loss, ErrProtocol, securechannel.ErrAuth} {
					tr.abort(later)
					if tr.TerminalError() != first {
						t.Fatal("first security failure replaced")
					}
				}
			})
		}
	}
}

func TestCleanupCipherRetirementDoesNotInventProtocolFailure(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint("local=", local), func(t *testing.T) {
			tr, _, _ := receiver(t, Options{})
			var want error
			if local {
				tr.Stop()
			} else {
				want = ErrIO
				tr.abort(want)
			}
			terminalRaceWait(t, tr.Stopped())
			if err := tr.checkTime(); err != ErrClosed {
				t.Errorf("joined cleanup = %v", err)
			}
			tr.ChannelIdentity()
			tr.VerifiedIdentity()
			if err := tr.TerminalError(); err != want {
				t.Errorf("cleanup invented a failure: %v, want %v", err, want)
			}
		})
	}
}

func TestLocalStopClassificationNeverSuppressesSecurity(t *testing.T) {
	tr, _, _ := receiver(t, Options{})
	tr.Suspend()
	for _, security := range []error{securechannel.ErrAuth, securechannel.ErrRecord, ErrProtocol,
		syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "private diagnostic")} {
		for _, interruption := range []error{context.Canceled, context.DeadlineExceeded, ErrClosed, ErrIO} {
			if tr.LocalStopError(errors.Join(interruption, security)) {
				t.Errorf("local stop suppressed %v joined with %v", security, interruption)
			}
		}
	}
}
