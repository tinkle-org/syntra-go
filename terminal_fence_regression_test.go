// File terminal_fence_regression_test.go races the terminal queue fence with
// the writer's competing receive and checks retained frame accounting.
package syntra

import (
	"testing"
	"time"
)

// TestTerminalFenceCompetingReceiveDoesNotBlock covers a writer that removes
// the last queued frame before acquiring mu, as hostWriter.run does. The fence
// must not wait for another frame while holding the accounting mutex. Each round
// owns its watchdog and joins both workers, including on the timeout path.
func TestTerminalFenceCompetingReceiveDoesNotBlock(t *testing.T) {
	for round := 0; round < 10000; round++ {
		w := &hostWriter{frames: make(chan []byte, 1), count: 1, bytes: 1, accepting: true, idle: make(chan struct{})}
		w.frames <- []byte{1}
		start, done := make(chan struct{}), make(chan struct{}, 2)
		go func() {
			<-start
			w.fence()
			done <- struct{}{}
		}()
		go func() {
			<-start
			select {
			case frame := <-w.frames:
				w.mu.Lock()
				w.count--
				w.bytes -= len(frame)
				if w.count == 0 {
					close(w.idle)
				}
				w.mu.Unlock()
			default:
			}
			done <- struct{}{}
		}()
		// Bound this round alone; completed rounds cannot consume its deadline.
		watchdog := time.NewTimer(5 * time.Second)
		close(start)
		for joined := 0; joined < 2; joined++ {
			select {
			case <-done:
			case <-watchdog.C:
				watchdog.Stop()
				// Rescue the old blocking fence without blocking if the queue is full.
				select {
				case w.frames <- []byte{1}:
				default:
				}
				for ; joined < 2; joined++ {
					<-done
				}
				t.Fatalf("fence blocked on an empty queue at round %d", round)
			}
		}
		watchdog.Stop()
		if w.count != 0 || w.bytes != 0 || w.accepting || !w.fenced {
			t.Fatal("fence lost queue accounting or admission state")
		}
		select {
		case <-w.idle:
		default:
			t.Fatal("fence lost idle completion")
		}
	}
}
