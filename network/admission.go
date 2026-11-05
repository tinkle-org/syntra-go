package network

import (
	"context"
	"sync"
)

type admissionWaiter struct {
	ready   chan struct{}
	granted bool
}

// Admission is FIFO across listeners. Idle endpoints reserve no shared slots.
// A permit covers establishment, live use, callbacks and complete teardown.
type Admission struct {
	mu            sync.Mutex
	maximum, used int
	waiters       []*admissionWaiter
	closed        bool
}

func NewAdmission(maximum int) (*Admission, error) {
	if maximum < 1 || maximum > 4096 {
		return nil, ErrConfig
	}
	return &Admission{maximum: maximum}, nil
}
func (a *Admission) InUse() int     { a.mu.Lock(); defer a.mu.Unlock(); return a.used }
func (a *Admission) Available() int { a.mu.Lock(); defer a.mu.Unlock(); return a.maximum - a.used }
func (a *Admission) acquire(ctx context.Context) (func(), error) {
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if a.closed {
		a.mu.Unlock()
		return nil, ErrClosed
	}
	if a.used < a.maximum && len(a.waiters) == 0 {
		a.used++
		a.mu.Unlock()
		return a.releaser(), nil
	}
	w := &admissionWaiter{ready: make(chan struct{})}
	a.waiters = append(a.waiters, w)
	a.mu.Unlock()
	select {
	case <-w.ready:
		a.mu.Lock()
		granted := w.granted
		a.mu.Unlock()
		if !granted {
			return nil, ErrClosed
		}
		return a.releaser(), nil
	case <-ctx.Done():
		a.mu.Lock()
		if w.granted {
			a.mu.Unlock()
			a.release()
		} else {
			for i, v := range a.waiters {
				if v == w {
					copy(a.waiters[i:], a.waiters[i+1:])
					a.waiters[len(a.waiters)-1] = nil
					a.waiters = a.waiters[:len(a.waiters)-1]
					break
				}
			}
			a.mu.Unlock()
		}
		return nil, ctx.Err()
	}
}

// close stops new admission and wakes queued owners. Existing permits remain
// charged until their owners finish cleanup and release them.
func (a *Admission) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	for _, w := range a.waiters {
		close(w.ready)
	}
	a.waiters = nil
}
func (a *Admission) releaser() func() { var once sync.Once; return func() { once.Do(a.release) } }
func (a *Admission) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.waiters) > 0 {
		w := a.waiters[0]
		a.waiters[0] = nil
		a.waiters = a.waiters[1:]
		w.granted = true
		close(w.ready)
	} else {
		a.used--
	}
}
