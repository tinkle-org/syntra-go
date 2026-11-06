// File terminal_receipt.go coordinates the optional terminal-only ordered path.
package ordered

import (
	"context"
	"encoding/binary"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// TerminalReceiptDriver returns this exact owner only with explicit per-driver
// AND per-carrier opt-in. Merely implementing MessageIO does not confer support.
func (t *Transport) TerminalReceiptDriver() syntra.TerminalReceiptDriver {
	carrier, ok := t.io.(interface{ SupportsTerminalReceipt() bool })
	if !t.opts.EnableTerminalReceipts || !ok || !carrier.SupportsTerminalReceipt() {
		return nil
	}
	return t
}

// TerminalClock preserves the channel's original trusted elapsed origin.
func (t *Transport) TerminalClock() syntra.TerminalClock { return t.channel.Clock() }

// TerminalBinding supplies the confirmed exact channel, including key selector
// and handshake binding. The diagnostic session connection ID is not involved.
func (t *Transport) TerminalBinding() (syntra.TerminalChannelBinding, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.identitySet || !t.peerAuthorized || !t.responder {
		return syntra.TerminalChannelBinding{}, false
	}
	return syntra.TerminalChannelBinding{Identity: channelIdentity(t.peer), ServerKeyID: t.peer.Context.ServerKeyID, HandshakeHash: t.peer.HandshakeHash}, true
}

// StopTerminal fences and interrupts immediately, without self-joining I/O.
func (t *Transport) StopTerminal() { t.abort(ErrClosed) }

// BeginTerminal installs the classifier at a complete outbound frame boundary.
// Acquiring sendGate waits for an already active ordinary frame; the runtime has
// already suppressed its unstarted queues. peerGate joins any old generic check
// before the operation is permitted to mutate authority.
func (t *Transport) BeginTerminal(ctx context.Context, p *syntra.TerminalPermit) (err error) {
	if t.TerminalReceiptDriver() == nil || p.CheckTime() != nil {
		return ErrOptions
	}
	until := t.operationDeadline(t.opts.WriteTimeout)
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	select {
	case t.peerGate <- struct{}{}:
		defer func() { <-t.peerGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return ErrClosed
	}
	t.mu.Lock()
	id, peer, valid := t.identity, t.peer, t.identitySet && t.peerAuthorized && t.terminalPermit == nil && !t.closed && t.responder
	t.mu.Unlock()
	if !valid || peer.Context.Mode != securechannel.Returning || !p.MatchesChannel(syntra.TerminalChannelBinding{Identity: channelIdentity(peer), ServerKeyID: peer.Context.ServerKeyID, HandshakeHash: peer.HandshakeHash}) || t.checkOperation(ctx, until) != nil {
		return securechannel.ErrAuth
	}
	// Retain the retirement owner BEFORE either callback. peerGate still joins
	// all prior checks, and remains held until the mandatory normal identity and
	// typed Active validations finish. Failure can now retire crypto even when
	// one of those callbacks ignores cancellation; it never grants ordinary I/O.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.terminalPermit = p
	t.terminalWake <- struct{}{}
	t.mu.Unlock()
	if err := t.server.CheckIdentity(ctx, id); err != nil {
		return securechannel.ErrAuth
	}
	state, err := p.Observe(ctx, false)
	if err != nil || state != syntra.TerminalActive {
		return securechannel.ErrAuth
	}
	if err := t.checkOperation(ctx, until); err != nil {
		return err
	}
	return nil
}

func channelIdentity(p securechannel.Peer) syntra.ChannelIdentity {
	c := p.Context
	return syntra.ChannelIdentity{Mode: c.Mode.String(), Carrier: c.Carrier.String(), Scope: c.Scope, Handle: c.Handle, Epoch: c.Epoch, Principal: p.Principal}
}

// ValidateTerminal uses the same serialized fresh classifier as every other
// operation. A different connection/permit cannot use this driver's state.
func (t *Transport) ValidateTerminal(ctx context.Context, p *syntra.TerminalPermit, committed bool) error {
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	t.mu.Lock()
	exact := p != nil && t.terminalPermit == p
	t.mu.Unlock()
	if !exact {
		return securechannel.ErrAuth
	}
	return t.checkPeerMode(ctx, t.operationDeadline(time.Second), false, committed, nil)
}

// SendTerminal writes the predeclared frame once using the sole nonce/writer
// owner. The <=1024-byte envelope fits one record. TCP may fragment that record;
// its carrier must finish the exact ciphertext or abort, never re-encrypt/replay.
func (t *Transport) SendTerminal(ctx context.Context, p *syntra.TerminalPermit) error {
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	t.mu.Lock()
	exact := p != nil && t.terminalPermit == p
	t.mu.Unlock()
	if !exact {
		return securechannel.ErrAuth
	}
	frame := p.Frame()
	if len(frame) == 0 || len(frame) > 1024 {
		t.abort(ErrProtocol)
		return ErrProtocol
	}
	until := t.operationDeadline(t.opts.WriteTimeout)
	if err := t.checkPeerMode(ctx, until, false, true, nil); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(t.sendPlain[:4], uint32(len(frame)))
	copy(t.sendPlain[4:], frame)
	record, err := t.channel.Encrypt(t.sendCipher[:0], t.sendPlain[:4+len(frame)])
	clear(t.sendPlain[:4+len(frame)])
	if err != nil {
		return t.cipherFailure(err)
	}
	// Final fresh observation happens after nonce consumption, before carrier
	// handoff. Failure now retires the stream; that nonce is never skipped.
	if err := t.checkPeerMode(ctx, until, false, true, p.Handoff); err != nil {
		return err
	}
	if err := t.checkOperation(ctx, until); err != nil {
		t.abort(err)
		return err
	}
	if err := t.io.WriteMessage(ctx, record); err != nil {
		err = publicError(ctx, err)
		t.abort(err)
		return err
	}
	if err := t.checkOperation(ctx, until); err != nil {
		t.abort(err)
		return err
	}
	return nil
}
