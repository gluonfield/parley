// Package session is parley's reference client engine. A Session is one end of
// one channel; it drives the handshake, seals and opens messages, and runs the
// non-blocking model the spec describes — Send posts and returns, Poll collects
// what has arrived — over any [parley.Relay]. It implements [parley.Session].
//
// A Session expects one call in flight at a time (the natural shape for an MCP
// host, which dispatches tools sequentially). Send and Poll from separate
// goroutines on the same Session are not supported; two different Sessions are
// fully independent.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gluonfield/parley"
	"github.com/gluonfield/parley/noise"
)

// A Session is one agent's end of one channel. Whether this node opened or
// joined is captured entirely by which constructor ran (responder vs initiator,
// recorded in hs) and whether a topic was set — there is no separate role flag.
type Session struct {
	self  noise.Keypair
	relay parley.Relay
	host  string
	caps  parley.Capabilities

	mu      sync.Mutex
	channel parley.ChannelID
	member  parley.Membership
	topic   string
	hs      *noise.Handshake
	tx      parley.Transport
	sendSeq uint64
	recvSeq uint64
	pending []string // sends queued before the channel went live
	peer    parley.Peer
}

var _ parley.Session = (*Session)(nil)

// New returns a session that speaks through relay and mints invites pointing at
// host, the relay's public name (e.g. "parley.chat").
func New(self noise.Keypair, relay parley.Relay, host string) *Session {
	return &Session{self: self, relay: relay, host: host, sendSeq: 1}
}

func (s *Session) Open(ctx context.Context, topic string) (parley.Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, err := parley.NewChannelID()
	if err != nil {
		return parley.Invite{}, err
	}
	secret, err := parley.NewSecret()
	if err != nil {
		return parley.Invite{}, err
	}
	member, err := s.relay.Open(ctx, ch, secret.JoinToken())
	if err != nil {
		return parley.Invite{}, fmt.Errorf("parley/session: open: %w", err)
	}
	hs, err := noise.NewResponder(s.self, secret.PSK(), prologue(ch))
	if err != nil {
		return parley.Invite{}, err
	}

	s.channel = ch
	s.member = member
	s.topic = topic
	s.hs = hs
	s.peer = parley.Peer{Topic: topic, State: parley.Pending}
	return parley.Invite{Relay: s.host, Channel: ch, Key: s.self.Public, Secret: secret}, nil
}

func (s *Session) Join(ctx context.Context, in parley.Invite) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	member, err := s.relay.Join(ctx, in.Channel, in.Secret.JoinToken())
	if err != nil {
		return fmt.Errorf("parley/session: join: %w", err)
	}
	hs, err := noise.NewInitiator(s.self, in.Key, in.Secret.PSK(), prologue(in.Channel))
	if err != nil {
		return err
	}
	id := parley.Identity{Key: in.Key}

	s.channel = in.Channel
	s.member = member
	s.hs = hs
	s.peer = parley.Peer{ID: id.ID(), Fingerprint: id.Fingerprint(), State: parley.Pending, Present: true}

	// Send the first handshake message now; the opener completes it on its first Poll.
	msg, err := s.hs.Write(s.payload())
	if err != nil {
		return err
	}
	return s.sendFrame(ctx, parley.Handshake, msg)
}

func (s *Session) Send(ctx context.Context, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peer.State == parley.Closed {
		return fmt.Errorf("parley/session: channel closed")
	}
	if s.tx == nil {
		s.pending = append(s.pending, text) // flushed once the handshake completes
		return nil
	}
	return s.sendMessage(ctx, parley.Message{Kind: parley.Say, Text: text})
}

func (s *Session) Poll(ctx context.Context, wait time.Duration) ([]parley.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drive(ctx, wait)
}

func (s *Session) Close(ctx context.Context, outcome string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peer.State == parley.Closed {
		return nil
	}
	if s.tx != nil {
		if err := s.sendMessage(ctx, parley.Message{Kind: parley.Close, Text: outcome}); err != nil {
			return err
		}
	}
	s.peer.State = parley.Closed
	return nil
}

func (s *Session) Peer() parley.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

// drive advances the channel: it refreshes presence, completes the handshake,
// flushes queued sends, and returns any messages, waiting up to wait for the
// first. Handshake frames are processed transparently; only data surfaces.
func (s *Session) drive(ctx context.Context, wait time.Duration) ([]parley.Message, error) {
	s.refreshPresence(ctx)
	deadline := time.Now().Add(wait)
	var out []parley.Message
	for {
		w := time.Until(deadline)
		if w < 0 {
			w = 0
		}
		frames, err := s.relay.Recv(ctx, s.member, s.recvSeq, w)
		if err != nil {
			return out, err
		}
		accepted := 0
		for _, f := range frames {
			if f.Seq <= s.recvSeq {
				continue // ignore replays and rewinds; the relay is untrusted
			}
			s.recvSeq = f.Seq
			accepted++
			if s.tx == nil {
				if err := s.advanceHandshake(ctx, f); err != nil {
					return out, err
				}
				continue
			}
			m, err := s.openMessage(f)
			if err != nil {
				return out, err
			}
			out = append(out, m)
			if m.Kind == parley.Close {
				s.peer.State = parley.Closed
			}
		}
		if s.tx != nil {
			if err := s.flush(ctx); err != nil {
				return out, err
			}
		}
		if len(out) > 0 || accepted == 0 {
			return out, nil // got data, or nothing new (empty, or only replays)
		}
		// accepted only handshake so far; keep waiting for data within the window
	}
}

func (s *Session) advanceHandshake(ctx context.Context, f parley.Frame) error {
	if f.Type != parley.Handshake {
		return fmt.Errorf("parley/session: expected handshake, got %d frame", f.Type)
	}
	got, err := s.hs.Read(f.Payload)
	if err != nil {
		return fmt.Errorf("parley/session: handshake: %w", err)
	}
	s.learn(got)
	if !s.hs.Done() { // a responder still owes the next handshake message
		msg, err := s.hs.Write(s.payload())
		if err != nil {
			return fmt.Errorf("parley/session: handshake: %w", err)
		}
		if err := s.sendFrame(ctx, parley.Handshake, msg); err != nil {
			return err
		}
	}
	if s.hs.Done() {
		tx, err := s.hs.Transport()
		if err != nil {
			return err
		}
		s.tx = tx
		s.peer.State = parley.Active
		s.peer.Present = true
		id := parley.Identity{Key: s.hs.PeerStatic()}
		s.peer.ID, s.peer.Fingerprint = id.ID(), id.Fingerprint()
	}
	return nil
}

func (s *Session) flush(ctx context.Context) error {
	for len(s.pending) > 0 {
		if err := s.sendMessage(ctx, parley.Message{Kind: parley.Say, Text: s.pending[0]}); err != nil {
			return err
		}
		s.pending = s.pending[1:]
	}
	return nil
}

func (s *Session) sendMessage(ctx context.Context, m parley.Message) error {
	b, err := m.MarshalBinary()
	if err != nil {
		return err
	}
	ct, err := s.tx.Seal(s.sendSeq, b)
	if err != nil {
		return fmt.Errorf("parley/session: seal: %w", err)
	}
	return s.sendFrame(ctx, parley.Data, ct)
}

func (s *Session) sendFrame(ctx context.Context, typ parley.FrameType, payload []byte) error {
	f := parley.Frame{Channel: s.channel, Seq: s.sendSeq, Type: typ, Payload: payload}
	if err := s.relay.Send(ctx, s.member, f); err != nil {
		return fmt.Errorf("parley/session: send: %w", err)
	}
	s.sendSeq++
	return nil
}

func (s *Session) openMessage(f parley.Frame) (parley.Message, error) {
	if f.Type != parley.Data {
		return parley.Message{}, fmt.Errorf("parley/session: expected data, got %d frame", f.Type)
	}
	pt, err := s.tx.Open(f.Seq, f.Payload)
	if err != nil {
		return parley.Message{}, fmt.Errorf("parley/session: open: %w", err)
	}
	var m parley.Message
	if err := m.UnmarshalBinary(pt); err != nil {
		return parley.Message{}, err
	}
	m.From = s.peer.ID // attribution from authenticated context, not the wire
	return m, nil
}

func (s *Session) refreshPresence(ctx context.Context) {
	if s.peer.State == parley.Active || s.peer.State == parley.Closed {
		s.peer.Present = true
		return
	}
	if n, err := s.relay.Members(ctx, s.member); err == nil {
		s.peer.Present = n >= 2
	}
}

// payload is this side's handshake payload. The opener has set a topic; the
// joiner has not, so its (empty) topic is omitted and it learns the opener's.
func (s *Session) payload() []byte {
	b, _ := json.Marshal(parley.HandshakePayload{Topic: s.topic, Capabilities: s.caps})
	return b
}

func (s *Session) learn(b []byte) {
	var p parley.HandshakePayload
	if json.Unmarshal(b, &p) == nil && p.Topic != "" {
		s.topic, s.peer.Topic = p.Topic, p.Topic
	}
}

// prologue binds the protocol version and channel into the handshake transcript,
// so a handshake cannot be replayed onto another channel or version.
func prologue(ch parley.ChannelID) []byte {
	p := strconv.AppendInt([]byte("parley/"), parley.Version, 10)
	return append(p, ch[:]...)
}
