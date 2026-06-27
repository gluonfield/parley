// Package session is parley's reference client engine. A Session is one end of
// one channel; it drives the handshake, seals and opens messages, and runs the
// turn loop the spec describes — Say sends and waits, Close ends — over any
// [parley.Relay]. It implements [parley.Session].
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/gluonfield/parley"
	"github.com/gluonfield/parley/noise"
)

type role int

const (
	opener role = iota // Noise responder; waits for the joiner's first message
	joiner             // Noise initiator; sends the first message
)

// A Session is one agent's end of one channel.
type Session struct {
	self  noise.Keypair
	relay parley.Relay
	host  string
	caps  parley.Capabilities

	mu       sync.Mutex
	role     role
	channel  parley.ChannelID
	member   parley.Membership
	psk      []byte
	prologue []byte
	topic    string

	hs      *noise.Handshake
	tx      parley.Transport
	sendSeq uint64
	recvSeq uint64
	inbuf   []parley.Frame
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

	s.role = opener
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

	s.role = joiner
	s.channel = in.Channel
	s.member = member
	s.hs = hs
	s.peer = parley.Peer{ID: id.ID(), Fingerprint: id.Fingerprint(), State: parley.Pending}

	// Send the first handshake message now, so the opener can advance the moment
	// it next listens.
	msg, err := s.hs.Write(s.payload())
	if err != nil {
		return err
	}
	return s.sendFrame(ctx, parley.Handshake, msg)
}

func (s *Session) Say(ctx context.Context, text string) (parley.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActive(ctx); err != nil {
		return parley.Message{}, err
	}
	if err := s.sendMessage(ctx, parley.Message{Kind: parley.Say, Text: text}); err != nil {
		return parley.Message{}, err
	}
	return s.receive(ctx)
}

func (s *Session) Recv(ctx context.Context) (parley.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActive(ctx); err != nil {
		return parley.Message{}, err
	}
	return s.receive(ctx)
}

func (s *Session) Close(ctx context.Context, outcome string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActive(ctx); err != nil {
		return err
	}
	if err := s.sendMessage(ctx, parley.Message{Kind: parley.Close, Text: outcome}); err != nil {
		return err
	}
	s.peer.State = parley.Closed
	return nil
}

func (s *Session) Peer() parley.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

// ensureActive completes the handshake on first use. The joiner has already sent
// its message in Join and only needs the opener's reply; the opener reads the
// joiner's message and sends its own.
func (s *Session) ensureActive(ctx context.Context) error {
	if s.tx != nil {
		return nil
	}
	switch s.role {
	case joiner:
		f, err := s.recvFrame(ctx)
		if err != nil {
			return err
		}
		got, err := s.hs.Read(f.Payload)
		if err != nil {
			return fmt.Errorf("parley/session: handshake: %w", err)
		}
		s.learn(got)
	case opener:
		f, err := s.recvFrame(ctx)
		if err != nil {
			return err
		}
		got, err := s.hs.Read(f.Payload)
		if err != nil {
			return fmt.Errorf("parley/session: handshake: %w", err)
		}
		s.learn(got)
		msg, err := s.hs.Write(s.payload())
		if err != nil {
			return err
		}
		if err := s.sendFrame(ctx, parley.Handshake, msg); err != nil {
			return err
		}
		id := parley.Identity{Key: s.hs.PeerStatic()}
		s.peer.ID, s.peer.Fingerprint = id.ID(), id.Fingerprint()
	}
	tx, err := s.hs.Transport()
	if err != nil {
		return err
	}
	s.tx = tx
	s.peer.State = parley.Active
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

func (s *Session) receive(ctx context.Context) (parley.Message, error) {
	f, err := s.recvFrame(ctx)
	if err != nil {
		return parley.Message{}, err
	}
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
	if m.Kind == parley.Close {
		s.peer.State = parley.Closed
	}
	return m, nil
}

func (s *Session) sendFrame(ctx context.Context, typ parley.FrameType, payload []byte) error {
	f := parley.Frame{Channel: s.channel, Seq: s.sendSeq, Type: typ, Payload: payload}
	if err := s.relay.Send(ctx, s.member, f); err != nil {
		return fmt.Errorf("parley/session: send: %w", err)
	}
	s.sendSeq++
	return nil
}

func (s *Session) recvFrame(ctx context.Context) (parley.Frame, error) {
	for len(s.inbuf) == 0 {
		frames, err := s.relay.Recv(ctx, s.member, s.recvSeq)
		if err != nil {
			return parley.Frame{}, fmt.Errorf("parley/session: recv: %w", err)
		}
		s.inbuf = append(s.inbuf, frames...)
		if n := len(frames); n > 0 {
			s.recvSeq = frames[n-1].Seq
		}
	}
	f := s.inbuf[0]
	s.inbuf = s.inbuf[1:]
	return f, nil
}

// payload is this side's handshake payload: its capabilities, plus the topic if
// it is the opener (the joiner learns the topic from the opener's reply).
func (s *Session) payload() []byte {
	p := parley.HandshakePayload{Capabilities: s.caps}
	if s.role == opener {
		p.Topic = s.topic
	}
	b, _ := json.Marshal(p)
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
