package relayhttp

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/gluonfield/parley"
)

var (
	errExists    = errors.New("channel already exists")
	errNoChannel = errors.New("no such channel")
	errFull      = errors.New("channel is full")
	errBadToken  = errors.New("unrecognized token")
	errNoPeer    = errors.New("peer has not joined")
)

// Store is the relay's state — channels, their two seats, and the frames queued
// for each seat — behind one swappable seam. The in-memory store ships here and
// keeps nothing across a restart; a Redis- or SQL-backed store implements the
// same contract to make retention durable, so a sealed frame survives until an
// offline peer next polls. Implementations must be safe for concurrent use and
// must return the package sentinel errors so the HTTP layer can map them to
// status codes. Token minting stays in the [Server], so a store is deterministic
// and holds only the values handed to it.
type Store interface {
	// Open creates ch with the opener seated under openerToken and the JoinToken
	// a future joiner must present. Returns errExists if ch is already live.
	Open(ctx context.Context, ch parley.ChannelID, expect parley.JoinToken, openerToken string) error

	// Join seats a second member under joinerToken when present matches the
	// expected JoinToken in constant time. Returns errNoChannel, errFull, or
	// errBadToken.
	Join(ctx context.Context, ch parley.ChannelID, present parley.JoinToken, joinerToken string) error

	// Append queues f for the peer of the seat holding fromToken. Returns
	// errNoChannel, errBadToken, or errNoPeer.
	Append(ctx context.Context, ch parley.ChannelID, fromToken string, f parley.Frame) error

	// Frames returns the frames queued for the seat holding token with Seq >
	// after, in order. Returns errNoChannel or errBadToken.
	Frames(ctx context.Context, ch parley.ChannelID, token string, after uint64) ([]parley.Frame, error)

	// Members reports how many of ch's two seats are occupied. Returns
	// errNoChannel or errBadToken.
	Members(ctx context.Context, ch parley.ChannelID, token string) (int, error)

	// Purge drops channels idle since before cutoff, bounding retention. A
	// durable store backed by native TTLs may treat this as advisory and no-op.
	Purge(ctx context.Context, cutoff time.Time) error
}

// memStore is the default in-memory Store: one mutex over a map, nothing kept
// across a restart. It suits a single-process relay and tests; swap in a durable
// Store to retain frames for an offline peer across restarts.
type memStore struct {
	mu       sync.Mutex
	channels map[parley.ChannelID]*memChannel
}

type memChannel struct {
	expect parley.JoinToken
	seats  [2]*memSeat
	seen   time.Time
}

type memSeat struct {
	token string
	inbox []parley.Frame
}

func newMemStore() *memStore {
	return &memStore{channels: make(map[parley.ChannelID]*memChannel)}
}

func (m *memStore) Open(_ context.Context, ch parley.ChannelID, expect parley.JoinToken, openerToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channels[ch]; ok {
		return errExists
	}
	m.channels[ch] = &memChannel{
		expect: expect,
		seats:  [2]*memSeat{{token: openerToken}},
		seen:   time.Now(),
	}
	return nil
}

func (m *memStore) Join(_ context.Context, ch parley.ChannelID, present parley.JoinToken, joinerToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.channels[ch]
	switch {
	case c == nil:
		return errNoChannel
	case c.seats[1] != nil:
		return errFull
	case subtle.ConstantTimeCompare([]byte(present), []byte(c.expect)) != 1:
		return errBadToken
	}
	c.seats[1] = &memSeat{token: joinerToken}
	c.seen = time.Now()
	return nil
}

func (m *memStore) Append(_ context.Context, ch parley.ChannelID, fromToken string, f parley.Frame) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.channels[ch]
	if c == nil {
		return errNoChannel
	}
	i := seatOf(c, fromToken)
	if i < 0 {
		return errBadToken
	}
	peer := c.seats[1-i]
	if peer == nil {
		return errNoPeer
	}
	peer.inbox = append(peer.inbox, f)
	c.seen = time.Now()
	return nil
}

func (m *memStore) Frames(_ context.Context, ch parley.ChannelID, token string, after uint64) ([]parley.Frame, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.channels[ch]
	if c == nil {
		return nil, errNoChannel
	}
	i := seatOf(c, token)
	if i < 0 {
		return nil, errBadToken
	}
	c.seen = time.Now()
	var out []parley.Frame
	for _, f := range c.seats[i].inbox {
		if f.Seq > after {
			out = append(out, f)
		}
	}
	return out, nil
}

func (m *memStore) Members(_ context.Context, ch parley.ChannelID, token string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.channels[ch]
	if c == nil {
		return 0, errNoChannel
	}
	if seatOf(c, token) < 0 {
		return 0, errBadToken
	}
	c.seen = time.Now()
	n := 0
	for _, st := range c.seats {
		if st != nil {
			n++
		}
	}
	return n, nil
}

func (m *memStore) Purge(_ context.Context, cutoff time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.channels {
		if c.seen.Before(cutoff) {
			delete(m.channels, id)
		}
	}
	return nil
}

func seatOf(c *memChannel, token string) int {
	for i, st := range c.seats {
		if st != nil && subtle.ConstantTimeCompare([]byte(st.token), []byte(token)) == 1 {
			return i
		}
	}
	return -1
}
