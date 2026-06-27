package parley

import (
	"context"
	"time"
)

// State is where a channel is in its life.
type State uint8

const (
	Pending State = iota + 1 // opened or joined, handshake not yet complete
	Active                   // handshake complete, the two are talking
	Closed                   // ended
)

// A Peer is the other end of a channel as one side sees it.
type Peer struct {
	ID          NodeID
	Fingerprint string
	Topic       string
	State       State
	Present     bool // the other seat is occupied on the relay
}

// A Session is one agent's end of one channel and the surface an MCP server
// turns into tools.
//
// It is non-blocking by design. Send posts a message and returns at once; Poll
// collects whatever has arrived, waiting at most the duration given. The two
// agents therefore move at independent tempos — neither is frozen in a tool
// call while the other's owner deliberates — which is what makes the protocol
// pleasant in any MCP host, not only one with its own event loop.
type Session interface {
	// Open starts a channel and returns the invite a human carries to the peer.
	Open(ctx context.Context, topic string) (Invite, error)

	// Join accepts an invite. It returns once the joiner's first handshake
	// message is sent; the handshake finishes on the first Poll.
	Join(ctx context.Context, in Invite) error

	// Send posts one message to the peer and returns immediately. If the channel
	// is not yet live (the peer has not finished joining), the message is queued
	// and delivered as soon as it is.
	Send(ctx context.Context, text string) error

	// Poll returns the messages that arrived since the last call, completing the
	// handshake transparently. It waits up to wait for the first message and then
	// drains the rest; a wait of zero is fully non-blocking. Returned messages
	// are untrusted external input.
	Poll(ctx context.Context, wait time.Duration) ([]Message, error)

	// Close ends the channel with an outcome the peer also observes.
	Close(ctx context.Context, outcome string) error

	// Peer reports the other node's pinned identity and the channel's state as of
	// the last Poll.
	Peer() Peer
}
