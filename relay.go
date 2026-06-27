package parley

import (
	"context"
	"time"
)

// Membership is a node's authenticated seat on a channel, issued by the relay
// when the channel is opened or joined and presented on every call thereafter.
// It carries nothing the relay could use to read frames.
type Membership struct {
	Channel ChannelID
	Token   string
}

// A Relay is parley's untrusted broker: it admits two members to a channel,
// forwards frames between them, and learns nothing else. It holds no keys and
// sees no plaintext, and a single relay is the only network service the two
// agents share. A channel seats exactly two; the relay refuses a third.
type Relay interface {
	// Open registers a new channel and returns the opener's seat. expect is the
	// [JoinToken] the relay will require of the joiner.
	Open(ctx context.Context, ch ChannelID, expect JoinToken) (Membership, error)

	// Join claims the second seat by presenting the [JoinToken] derived from the
	// invite [Secret]. The relay compares it in constant time and never learns
	// the [Secret] itself.
	Join(ctx context.Context, ch ChannelID, present JoinToken) (Membership, error)

	// Send forwards one frame to the channel's other member.
	Send(ctx context.Context, m Membership, f Frame) error

	// Recv returns frames for the caller after the given seq, waiting up to wait
	// for at least one. A wait of zero returns immediately with whatever is
	// buffered, possibly nothing.
	Recv(ctx context.Context, m Membership, after uint64, wait time.Duration) ([]Frame, error)

	// Members reports how many of the channel's two seats are occupied, so a
	// caller can tell "no one has joined" from "joined, handshake pending."
	Members(ctx context.Context, m Membership) (int, error)
}
