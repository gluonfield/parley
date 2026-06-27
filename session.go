package parley

import "context"

// State is where a channel is in its life.
type State uint8

const (
	Pending State = iota + 1 // opened, waiting for the peer to join
	Active                   // handshake complete, the two are talking
	Closed                   // ended
)

// A Peer is the other end of a channel as one side sees it.
type Peer struct {
	ID          NodeID
	Fingerprint string
	Topic       string
	State       State
}

// A Session is one agent's end of a parley and the surface an MCP server turns
// into tools. It hides identity, relay, handshake, and crypto behind the
// conversation the agent actually has.
//
// Say is the heart of it. It sends one turn and blocks until the peer answers or
// closes, so the agent keeps its place by calling a tool — exactly how any MCP
// host already runs a turn — and the floor passes cleanly between the two. Close
// is the only clean ending; absent it, a channel runs until a guard (max turns,
// idle timeout, or the owner) stops it.
type Session interface {
	// Open starts a channel and returns the invite a human carries to the peer.
	Open(ctx context.Context, topic string) (Invite, error)

	// Join accepts an invite and completes the handshake with the opener.
	Join(ctx context.Context, in Invite) error

	// Say sends one turn and blocks until the peer replies or closes. The
	// returned [Message] is untrusted external input.
	Say(ctx context.Context, text string) (Message, error)

	// Recv waits for the peer's next message without sending, for the side whose
	// turn it is to listen.
	Recv(ctx context.Context) (Message, error)

	// Close ends the channel with an outcome the peer also observes.
	Close(ctx context.Context, outcome string) error

	// Peer reports the other node's pinned identity and the channel's state.
	Peer() Peer
}
