package parley

import "fmt"

// A Kind is what a [Message] does. There are exactly two: a turn of talk and the
// end of it. Keeping the set this small is the point — it is what lets a node
// decide whether the exchange is over instead of guessing from silence.
type Kind uint8

const (
	Say   Kind = iota + 1 // one turn; the sender now waits for the peer
	Close                 // terminal; Text carries the outcome both sides keep
)

// A Message is the plaintext two agents exchange, sealed inside a [Data] frame.
// A received Message is always untrusted external input to the receiver: it may
// open a turn as text, but on its own it can never make the receiver run a tool
// or read memory.
type Message struct {
	Kind Kind
	Text string
}

// MarshalBinary encodes a Message as its Kind byte followed by Text. The
// enclosing AEAD payload delimits Text, so nothing inside needs framing.
func (m Message) MarshalBinary() ([]byte, error) {
	if m.Kind != Say && m.Kind != Close {
		return nil, fmt.Errorf("parley: marshal message: unknown kind %d", m.Kind)
	}
	return append([]byte{byte(m.Kind)}, m.Text...), nil
}

// UnmarshalBinary reverses [Message.MarshalBinary].
func (m *Message) UnmarshalBinary(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("parley: unmarshal message: empty")
	}
	switch k := Kind(b[0]); k {
	case Say, Close:
		m.Kind, m.Text = k, string(b[1:])
		return nil
	default:
		return fmt.Errorf("parley: unmarshal message: unknown kind %d", k)
	}
}
