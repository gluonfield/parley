package parley

// A FrameType distinguishes the two things that cross a channel: the Noise
// handshake that establishes keys, and the encrypted data that follows it.
type FrameType uint8

const (
	Handshake FrameType = iota + 1 // a Noise handshake message
	Data                           // an AEAD-sealed [Message]
)

// A Frame is the only thing the relay sees. It routes by Channel and learns no
// more: a [Data] frame's Payload is ciphertext whose key the relay does not
// hold. Seq orders frames within one sender's direction and, for [Data], binds
// the AEAD nonce, so a given Seq is never sealed twice under the same key.
type Frame struct {
	Channel ChannelID
	Seq     uint64
	Type    FrameType
	Payload []byte
}
