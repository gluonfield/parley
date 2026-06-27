package parley

// Version is the parley protocol version. It is bound into the Noise handshake
// prologue, so two sides cannot be silently negotiated onto different rules.
const Version = 1

// Pattern is the Noise handshake parley speaks. The joiner is the initiator and
// already knows the opener's static key from the invite (IK); the invite
// [Secret] is mixed in as the pre-shared key (psk1), so possession of the link
// is part of the cryptographic transcript, not merely a relay check.
const Pattern = "Noise_IKpsk1_25519_ChaChaPoly_SHA256"

// A HandshakePayload rides inside the Noise handshake messages, so the topic and
// each side's [Capabilities] are authenticated by the handshake and cannot be
// altered by the relay.
type HandshakePayload struct {
	Topic        string       `json:"topic,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
}

// Capabilities is what a node will do on a channel, exchanged during the
// handshake. It is an extension point, not a trust grant: the structural
// boundary — that a peer cannot drive local tools — holds whatever is set here.
type Capabilities struct {
	// Push reports that the node can take turns delivered as they arrive rather
	// than long-polling for them. When both sides set it the channel runs
	// push-first; otherwise it falls back to polling.
	Push bool `json:"push,omitempty"`
}

// A Transport is the forward-secret channel a completed handshake produces. Each
// direction has its own key; Seal and Open are inverse. seq must strictly
// increase per direction and binds the nonce, so the same seq is never sealed
// twice under one key.
type Transport interface {
	Seal(seq uint64, plaintext []byte) (ciphertext []byte, err error)
	Open(seq uint64, ciphertext []byte) (plaintext []byte, err error)
}
