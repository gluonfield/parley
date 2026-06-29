// Package noise implements parley's handshake and transport with the Noise
// Protocol Framework, via github.com/flynn/noise. It is the reference crypto for
// the pattern the spec names ([parley.Pattern]); none of it is hand-rolled.
//
// The joiner is the Noise initiator and the opener is the responder. Each side
// alternately calls [Handshake.Write] to produce the next message and
// [Handshake.Read] to consume the peer's, until [Handshake.Done]. The resulting
// [parley.Transport] binds each frame's sequence number to the AEAD nonce.
package noise

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/flynn/noise"
	"github.com/gluonfield/parley"
)

// suite is parley's cipher suite: X25519, ChaCha20-Poly1305, SHA-256.
var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// pskPlacement is the IKpsk1 position: the preshared key is mixed after the
// first handshake token.
const pskPlacement = 1

// A Keypair is a node's static X25519 keypair. The public half is the node's
// [parley.PublicKey] identity; the private half never leaves the node.
type Keypair struct {
	Private []byte
	Public  parley.PublicKey
}

// GenerateKeypair mints a fresh static keypair.
func GenerateKeypair() (Keypair, error) {
	dh, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("parley/noise: generate keypair: %w", err)
	}
	kp := Keypair{Private: dh.Private}
	copy(kp.Public[:], dh.Public)
	return kp, nil
}

// DeriveKeypair deterministically derives a static keypair from high-entropy
// secret seed material. It is for hosted node processes that intentionally keep
// no at-rest key store; callers must not feed it usernames or other guessable
// identifiers.
func DeriveKeypair(seed []byte) (Keypair, error) {
	if len(seed) == 0 {
		return Keypair{}, fmt.Errorf("parley/noise: derive keypair: empty seed")
	}
	h := sha256.New()
	h.Write([]byte("parley:identity-key:v1\x00"))
	h.Write(seed)
	sum := h.Sum(nil)
	dh, err := suite.GenerateKeypair(bytes.NewReader(sum))
	if err != nil {
		return Keypair{}, fmt.Errorf("parley/noise: derive keypair: %w", err)
	}
	kp := Keypair{Private: dh.Private}
	copy(kp.Public[:], dh.Public)
	return kp, nil
}

// A Handshake drives one IKpsk1 exchange to a [parley.Transport].
type Handshake struct {
	hs        *noise.HandshakeState
	initiator bool
	send      *noise.CipherState
	recv      *noise.CipherState
}

// NewInitiator starts the joiner's side. It already knows the opener's static
// key (peer) from the invite, and mixes in psk derived from the invite secret.
func NewInitiator(self Keypair, peer parley.PublicKey, psk, prologue []byte) (*Handshake, error) {
	return newHandshake(noise.Config{
		CipherSuite:           suite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskPlacement,
		StaticKeypair:         noise.DHKey{Private: self.Private, Public: self.Public[:]},
		PeerStatic:            peer[:],
	})
}

// NewResponder starts the opener's side. It learns the joiner's static key from
// the first message.
func NewResponder(self Keypair, psk, prologue []byte) (*Handshake, error) {
	return newHandshake(noise.Config{
		CipherSuite:           suite,
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskPlacement,
		StaticKeypair:         noise.DHKey{Private: self.Private, Public: self.Public[:]},
	})
}

func newHandshake(c noise.Config) (*Handshake, error) {
	hs, err := noise.NewHandshakeState(c)
	if err != nil {
		return nil, fmt.Errorf("parley/noise: new handshake: %w", err)
	}
	return &Handshake{hs: hs, initiator: c.Initiator}, nil
}

// Write produces the next handshake message to send to the peer, carrying
// payload. It completes the handshake if the pattern ends on this side.
func (h *Handshake) Write(payload []byte) ([]byte, error) {
	msg, cs0, cs1, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("parley/noise: write handshake: %w", err)
	}
	h.complete(cs0, cs1)
	return msg, nil
}

// Read consumes a handshake message from the peer and returns its payload. It
// completes the handshake if the pattern ends on this side.
func (h *Handshake) Read(msg []byte) ([]byte, error) {
	payload, cs0, cs1, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, fmt.Errorf("parley/noise: read handshake: %w", err)
	}
	h.complete(cs0, cs1)
	return payload, nil
}

// complete records the transport keys when the handshake ends. flynn/noise
// always returns them in pattern order — first initiator→responder, second
// responder→initiator — so the responder takes them swapped.
func (h *Handshake) complete(cs0, cs1 *noise.CipherState) {
	if cs0 == nil || cs1 == nil {
		return
	}
	if h.initiator {
		h.send, h.recv = cs0, cs1
	} else {
		h.send, h.recv = cs1, cs0
	}
}

// Done reports whether the handshake has produced transport keys.
func (h *Handshake) Done() bool { return h.send != nil }

// PeerStatic returns the peer's authenticated static key. For the responder it
// is valid only after the first message is read.
func (h *Handshake) PeerStatic() parley.PublicKey {
	var pk parley.PublicKey
	copy(pk[:], h.hs.PeerStatic())
	return pk
}

// Transport returns the established channel. It is valid once [Handshake.Done].
func (h *Handshake) Transport() (parley.Transport, error) {
	if !h.Done() {
		return nil, fmt.Errorf("parley/noise: handshake incomplete")
	}
	return &transport{send: h.send, recv: h.recv}, nil
}

type transport struct {
	send *noise.CipherState
	recv *noise.CipherState
}

var _ parley.Transport = (*transport)(nil)

func (t *transport) Seal(seq uint64, plaintext []byte) ([]byte, error) {
	t.send.SetNonce(seq)
	ct, err := t.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("parley/noise: seal: %w", err)
	}
	return ct, nil
}

func (t *transport) Open(seq uint64, ciphertext []byte) ([]byte, error) {
	t.recv.SetNonce(seq)
	pt, err := t.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("parley/noise: open: %w", err)
	}
	return pt, nil
}
