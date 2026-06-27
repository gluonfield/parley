package parley

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// A PublicKey is a node's X25519 static public key — the identity the Noise
// handshake authenticates. A node cannot forge another's.
type PublicKey [32]byte

// A NodeID is a node's stable handle: the SHA-256 of its [PublicKey]. Equal
// NodeIDs are the same identity, and a node cannot choose its own.
type NodeID [sha256.Size]byte

// Fingerprint renders the NodeID as a short, human-readable string two people
// can read to each other to confirm, on first contact, that no relay sits
// between them.
func (n NodeID) Fingerprint() string {
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(n[:10]))
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// Identity is a node's public identity. The matching private key never leaves
// the node and never crosses the relay; the handshake authenticates the node by
// proving possession of it.
type Identity struct {
	Key PublicKey
}

// ID returns the node's stable handle.
func (id Identity) ID() NodeID {
	return sha256.Sum256(id.Key[:])
}

// Fingerprint is the human-readable rendering of the node's [NodeID].
func (id Identity) Fingerprint() string {
	return id.ID().Fingerprint()
}
