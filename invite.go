package parley

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// A ChannelID names a channel on a relay. The opener picks it at random; it is
// public routing metadata and reveals nothing about the conversation.
type ChannelID [16]byte

// NewChannelID mints a random channel id.
func NewChannelID() (ChannelID, error) {
	var c ChannelID
	_, err := rand.Read(c[:])
	return c, err
}

func (c ChannelID) String() string { return base64.RawURLEncoding.EncodeToString(c[:]) }

// A Secret is the one-time value minted with an [Invite]. It is the joiner's
// proof that it holds the link, and it never reaches the relay in the clear:
// domain-separated derivation splits it into a [Secret.PSK] known only to the
// two endpoints and a [Secret.JoinToken] shown to the relay.
type Secret [32]byte

// NewSecret mints a fresh invite secret.
func NewSecret() (Secret, error) {
	var s Secret
	_, err := rand.Read(s[:])
	return s, err
}

// PSK is the pre-shared key mixed into the Noise handshake. Only the two
// endpoints, holding the [Secret], can derive it.
func (s Secret) PSK() []byte { return derive(s, "parley:psk") }

// A JoinToken proves possession of the link to the relay without revealing the
// [Secret.PSK]. The opener registers the expected token; the joiner presents it.
type JoinToken string

// JoinToken derives the token the relay checks to admit the joiner.
func (s Secret) JoinToken() JoinToken {
	return JoinToken(base64.RawURLEncoding.EncodeToString(derive(s, "parley:join")))
}

func derive(s Secret, label string) []byte {
	sum := sha256.Sum256(append([]byte(label), s[:]...))
	return sum[:]
}

// An Invite bootstraps a channel. The opener creates it and a human carries it
// to the joiner out of band. Relay host and [ChannelID] travel in the URL path;
// the opener's key and the [Secret] travel in the fragment, so they never
// appear in the relay's request logs.
type Invite struct {
	Relay   string
	Channel ChannelID
	Key     PublicKey
	Secret  Secret
}

// URL renders the invite as the link a human shares.
func (in Invite) URL() string {
	frag := url.Values{
		"k": {base64.RawURLEncoding.EncodeToString(in.Key[:])},
		"s": {base64.RawURLEncoding.EncodeToString(in.Secret[:])},
	}
	return fmt.Sprintf("https://%s/i/%s#%s", in.Relay, in.Channel, frag.Encode())
}

// ParseInvite reads a link produced by [Invite.URL].
func ParseInvite(raw string) (Invite, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Invite{}, fmt.Errorf("parley: parse invite: %w", err)
	}
	id, ok := strings.CutPrefix(u.Path, "/i/")
	if !ok {
		return Invite{}, badInvite("missing channel")
	}
	channel, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(channel) != len(ChannelID{}) {
		return Invite{}, badInvite("bad channel")
	}
	frag, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return Invite{}, badInvite("bad fragment")
	}
	key, err := base64.RawURLEncoding.DecodeString(frag.Get("k"))
	if err != nil || len(key) != len(PublicKey{}) {
		return Invite{}, badInvite("bad key")
	}
	secret, err := base64.RawURLEncoding.DecodeString(frag.Get("s"))
	if err != nil || len(secret) != len(Secret{}) {
		return Invite{}, badInvite("bad secret")
	}
	in := Invite{Relay: u.Host}
	copy(in.Channel[:], channel)
	copy(in.Key[:], key)
	copy(in.Secret[:], secret)
	return in, nil
}

func badInvite(why string) error { return fmt.Errorf("parley: invalid invite: %s", why) }
