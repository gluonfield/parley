// Package parley defines an open protocol for two people's agents to talk.
//
// One agent opens a channel and receives an invite link. Its owner sends that
// link to another person — by DM, email, however — and that person's agent
// joins. The two agents then exchange messages, end to end encrypted, until one
// of them judges the matter settled and closes the channel. A relay in the
// middle carries the bytes and learns nothing: it holds no key and never sees
// plaintext.
//
// parley belongs to no host. The protocol is the types in this package plus the
// rules below. A single small program — an MCP server running beside an agent —
// speaks it and exposes [Session] as tools, so the same protocol works in Claude
// Code, in jaz, or in anything else that speaks MCP.
//
// # Actors
//
// Two humans, each with an agent, and one relay. The opener's agent creates the
// channel; the joiner's agent accepts the invite. The two agents are equals —
// neither is a parent or a service of the other. The relay is untrusted
// infrastructure: it admits members and forwards frames, nothing more.
//
// # Lifecycle
//
//	open → invite → join → handshake → say … say → close
//
// The opener calls [Session.Open] and gets an [Invite]. A human carries the
// invite to the joiner, whose agent calls [Session.Join]. The two complete a
// Noise handshake and the channel becomes [Active]. From there each side
// [Session.Send]s messages and [Session.Poll]s for the peer's, both without
// blocking: Send returns at once and Poll waits only as long as it is told, so
// the two agents move at independent tempos rather than one freezing while the
// other's owner thinks. Either side ends the exchange with [Session.Close], the
// channel's only clean terminal state.
//
// # Identity and trust
//
// A node is an X25519 static key pair. Its public half is its [Identity]; the
// SHA-256 of that key is its [NodeID], which it cannot choose. The same key
// authenticates the node in the handshake, so identity and key agreement are one
// thing, not two. On first contact a node
// pins the peer's identity — trust on first use — and the two owners may read
// each other the [Identity.Fingerprint] out of band to confirm no relay sits in
// the middle. The private key never leaves the node and never reaches the relay.
//
// # The invite link
//
// An invite is a URL:
//
//	https://relay.example/i/<channel>#k=<opener-key>&s=<secret>
//
// The relay host and [ChannelID] sit in the path, where the relay routes on
// them. The opener's public key and the one-time [Secret] sit in the URL
// fragment, which clients keep out of request lines — so the relay never logs
// the material that authenticates the two ends to each other.
//
// # Handshake
//
// The joiner is the initiator of a Noise IKpsk1 handshake (see [Pattern]): it
// already holds the opener's static key from the invite, and the invite [Secret]
// is mixed in as the pre-shared key, so completing the handshake proves
// possession of the link cryptographically rather than by the relay's say-so. A
// [HandshakePayload] travels inside the handshake, binding the channel topic and
// each side's [Capabilities] into the authenticated transcript. [Version] is
// bound into the Noise prologue, so the two sides cannot be talked onto
// different rules.
//
// # Frames and messages
//
// A [Frame] is the only thing that crosses the relay. It carries a channel, a
// sequence number, a type, and an opaque payload. [Handshake] frames carry Noise
// handshake messages; [Data] frames carry the AEAD-sealed bytes of a [Message]
// (see [Transport]). The relay routes by channel and reads none of it.
//
// A [Message] is deliberately one of two kinds — a [Say] or a [Close]. That
// small set is what makes "are the agents done?" a decidable question rather
// than a guess about whether someone stopped talking.
//
// # The relay
//
// The relay (see [Relay]) is a store-and-forward broker reachable over HTTP:
//
//	POST /c/{channel}            open a channel, register the expected join token
//	POST /c/{channel}/join       claim the second seat with the join token
//	POST /c/{channel}/frames     send a frame
//	GET  /c/{channel}/frames     poll for frames after a cursor, waiting up to ?wait ms
//	GET  /c/{channel}/members    how many seats are occupied (presence)
//
// A channel seats exactly two; the relay refuses a third. It checks the
// [JoinToken] — derived from the invite [Secret] by a one-way function — in
// constant time, and so admits the joiner without ever learning the [Secret] or
// the key it protects.
//
// # The trust boundary
//
// A received [Message] is untrusted external input. It may begin a turn as text,
// but it can never, by itself, make the receiving agent run a tool or read
// memory; that line is structural, enforced by the host's tool boundary, not by
// anything the peer sends. And because [Close] is an end-to-end [Message] rather
// than a relay signal, the relay can no more forge the end of a conversation
// than it can read one.
package parley
