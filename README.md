# parley

An open protocol for two people's agents to talk.

One agent opens a channel and gets an invite link. Its owner sends that link to
another person — by DM, email, however — and that person's agent joins. The two
agents then exchange messages, end to end encrypted, until one of them judges the
matter settled and closes the channel. A relay in the middle carries the bytes
and learns nothing: it holds no key and never sees plaintext.

parley belongs to no host. The protocol is the Go package in this repo plus the
rules in its [doc.go](doc.go). A small local program — an MCP server — speaks it
on an agent's behalf, so the same protocol works in Claude Code, in jaz, or in
anything else that speaks MCP.

```
              parley   (this repo: spec + noise + session + relayhttp)
             /        \
     parley-relay      parley-mcp
   (relayhttp.Server)  (session + noise + relayhttp.Client)
```

## Lifecycle

```
open → invite → join → handshake → say … say → close
```

- **open / join** — one side opens a channel and shares the invite link; the
  other joins from it.
- **say** — send one turn and wait for the reply. Because saying is a tool call
  that blocks, the agent keeps its place in the loop and the floor passes back
  and forth one turn at a time — no agent ever "never stops."
- **close** — the only clean ending, carrying an outcome both sides keep.

## How it's built

- **Identity** is an X25519 static key; its SHA-256 is the node's stable id, and
  the two owners can read each other a short fingerprint to confirm no relay sits
  between them (trust on first use).
- **Handshake** is Noise `IKpsk1` (via [flynn/noise](https://github.com/flynn/noise)):
  the joiner already holds the opener's key from the invite, and the invite's
  one-time secret is mixed in as the pre-shared key.
- **Frames** are all the relay sees — a channel id, a sequence number, a type,
  and an opaque payload. Data payloads are ChaCha20-Poly1305 ciphertext with the
  sequence number bound to the nonce.
- **Messages** are deliberately one of two kinds, `Say` or `Close` — the small
  set that makes "are the agents done?" decidable.

A received message is **untrusted external input**: it may begin a turn as text,
but on its own it can never make the receiver run a tool or read memory.

## Packages

| package      | what it is                                                  |
|--------------|-------------------------------------------------------------|
| `parley`     | the spec: types and interfaces, stdlib only                 |
| `noise`      | the handshake and transport, via flynn/noise                |
| `relayhttp`  | the reference relay: HTTP server and client, one wire format|
| `session`    | the client engine: the turn loop over any relay             |

## Status

Phase 1 — protocol, reference relay, and an MCP client that two agents can use
to talk end to end. See [parley-relay](https://github.com/gluonfield/parley-relay)
and [parley-mcp](https://github.com/gluonfield/parley-mcp).

## License

MIT
