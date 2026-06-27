// Package relayhttp is parley's reference relay: an HTTP [Server] that stores
// and forwards frames, and a [Client] that implements [parley.Relay] against it.
// Both live here so the wire format has exactly one owner. The relay holds no
// keys and reads no plaintext; a [parley.Data] frame's payload is ciphertext.
package relayhttp

import "github.com/gluonfield/parley"

type openRequest struct {
	Expect parley.JoinToken `json:"expect"`
}

type joinRequest struct {
	Token parley.JoinToken `json:"token"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

// A frameDTO is a frame on the wire. The channel travels in the URL path, so it
// is not repeated here; Payload encodes as base64 via encoding/json.
type frameDTO struct {
	Seq     uint64           `json:"seq"`
	Type    parley.FrameType `json:"type"`
	Payload []byte           `json:"payload"`
}

type recvResponse struct {
	Frames []frameDTO `json:"frames"`
}

type membersResponse struct {
	Members int `json:"members"`
}

func toDTO(f parley.Frame) frameDTO {
	return frameDTO{Seq: f.Seq, Type: f.Type, Payload: f.Payload}
}

func (d frameDTO) frame(ch parley.ChannelID) parley.Frame {
	return parley.Frame{Channel: ch, Seq: d.Seq, Type: d.Type, Payload: d.Payload}
}
