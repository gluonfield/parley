package relayhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gluonfield/parley"
)

// A Client reaches a relay over HTTP. It implements [parley.Relay].
type Client struct {
	base string
	hc   *http.Client
}

var _ parley.Relay = (*Client)(nil)

// NewClient returns a client for the relay at base (e.g. "https://parley.chat").
func NewClient(base string) *Client {
	return &Client{base: strings.TrimRight(base, "/"), hc: http.DefaultClient}
}

func (c *Client) Open(ctx context.Context, ch parley.ChannelID, expect parley.JoinToken) (parley.Membership, error) {
	var resp tokenResponse
	err := c.do(ctx, http.MethodPost, c.channelURL(ch), "", openRequest{Expect: expect}, &resp)
	return parley.Membership{Channel: ch, Token: resp.Token}, err
}

func (c *Client) Join(ctx context.Context, ch parley.ChannelID, present parley.JoinToken) (parley.Membership, error) {
	var resp tokenResponse
	err := c.do(ctx, http.MethodPost, c.channelURL(ch)+"/join", "", joinRequest{Token: present}, &resp)
	return parley.Membership{Channel: ch, Token: resp.Token}, err
}

func (c *Client) Send(ctx context.Context, m parley.Membership, f parley.Frame) error {
	return c.do(ctx, http.MethodPost, c.channelURL(m.Channel)+"/frames", m.Token, toDTO(f), nil)
}

// Recv long-polls until at least one frame is available, the context ends, or
// the relay reports the channel gone. Empty poll responses are retried.
func (c *Client) Recv(ctx context.Context, m parley.Membership, after uint64) ([]parley.Frame, error) {
	url := c.channelURL(m.Channel) + "/frames?after=" + strconv.FormatUint(after, 10)
	for {
		var resp recvResponse
		if err := c.do(ctx, http.MethodGet, url, m.Token, nil, &resp); err != nil {
			return nil, err
		}
		if len(resp.Frames) > 0 {
			out := make([]parley.Frame, len(resp.Frames))
			for i, d := range resp.Frames {
				out[i] = d.frame(m.Channel)
			}
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func (c *Client) channelURL(ch parley.ChannelID) string {
	return c.base + "/c/" + ch.String()
}

func (c *Client) do(ctx context.Context, method, url, token string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("parley/relayhttp: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
