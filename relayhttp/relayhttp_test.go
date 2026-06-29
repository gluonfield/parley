package relayhttp

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gluonfield/parley"
)

func newRelay(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(NewServer().Handler())
	t.Cleanup(srv.Close)
	return NewClient(srv.URL)
}

func opened(t *testing.T, c *Client) (parley.ChannelID, parley.Secret, parley.Membership) {
	t.Helper()
	ch, err := parley.NewChannelID()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := parley.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.Open(context.Background(), ch, secret.JoinToken())
	if err != nil {
		t.Fatal(err)
	}
	return ch, secret, m
}

func data(ch parley.ChannelID, seq uint64, text string) parley.Frame {
	return parley.Frame{Channel: ch, Seq: seq, Type: parley.Data, Payload: []byte(text)}
}

func TestOpenJoinSendRecv(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	ch, secret, opener := opened(t, c)
	joiner, err := c.Join(ctx, ch, secret.JoinToken())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, joiner, data(ch, 1, "hi")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Recv(ctx, opener, 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Seq != 1 || string(got[0].Payload) != "hi" {
		t.Fatalf("got %+v", got)
	}
}

func TestThirdSeatRefused(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	ch, secret, _ := opened(t, c)
	if _, err := c.Join(ctx, ch, secret.JoinToken()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Join(ctx, ch, secret.JoinToken()); err == nil {
		t.Fatal("relay admitted a third member")
	}
}

func TestBadJoinToken(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	ch, _, _ := opened(t, c)
	wrong, _ := parley.NewSecret()
	if _, err := c.Join(ctx, ch, wrong.JoinToken()); err == nil {
		t.Fatal("relay admitted a wrong join token")
	}
}

func TestMembersPresence(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	ch, secret, opener := opened(t, c)
	if n, err := c.Members(ctx, opener); err != nil || n != 1 {
		t.Fatalf("before join: members=%d err=%v", n, err)
	}
	if _, err := c.Join(ctx, ch, secret.JoinToken()); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Members(ctx, opener); err != nil || n != 2 {
		t.Fatalf("after join: members=%d err=%v", n, err)
	}
}

func TestNonBlockingPollIsEmpty(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	_, _, opener := opened(t, c)
	start := time.Now()
	got, err := c.Recv(ctx, opener, 0, 0) // wait=0 must return at once
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no frames, got %d", len(got))
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait=0 poll blocked")
	}
}

func TestLongPollWakesOnFrame(t *testing.T) {
	c := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, secret, opener := opened(t, c)
	joiner, err := c.Join(ctx, ch, secret.JoinToken())
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan parley.Frame, 1)
	go func() {
		got, err := c.Recv(ctx, opener, 0, 5*time.Second)
		if err != nil || len(got) == 0 {
			done <- parley.Frame{}
			return
		}
		done <- got[0]
	}()

	if err := c.Send(ctx, joiner, data(ch, 1, "late")); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-done:
		if string(f.Payload) != "late" {
			t.Fatalf("got %q", f.Payload)
		}
	case <-ctx.Done():
		t.Fatal("long-poll did not wake")
	}
}

func TestPurgeDropsIdleChannels(t *testing.T) {
	m := newMemStore()
	secret, _ := parley.NewSecret()
	stale, _ := parley.NewChannelID()
	if err := m.Open(context.Background(), stale, secret.JoinToken(), "stale-token"); err != nil {
		t.Fatal(err)
	}
	m.channels[stale].seen = time.Now().Add(-time.Hour)
	fresh, _ := parley.NewChannelID()
	if err := m.Open(context.Background(), fresh, secret.JoinToken(), "fresh-token"); err != nil {
		t.Fatal(err)
	}
	if err := m.Purge(context.Background(), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.channels[stale]; ok {
		t.Error("idle channel was not purged")
	}
	if _, ok := m.channels[fresh]; !ok {
		t.Error("fresh channel missing")
	}
}

// countingStore proves the relay drives whatever Store it is given: a deployment
// can swap in a durable backend without changing the HTTP or wire layers.
type countingStore struct {
	Store
	mu      sync.Mutex
	appends int
}

func (c *countingStore) Append(ctx context.Context, ch parley.ChannelID, from string, f parley.Frame) error {
	c.mu.Lock()
	c.appends++
	c.mu.Unlock()
	return c.Store.Append(ctx, ch, from, f)
}

func TestServerUsesInjectedStore(t *testing.T) {
	cs := &countingStore{Store: newMemStore()}
	srv := httptest.NewServer(NewServerWithStore(cs).Handler())
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL)
	ctx := context.Background()
	ch, secret, _ := opened(t, c)
	joiner, err := c.Join(ctx, ch, secret.JoinToken())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, joiner, data(ch, 1, "hi")); err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.appends != 1 {
		t.Fatalf("injected store not used: appends=%d", cs.appends)
	}
}

func TestAfterCursor(t *testing.T) {
	c := newRelay(t)
	ctx := context.Background()
	ch, secret, opener := opened(t, c)
	joiner, err := c.Join(ctx, ch, secret.JoinToken())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, joiner, data(ch, 1, "one")); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, joiner, data(ch, 2, "two")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Recv(ctx, opener, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("after-cursor returned %+v", got)
	}
}
