package session_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gluonfield/parley"
	"github.com/gluonfield/parley/noise"
	"github.com/gluonfield/parley/relayhttp"
	"github.com/gluonfield/parley/session"
)

// pollUntil drives a session until it yields a message or the context ends.
func pollUntil(ctx context.Context, s *session.Session) (parley.Message, error) {
	for {
		msgs, err := s.Poll(ctx, time.Second)
		if err != nil {
			return parley.Message{}, err
		}
		if len(msgs) > 0 {
			return msgs[0], nil
		}
		if ctx.Err() != nil {
			return parley.Message{}, ctx.Err()
		}
	}
}

// TestTwoAgentsParley is the milestone for the non-blocking model: two
// independent sessions, a live relay, and an invite carried through its URL
// form, hold a full conversation by sending and polling — never blocking on a
// say — and end on a Close.
func TestTwoAgentsParley(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relaySrv := httptest.NewServer(relayhttp.NewServer().Handler())
	defer relaySrv.Close()
	relay := relayhttp.NewClient(relaySrv.URL)

	okp, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	jkp, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opener := session.New(okp, relay, "parley.test")
	joiner := session.New(jkp, relay, "parley.test")

	invite, err := opener.Open(ctx, "plan the offsite")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	parsed, err := parley.ParseInvite(invite.URL())
	if err != nil {
		t.Fatalf("parse invite: %v", err)
	}
	if err := joiner.Join(ctx, parsed); err != nil {
		t.Fatalf("join: %v", err)
	}

	var (
		wg          sync.WaitGroup
		joinerHeard string
		openerHeard string
		openerFinal parley.Kind
		errs        [2]error
	)
	wg.Add(2)
	go func() { // joiner: speaks first, then closes
		defer wg.Done()
		if err := joiner.Send(ctx, "hello opener"); err != nil {
			errs[0] = err
			return
		}
		reply, err := pollUntil(ctx, joiner)
		if err != nil {
			errs[0] = err
			return
		}
		joinerHeard = reply.Text
		errs[0] = joiner.Close(ctx, "agreed: offsite in september")
	}()
	go func() { // opener: listens, replies, then hears the close
		defer wg.Done()
		msg, err := pollUntil(ctx, opener)
		if err != nil {
			errs[1] = err
			return
		}
		openerHeard = msg.Text
		if err := opener.Send(ctx, "hello joiner"); err != nil {
			errs[1] = err
			return
		}
		final, err := pollUntil(ctx, opener)
		if err != nil {
			errs[1] = err
			return
		}
		openerFinal = final.Kind
	}()
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatalf("conversation: %v", err)
		}
	}
	if openerHeard != "hello opener" {
		t.Errorf("opener heard %q", openerHeard)
	}
	if joinerHeard != "hello joiner" {
		t.Errorf("joiner heard %q", joinerHeard)
	}
	if openerFinal != parley.Close {
		t.Errorf("opener's final message kind = %d, want Close", openerFinal)
	}
	if got := joiner.Peer().Topic; got != "plan the offsite" {
		t.Errorf("joiner learned topic %q", got)
	}
	if got, want := opener.Peer().Fingerprint, (parley.Identity{Key: jkp.Public}).Fingerprint(); got != want {
		t.Errorf("opener pinned %q, want joiner %q", got, want)
	}
	if !opener.Peer().Present {
		t.Error("opener does not see the peer as present")
	}
	if opener.Peer().State != parley.Closed {
		t.Error("opener channel not closed")
	}
}

// TestPollNonBlocking confirms a poll with no peer returns promptly and empty.
func TestPollNonBlocking(t *testing.T) {
	ctx := context.Background()
	relaySrv := httptest.NewServer(relayhttp.NewServer().Handler())
	defer relaySrv.Close()
	relay := relayhttp.NewClient(relaySrv.URL)

	kp, _ := noise.GenerateKeypair()
	opener := session.New(kp, relay, "parley.test")
	if _, err := opener.Open(ctx, "lonely"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	msgs, err := opener.Poll(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected no messages, got %d", len(msgs))
	}
	if time.Since(start) > time.Second {
		t.Fatal("non-blocking poll blocked")
	}
	if opener.Peer().Present {
		t.Error("reported peer present with no joiner")
	}
}
