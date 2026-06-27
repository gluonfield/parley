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

// TestTwoAgentsParley is the milestone: two independent sessions, a live relay,
// and an invite carried through its URL form, exchange a full conversation and
// end on a Close — without ever sharing memory.
func TestTwoAgentsParley(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	// The joiner only ever sees the link, so parse it back from its URL form.
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
	go func() {
		defer wg.Done()
		reply, err := joiner.Say(ctx, "hello opener")
		if err != nil {
			errs[0] = err
			return
		}
		joinerHeard = reply.Text
		errs[0] = joiner.Close(ctx, "agreed: offsite in september")
	}()
	go func() {
		defer wg.Done()
		msg, err := opener.Recv(ctx)
		if err != nil {
			errs[1] = err
			return
		}
		openerHeard = msg.Text
		// Say returns the joiner's next message — which is the Close.
		final, err := opener.Say(ctx, "hello joiner")
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

	// The joiner learned the topic from the handshake; both pinned the other's
	// real identity.
	if got := joiner.Peer().Topic; got != "plan the offsite" {
		t.Errorf("joiner learned topic %q", got)
	}
	if got, want := opener.Peer().Fingerprint, (parley.Identity{Key: jkp.Public}).Fingerprint(); got != want {
		t.Errorf("opener pinned %q, want joiner %q", got, want)
	}
	if got, want := joiner.Peer().Fingerprint, (parley.Identity{Key: okp.Public}).Fingerprint(); got != want {
		t.Errorf("joiner pinned %q, want opener %q", got, want)
	}
	if opener.Peer().State != parley.Closed {
		t.Error("opener channel not closed")
	}
}
