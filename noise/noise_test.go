package noise

import (
	"bytes"
	"testing"

	"github.com/gluonfield/parley"
)

// run drives a full IKpsk1 exchange between a joiner (initiator) and an opener
// (responder) and returns their transports.
func run(t *testing.T, joinerPSK, openerPSK, prologue []byte) (parley.Transport, parley.Transport, error) {
	t.Helper()
	opener, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ini, err := NewInitiator(joiner, opener.Public, joinerPSK, prologue)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(opener, openerPSK, prologue)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := ini.Write([]byte("hello from joiner"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := res.Read(msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := res.Write([]byte("hello from opener"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.Read(msg2); err != nil {
		return nil, nil, err
	}
	if !ini.Done() || !res.Done() {
		t.Fatal("handshake did not complete")
	}
	it, err := ini.Transport()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := res.Transport()
	if err != nil {
		t.Fatal(err)
	}
	return it, rt, nil
}

func TestHandshakeRoundTrip(t *testing.T) {
	secret, _ := parley.NewSecret()
	psk, prologue := secret.PSK(), []byte("parley/1")

	joiner, opener, err := run(t, psk, psk, prologue)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Both directions, with the frame sequence binding the nonce.
	for seq := uint64(1); seq <= 3; seq++ {
		ping := []byte("ping")
		ct, err := joiner.Seal(seq, ping)
		if err != nil {
			t.Fatal(err)
		}
		got, err := opener.Open(seq, ct)
		if err != nil {
			t.Fatalf("opener open: %v", err)
		}
		if !bytes.Equal(got, ping) {
			t.Fatalf("joiner→opener: got %q", got)
		}

		pong := []byte("pong")
		ct, err = opener.Seal(seq, pong)
		if err != nil {
			t.Fatal(err)
		}
		got, err = joiner.Open(seq, ct)
		if err != nil {
			t.Fatalf("joiner open: %v", err)
		}
		if !bytes.Equal(got, pong) {
			t.Fatalf("opener→joiner: got %q", got)
		}
	}
}

func TestWrongPSKFails(t *testing.T) {
	a, _ := parley.NewSecret()
	b, _ := parley.NewSecret()
	if _, _, err := run(t, a.PSK(), b.PSK(), []byte("parley/1")); err == nil {
		t.Fatal("handshake completed with mismatched preshared keys")
	}
}

func TestWrongPrologueFails(t *testing.T) {
	secret, _ := parley.NewSecret()
	if _, _, err := run(t, secret.PSK(), secret.PSK(), nil); true {
		// control: matching nil prologue succeeds
		if err != nil {
			t.Fatalf("matching prologue failed: %v", err)
		}
	}
	secret, _ = parley.NewSecret()
	psk := secret.PSK()
	// Mismatched prologues must fail: drive it manually.
	opener, _ := GenerateKeypair()
	joiner, _ := GenerateKeypair()
	ini, _ := NewInitiator(joiner, opener.Public, psk, []byte("parley/1"))
	res, _ := NewResponder(opener, psk, []byte("parley/2"))
	msg1, _ := ini.Write(nil)
	if _, err := res.Read(msg1); err == nil {
		t.Fatal("handshake accepted mismatched prologue")
	}
}
