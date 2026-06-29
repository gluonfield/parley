package relayhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gluonfield/parley"
)

const (
	// maxWait caps one long-poll, so a connection never hangs indefinitely even
	// if a client asks for a longer wait.
	maxWait = 30 * time.Second

	// pollInterval re-checks the store during a long-poll, so frames appended by
	// another relay instance against a shared durable store are seen promptly
	// even without an in-process signal.
	pollInterval = time.Second

	// defaultRetention bounds how long an idle channel is kept. It is long enough
	// that a sealed frame survives until an offline peer next polls; back it with
	// a durable Store to also survive a relay restart.
	defaultRetention = 7 * 24 * time.Hour
)

// A Server is the relay's HTTP surface over a [Store]. It owns the wire format,
// membership-token minting, the long-poll wait, and retention policy; the Store
// owns where channel state lives. [NewServer] backs it with an in-memory store.
type Server struct {
	store     Store
	notify    *notifier
	retention time.Duration
}

// An Option configures a [Server].
type Option func(*Server)

// WithRetention sets how long an idle channel is kept before purge. Longer
// retention lets an offline peer collect a sealed frame after more downtime;
// pair it with a durable [Store] to also survive a relay restart.
func WithRetention(d time.Duration) Option {
	return func(s *Server) { s.retention = d }
}

// NewServer returns a relay backed by the default in-memory store.
func NewServer(opts ...Option) *Server { return NewServerWithStore(newMemStore(), opts...) }

// NewServerWithStore returns a relay backed by store, letting a deployment swap
// in durable storage (Redis, SQL, …) without touching the HTTP or wire layers.
func NewServerWithStore(store Store, opts ...Option) *Server {
	s := &Server{store: store, notify: newNotifier(), retention: defaultRetention}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler mounts the relay's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /c/{channel}", withChannel(s.handleOpen))
	mux.HandleFunc("POST /c/{channel}/join", withChannel(s.handleJoin))
	mux.HandleFunc("POST /c/{channel}/frames", withChannel(s.handleSend))
	mux.HandleFunc("GET /c/{channel}/frames", withChannel(s.handleRecv))
	mux.HandleFunc("GET /c/{channel}/members", withChannel(s.handleMembers))
	return mux
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request, ch parley.ChannelID) {
	var req openRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Purge(r.Context(), time.Now().Add(-s.retention))
	token := mintToken()
	if err := s.store.Open(r.Context(), ch, req.Expect, token); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, tokenResponse{Token: token})
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request, ch parley.ChannelID) {
	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := mintToken()
	if err := s.store.Join(r.Context(), ch, req.Token, token); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, tokenResponse{Token: token})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, ch parley.ChannelID) {
	var dto frameDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.Append(r.Context(), ch, bearer(r), dto.frame(ch)); err != nil {
		writeError(w, err)
		return
	}
	s.notify.signal(ch)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request, ch parley.ChannelID) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	waitMs, _ := strconv.ParseInt(r.URL.Query().Get("wait"), 10, 64)
	frames, err := s.recv(r.Context(), ch, bearer(r), after, time.Duration(waitMs)*time.Millisecond)
	if err != nil {
		writeError(w, err)
		return
	}
	dtos := make([]frameDTO, len(frames))
	for i, f := range frames {
		dtos[i] = toDTO(f)
	}
	writeJSON(w, recvResponse{Frames: dtos})
}

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request, ch parley.ChannelID) {
	n, err := s.store.Members(r.Context(), ch, bearer(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, membersResponse{Members: n})
}

// recv long-polls the store: it returns as soon as the seat has frames after the
// cursor, and otherwise waits up to wait for a signal, a periodic re-check, or
// the deadline. Subscribing to the notify channel before reading the store
// closes the gap where a frame could land between the read and the wait.
func (s *Server) recv(ctx context.Context, ch parley.ChannelID, token string, after uint64, wait time.Duration) ([]parley.Frame, error) {
	if wait > maxWait {
		wait = maxWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		ready := s.notify.wait(ch)
		frames, err := s.store.Frames(ctx, ch, token, after)
		if err != nil {
			return nil, err
		}
		if len(frames) > 0 || wait <= 0 {
			return frames, nil
		}
		select {
		case <-ready:
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, nil
		}
	}
}

func mintToken() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// notifier wakes long-polling readers on a channel when a frame is appended to
// it on this relay instance. It is in-process coordination only — a reader
// against a shared durable store also re-checks on pollInterval — so it carries
// no state a restart could lose.
type notifier struct {
	mu    sync.Mutex
	chans map[parley.ChannelID]chan struct{}
}

func newNotifier() *notifier {
	return &notifier{chans: make(map[parley.ChannelID]chan struct{})}
}

func (n *notifier) wait(ch parley.ChannelID) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.chans[ch]
	if !ok {
		c = make(chan struct{})
		n.chans[ch] = c
	}
	return c
}

func (n *notifier) signal(ch parley.ChannelID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.chans[ch]; ok {
		close(c)
		delete(n.chans, ch)
	}
}

// channelFunc is an HTTP handler whose channel has already been parsed.
type channelFunc func(http.ResponseWriter, *http.Request, parley.ChannelID)

// withChannel parses the {channel} path value once and rejects a malformed one,
// so the handlers need not each repeat it.
func withChannel(fn channelFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ch, ok := channelOf(r)
		if !ok {
			http.Error(w, "bad channel", http.StatusBadRequest)
			return
		}
		fn(w, r, ch)
	}
}

func channelOf(r *http.Request) (parley.ChannelID, bool) {
	b, err := base64.RawURLEncoding.DecodeString(r.PathValue("channel"))
	if err != nil || len(b) != len(parley.ChannelID{}) {
		return parley.ChannelID{}, false
	}
	var ch parley.ChannelID
	copy(ch[:], b)
	return ch, true
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errNoChannel):
		status = http.StatusNotFound
	case errors.Is(err, errExists), errors.Is(err, errFull), errors.Is(err, errNoPeer):
		status = http.StatusConflict
	case errors.Is(err, errBadToken):
		status = http.StatusUnauthorized
	}
	http.Error(w, err.Error(), status)
}
