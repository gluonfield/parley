package relayhttp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gluonfield/parley"
)

// maxWait caps one long-poll, so a connection never hangs indefinitely even if a
// client asks for a longer wait.
const maxWait = 30 * time.Second

// idleTTL bounds how long an idle channel is retained before eviction, so a
// long-running relay does not accumulate dead channels (close is end-to-end, so
// the relay never sees it directly).
const idleTTL = 30 * time.Minute

var (
	errExists    = errors.New("channel already exists")
	errNoChannel = errors.New("no such channel")
	errFull      = errors.New("channel is full")
	errBadToken  = errors.New("unrecognized token")
	errNoPeer    = errors.New("peer has not joined")
)

// A Server is the relay's HTTP surface over an in-memory store. The zero value
// is not usable; construct it with [NewServer].
type Server struct {
	mu       sync.Mutex
	channels map[parley.ChannelID]*channel
}

type channel struct {
	expect parley.JoinToken
	seats  [2]*seat
	notify chan struct{} // closed and replaced when a frame is delivered
	seen   time.Time     // last activity, for idle eviction
}

type seat struct {
	token string
	inbox []parley.Frame
}

// NewServer returns an empty relay.
func NewServer() *Server {
	return &Server{channels: make(map[parley.ChannelID]*channel)}
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
	token, err := s.open(ch, req.Expect)
	if err != nil {
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
	token, err := s.join(ch, req.Token)
	if err != nil {
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
	if err := s.send(ch, bearer(r), dto.frame(ch)); err != nil {
		writeError(w, err)
		return
	}
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
	n, err := s.members(ch, bearer(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, membersResponse{Members: n})
}

func (s *Server) open(ch parley.ChannelID, expect parley.JoinToken) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictIdle()
	if _, ok := s.channels[ch]; ok {
		return "", errExists
	}
	token := mintToken()
	s.channels[ch] = &channel{
		expect: expect,
		seats:  [2]*seat{{token: token}},
		notify: make(chan struct{}),
		seen:   time.Now(),
	}
	return token, nil
}

func (s *Server) join(ch parley.ChannelID, present parley.JoinToken) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channels[ch]
	switch {
	case c == nil:
		return "", errNoChannel
	case c.seats[1] != nil:
		return "", errFull
	case subtle.ConstantTimeCompare([]byte(present), []byte(c.expect)) != 1:
		return "", errBadToken
	}
	c.seen = time.Now()
	token := mintToken()
	c.seats[1] = &seat{token: token}
	return token, nil
}

func (s *Server) send(ch parley.ChannelID, token string, f parley.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channels[ch]
	if c == nil {
		return errNoChannel
	}
	i := seatOf(c, token)
	if i < 0 {
		return errBadToken
	}
	peer := c.seats[1-i]
	if peer == nil {
		return errNoPeer
	}
	c.seen = time.Now()
	peer.inbox = append(peer.inbox, f)
	close(c.notify)
	c.notify = make(chan struct{})
	return nil
}

func (s *Server) recv(ctx context.Context, ch parley.ChannelID, token string, after uint64, wait time.Duration) ([]parley.Frame, error) {
	if wait > maxWait {
		wait = maxWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		c := s.channels[ch]
		if c == nil {
			s.mu.Unlock()
			return nil, errNoChannel
		}
		i := seatOf(c, token)
		if i < 0 {
			s.mu.Unlock()
			return nil, errBadToken
		}
		c.seen = time.Now()
		var out []parley.Frame
		for _, f := range c.seats[i].inbox {
			if f.Seq > after {
				out = append(out, f)
			}
		}
		notify := c.notify
		s.mu.Unlock()

		if len(out) > 0 || wait <= 0 {
			return out, nil
		}
		select {
		case <-notify:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, nil
		}
	}
}

func (s *Server) members(ch parley.ChannelID, token string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channels[ch]
	if c == nil {
		return 0, errNoChannel
	}
	if seatOf(c, token) < 0 {
		return 0, errBadToken
	}
	c.seen = time.Now()
	n := 0
	for _, st := range c.seats {
		if st != nil {
			n++
		}
	}
	return n, nil
}

// evictIdle drops channels with no activity for longer than idleTTL. The caller
// must hold s.mu. It runs opportunistically on open, so a long-running relay
// sheds dead channels without a background sweeper.
func (s *Server) evictIdle() {
	cutoff := time.Now().Add(-idleTTL)
	for id, c := range s.channels {
		if c.seen.Before(cutoff) {
			delete(s.channels, id)
		}
	}
}

func seatOf(c *channel, token string) int {
	for i, st := range c.seats {
		if st != nil && subtle.ConstantTimeCompare([]byte(st.token), []byte(token)) == 1 {
			return i
		}
	}
	return -1
}

func mintToken() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
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
