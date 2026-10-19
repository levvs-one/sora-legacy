package control

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/levvs-one/sora-client/core/errs"
	"github.com/levvs-one/sora-client/core/secret"
)

// TokenLen is the control token length in bytes. Connect and Disconnect carry
// raw bytes; any other length is rejected.
const TokenLen = 32

// tokenFile stores the control token in the core data directory with owner-only
// read access for client authentication.
const tokenFile = "control.token"

// Authenticator checks tokens in constant time. The token distinguishes the
// client that performed Handshake from stale or accidental clients; it is NOT
// a security boundary against other processes of the same account. Handshake
// issues the token to every peer the transport admits, so any same-account
// process can obtain it. The real authorization boundary is the transport's
// peer allow-list (Unix socket permissions / SO_PEERCRED, Windows pipe ACL,
// polkit policy): see the ipc package.
type Authenticator struct {
	mu sync.RWMutex
	// path is the token file written by LoadOrCreateToken. Empty for
	// instances built with NewAuthenticator, for which Rotate keeps the
	// token in memory only.
	path  string
	token []byte
}

// NewAuthenticator returns an authenticator for an existing token. The token is
// copied, so the caller may wipe its own. The instance has no token file, so
// Rotate keeps the new token in memory only.
func NewAuthenticator(token []byte) (*Authenticator, error) {
	if len(token) != TokenLen {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyUnauthenticated,
			"control: the authenticator must be %d bytes, got %d", TokenLen, len(token))
	}
	return &Authenticator{token: append([]byte(nil), token...)}, nil
}

// LoadOrCreateToken loads the data directory's token or creates it on first
// start. Invalid existing files are rejected to expose corruption and avoid
// disconnecting clients.
func LoadOrCreateToken(dir string) (*Authenticator, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyUnauthenticated,
			"control: no data directory for the authenticator")
	}
	path := filepath.Join(dir, tokenFile)
	raw, err := os.ReadFile(path) //nolint:gosec // a fixed file name inside the data directory of the core
	switch {
	case err == nil:
		token, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(token) != TokenLen {
			return nil, errs.Newf(errs.CodeInternal, errs.KeyUnauthenticated,
				"control: the stored authenticator is not readable")
		}
		return NewAuthenticator(token)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, errs.Wrap(err, errs.CodeInternal, errs.KeyUnauthenticated)
	}
	token := make([]byte, TokenLen)
	if _, err := rand.Read(token); err != nil {
		return nil, errs.Wrap(err, errs.CodeInternal, errs.KeyUnauthenticated)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(token))
	if err := secret.WriteFileAtomic(path, encoded, 0o600); err != nil {
		return nil, err
	}
	auth, err := NewAuthenticator(token)
	if err != nil {
		return nil, err
	}
	auth.path = path
	return auth, nil
}

// Verify checks a token in constant time after rejecting an invalid length.
func (a *Authenticator) Verify(presented []byte) bool {
	if a == nil || len(presented) != TokenLen {
		return false
	}
	a.mu.RLock()
	expected := a.token
	a.mu.RUnlock()
	if len(expected) != TokenLen {
		return false
	}
	return subtle.ConstantTimeCompare(presented, expected) == 1
}

// Check returns the catalog error when token verification fails.
func (a *Authenticator) Check(presented []byte) error {
	if a.Verify(presented) {
		return nil
	}
	return errs.Newf(errs.CodeUnauthenticated, errs.KeyUnauthenticated,
		"control: the presented authenticator does not match")
}

// Token returns a copy of the token for Handshake. Every peer admitted by
// the transport receives it, so possession of the token proves only that the
// presenter once completed Handshake, not that it is the legitimate UI.
func (a *Authenticator) Token() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]byte(nil), a.token...)
}

// Rotate replaces and returns the token without restarting the core. All
// existing client tokens become invalid. When the authenticator was loaded
// from a token file, the new token is persisted atomically before it takes
// effect, so a restart cannot resurrect the compromised token; a failed
// write leaves the old token in place.
func (a *Authenticator) Rotate() ([]byte, error) {
	fresh := make([]byte, TokenLen)
	if _, err := rand.Read(fresh); err != nil {
		return nil, errs.Wrap(err, errs.CodeInternal, errs.KeyUnauthenticated)
	}
	a.mu.RLock()
	path := a.path
	a.mu.RUnlock()
	if path != "" {
		encoded := []byte(base64.StdEncoding.EncodeToString(fresh))
		if err := secret.WriteFileAtomic(path, encoded, 0o600); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	a.token = append([]byte(nil), fresh...)
	a.mu.Unlock()
	return fresh, nil
}
