package broker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Connection struct {
	ID, Owner, TenantID, ObjectID, ClientID string
	Mode                                    string
	AccessToken, RefreshToken, Scope        string
	ExpiresAt, CreatedAt                    time.Time
	Status                                  string
}
type Intent struct {
	ID, Owner string
	ExpiresAt time.Time
}
type Delegation struct {
	ID, ConnectionID, Owner, AgentClientID string
	Operations                             []string
	ExpiresAt                              time.Time
}
type State struct {
	Connections map[string]Connection
	Intents     map[string]Intent
	Delegations map[string]Delegation
}

func emptyState() State {
	return State{map[string]Connection{}, map[string]Intent{}, map[string]Delegation{}}
}

// Store is a small single-process encrypted store. A process-level file lock rejects
// a second broker using the same directory. Use a transactional database before scaling.
type Store struct {
	mu       sync.Mutex
	state    State
	path     string
	lock     *os.File
	aead     cipher.AEAD
	poisoned bool
}

func OpenStore(dir string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "broker.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("data directory is already locked by another broker")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		f.Close()
		return nil, err
	}
	s := &Store{state: emptyState(), path: filepath.Join(dir, "state.enc"), lock: f, aead: aead}
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	plain, err := s.open(b, "broker-state-v1")
	if err == nil {
		err = json.Unmarshal(plain, &s.state)
	}
	if err != nil {
		s.Close()
		return nil, errors.New("cannot decrypt/read store: wrong key or damaged data")
	}
	if s.state.Connections == nil || s.state.Intents == nil || s.state.Delegations == nil {
		s.Close()
		return nil, errors.New("invalid store schema")
	}
	return s, nil
}
func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) seal(b []byte, aad string) ([]byte, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return s.aead.Seal(n, n, b, []byte(aad)), nil
}
func (s *Store) open(b []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("invalid ciphertext")
	}
	return s.aead.Open(nil, b[:n], b[n:], []byte(aad))
}
func (s *Store) View(fn func(State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return errors.New("store unavailable; restart after checking disk")
	}
	// Callers must not mutate the maps or slice values in a View callback.
	return fn(s.state)
}
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return errors.New("store unavailable; restart after checking disk")
	}
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	var next State
	if err = json.Unmarshal(b, &next); err != nil {
		return err
	}
	if err = fn(&next); err != nil {
		return err
	}
	b, err = json.Marshal(next)
	if err != nil {
		return err
	}
	b, err = s.seal(b, "broker-state-v1")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), "state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	// A failure after rename leaves durability uncertain. Fail closed until restart.
	d, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		s.poisoned = true
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		s.poisoned = true
		return err
	}
	s.state = next
	return nil
}
func newID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
