package acme

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

// User implements the registration.User interface required by Lego.
type User struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// saveUser persists account registration details to disk as JSON.
func saveUser(path string, u *User) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// loadUser loads account registration details from disk.
func loadUser(path string, key crypto.PrivateKey) (*User, error) {
	// #nosec G304 -- This variable is loaded from config.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}
	u.key = key
	return &u, nil
}
