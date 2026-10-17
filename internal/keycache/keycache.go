// Package keycache keeps the store key in the OS keychain.
package keycache

import (
	"strings"

	"github.com/zalando/go-keyring"

	"github.com/lminii/envs/internal/crypt"
)

const (
	service = "envs"
	user    = "store-key"
)

// Get returns the cached store key and the SHA-256 of the key.age it came from.
// ok is false when the keychain has no usable entry, for any reason.
func Get() (storeKey, keyFileHash string, ok bool) {
	value, err := keyring.Get(service, user)
	if err != nil {
		return "", "", false
	}
	storeKey, keyFileHash, found := strings.Cut(value, ":")
	if !found || !crypt.ValidStoreKey(storeKey) || !crypt.ValidStoreKey(keyFileHash) {
		return "", "", false
	}
	return storeKey, keyFileHash, true
}

func Set(storeKey, keyFileHash string) error {
	return keyring.Set(service, user, storeKey+":"+keyFileHash)
}

// Delete removes the entry. A missing entry is not an error.
func Delete() error {
	err := keyring.Delete(service, user)
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}
