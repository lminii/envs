package keycache

import (
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestRoundTrip(t *testing.T) {
	keyring.MockInit()
	key, hash := strings.Repeat("0a", 32), strings.Repeat("1b", 32)

	if _, _, ok := Get(); ok {
		t.Fatal("Get is ok on an empty keychain")
	}
	if err := Set(key, hash); err != nil {
		t.Fatal(err)
	}
	gotKey, gotHash, ok := Get()
	if !ok || gotKey != key || gotHash != hash {
		t.Fatal("Get does not return the stored entry")
	}
	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := Get(); ok {
		t.Fatal("Get is ok after Delete")
	}
	if err := Delete(); err != nil {
		t.Fatalf("Delete of a missing entry: %v", err)
	}
}

func TestGetUnusableEntry(t *testing.T) {
	key, hash := strings.Repeat("0a", 32), strings.Repeat("1b", 32)
	cases := []struct {
		name  string
		value string
	}{
		{"no hash", key},
		{"empty", ""},
		{"short key", key[:62] + ":" + hash},
		{"short hash", key + ":" + hash[:62]},
		{"uppercase key", strings.ToUpper(key) + ":" + hash},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keyring.MockInit()
			if err := keyring.Set(service, user, c.value); err != nil {
				t.Fatal(err)
			}
			if _, _, ok := Get(); ok {
				t.Fatal("Get is ok for an unusable entry")
			}
		})
	}
	t.Run("keychain error", func(t *testing.T) {
		keyring.MockInitWithError(errors.New("no keychain"))
		if _, _, ok := Get(); ok {
			t.Fatal("Get is ok when the keychain fails")
		}
	})
}
