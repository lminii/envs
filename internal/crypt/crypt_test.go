package crypt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	key, err := NewStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sealed(t *testing.T, key, project, environment string) []byte {
	t.Helper()
	file := NewSecretFile(project, environment)
	file.Values["API_KEY"] = "s3cret-value"
	data, err := EncryptSecretFile(key, file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// setWorkFactor rewrites the scrypt work factor in the age header.
func setWorkFactor(t *testing.T, data []byte, from, to string) []byte {
	t.Helper()
	old := []byte(" " + from + "\n")
	if !bytes.Contains(data, old) {
		t.Fatalf("header has no work factor %s", from)
	}
	return bytes.Replace(data, old, []byte(" "+to+"\n"), 1)
}

func TestNewStoreKey(t *testing.T) {
	a, b := newKey(t), newKey(t)
	if !ValidStoreKey(a) || !ValidStoreKey(b) {
		t.Fatalf("invalid store key form")
	}
	if a == b {
		t.Fatal("two store keys are equal")
	}
}

func TestValidStoreKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		ok   bool
	}{
		{"valid", strings.Repeat("0a", 32), true},
		{"uppercase", strings.Repeat("0A", 32), false},
		{"short", strings.Repeat("0a", 31), false},
		{"long", strings.Repeat("0a", 33), false},
		{"not hex", strings.Repeat("zz", 32), false},
		{"trailing newline", strings.Repeat("0a", 31) + "0\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidStoreKey(c.key); got != c.ok {
				t.Errorf("ValidStoreKey = %v, want %v", got, c.ok)
			}
		})
	}
}

func TestSecretFileRoundTrip(t *testing.T) {
	key := newKey(t)
	file := NewSecretFile("myapp", "dev")
	file.Values["API_KEY"] = "line1\nline2 \"quoted\" $HOME"
	file.Values["EMPTY"] = ""
	data, err := EncryptSecretFile(key, file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("API_KEY")) {
		t.Fatal("ciphertext contains a key name")
	}
	got, err := DecryptSecretFile(key, data, "myapp", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Values) != 2 || got.Values["API_KEY"] != file.Values["API_KEY"] || got.Values["EMPTY"] != "" {
		t.Fatalf("values changed in the round trip")
	}
}

func TestDecryptSecretFile(t *testing.T) {
	key := newKey(t)
	valid := sealed(t, key, "myapp", "dev")

	encryptJSON := func(plaintext string) []byte {
		data, err := encrypt(key, secretWorkFactor, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	cases := []struct {
		name    string
		key     string
		data    []byte
		project string
		wantIs  error
		wantMsg string
	}{
		{"truncated", key, valid[:len(valid)-1], "myapp", ErrDamaged, ""},
		{"truncated to header", key, valid[:bytes.Index(valid, []byte("\n---"))], "myapp", ErrDamaged, ""},
		{"flipped payload byte", key, flipLast(valid), "myapp", ErrDamaged, ""},
		{"moved between projects", key, valid, "other", ErrDamaged, "belongs to myapp/dev"},
		{"work factor 22", key, setWorkFactor(t, valid, "10", "22"), "myapp", ErrDamaged, "work factor too large"},
		{"work factor 11", key, setWorkFactor(t, valid, "10", "11"), "myapp", ErrDamaged, "work factor too large"},
		{"another key", newKey(t), valid, "myapp", ErrWrongKey, ""},
		{"too large", key, make([]byte, MaxFileSize+1), "myapp", ErrTooLarge, ""},
		{"not an age file", key, []byte("hello"), "myapp", ErrDamaged, ""},
		{"empty", key, nil, "myapp", ErrDamaged, ""},
		{"not JSON", key, encryptJSON("API_KEY=plain"), "myapp", ErrDamaged, "not valid JSON"},
		{"unknown field", key, encryptJSON(`{"version":1,"project":"myapp","environment":"dev","values":{},"extra":1}`), "myapp", ErrDamaged, "not valid JSON"},
		{"version 2", key, encryptJSON(`{"version":2,"project":"myapp","environment":"dev","values":{}}`), "myapp", nil, "Update envs"},
		{"invalid key name", key, encryptJSON(`{"version":1,"project":"myapp","environment":"dev","values":{"A=B":"x"}}`), "myapp", ErrDamaged, "invalid key name"},
		{"invalid project name", key, encryptJSON(`{"version":1,"project":"../x","environment":"dev","values":{}}`), "myapp", ErrDamaged, "invalid project or environment name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecryptSecretFile(c.key, c.data, c.project, "dev")
			if err == nil {
				t.Fatal("no error")
			}
			if c.wantIs != nil && !errors.Is(err, c.wantIs) {
				t.Errorf("error = %v, want %v", err, c.wantIs)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err, c.wantMsg)
			}
			if strings.Contains(err.Error(), "s3cret-value") || strings.Contains(err.Error(), "plain") {
				t.Errorf("error contains plaintext: %q", err)
			}
		})
	}
}

func flipLast(data []byte) []byte {
	out := bytes.Clone(data)
	out[len(out)-1] ^= 1
	return out
}

func TestKeyFile(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt with work factor 18")
	}
	key := newKey(t)
	passphrase := "correct horse battery"
	data, err := EncryptKeyFile(passphrase, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(" 18\n")) {
		t.Fatal("key.age does not use work factor 18")
	}

	t.Run("round trip", func(t *testing.T) {
		got, err := DecryptKeyFile(passphrase, data)
		if err != nil {
			t.Fatal(err)
		}
		if got != key {
			t.Fatal("store key changed in the round trip")
		}
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		if _, err := DecryptKeyFile("wrong horse battery!", data); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("error = %v, want ErrWrongKey", err)
		}
	})
	t.Run("work factor 21", func(t *testing.T) {
		_, err := DecryptKeyFile(passphrase, setWorkFactor(t, data, "18", "21"))
		if !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "work factor too large") {
			t.Fatalf("error = %v, want a work factor error", err)
		}
	})
	t.Run("content is not a store key", func(t *testing.T) {
		bad, err := encrypt(passphrase, secretWorkFactor, []byte("not a key"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecryptKeyFile(passphrase, bad); !errors.Is(err, ErrDamaged) {
			t.Fatalf("error = %v, want ErrDamaged", err)
		}
	})
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		size int
		want error
	}{
		{"at the limit", MaxFileSize, nil},
		{"above the limit", MaxFileSize + 1, ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, "f.age")
			if err := os.WriteFile(path, make([]byte, c.size), 0o600); err != nil {
				t.Fatal(err)
			}
			data, err := ReadFile(path)
			if !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
			if c.want == nil && len(data) != c.size {
				t.Fatalf("read %d bytes, want %d", len(data), c.size)
			}
		})
	}
}
