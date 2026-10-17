// Package crypt wraps age passphrase mode for the store key and the secret files.
package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/lminii/envs/internal/names"
)

const (
	// MaxFileSize is the largest .age file the tool parses.
	MaxFileSize = 1 << 20

	// MinPassphraseLength is counted in characters.
	MinPassphraseLength = 16

	formatVersion = 1

	// The store key has 256 bits of entropy, so secret files need no key stretching.
	secretWorkFactor = 10
	keyWorkFactor    = 18

	// The work factor is in the file header and scrypt runs before the
	// authentication check. These caps stop a changed header from forcing a
	// 2^22 scrypt (about 4 GiB and 15 s). Do not raise them.
	secretMaxWorkFactor = 10
	keyMaxWorkFactor    = 20
)

var (
	// ErrWrongKey means the key or passphrase does not open the file.
	ErrWrongKey = errors.New("wrong key")
	// ErrDamaged means the file is not a valid file from envs.
	ErrDamaged = errors.New("damaged file")
	// ErrTooLarge means the file is above MaxFileSize.
	ErrTooLarge = errors.New("file is larger than 1 MiB")
)

// SecretFile is the plaintext of one <project>/<environment>.age file.
type SecretFile struct {
	Version     int               `json:"version"`
	Project     string            `json:"project"`
	Environment string            `json:"environment"`
	Values      map[string]string `json:"values"`
}

func NewSecretFile(project, environment string) *SecretFile {
	return &SecretFile{
		Version:     formatVersion,
		Project:     project,
		Environment: environment,
		Values:      map[string]string{},
	}
}

// NewStoreKey returns 32 random bytes as 64 lowercase hex characters.
func NewStoreKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ValidStoreKey(key string) bool {
	if len(key) != 64 || strings.ToLower(key) != key {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

// Hash returns the hex SHA-256 of data.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReadFile reads an .age file and refuses one above MaxFileSize.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	return data, nil
}

func EncryptSecretFile(storeKey string, file *SecretFile) ([]byte, error) {
	plaintext, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	return encrypt(storeKey, secretWorkFactor, plaintext)
}

// DecryptSecretFile decrypts data and checks that it belongs to project and environment.
func DecryptSecretFile(storeKey string, data []byte, project, environment string) (*SecretFile, error) {
	plaintext, err := decrypt(storeKey, secretMaxWorkFactor, data)
	if err != nil {
		return nil, err
	}
	var file SecretFile
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		// The JSON error can quote plaintext, so it is not passed on.
		return nil, fmt.Errorf("%w: the content is not valid JSON", ErrDamaged)
	}
	if file.Version != formatVersion {
		return nil, fmt.Errorf("file format version %d is not supported. Update envs", file.Version)
	}
	if file.Project != project || file.Environment != environment {
		if names.Project(file.Project) != nil || names.Environment(file.Environment) != nil {
			return nil, fmt.Errorf("%w: the content has an invalid project or environment name", ErrDamaged)
		}
		return nil, fmt.Errorf("%w: the content belongs to %s/%s. The file was moved", ErrDamaged, file.Project, file.Environment)
	}
	for key := range file.Values {
		if names.Key(key) != nil {
			return nil, fmt.Errorf("%w: the content has an invalid key name", ErrDamaged)
		}
	}
	if file.Values == nil {
		file.Values = map[string]string{}
	}
	return &file, nil
}

func EncryptKeyFile(passphrase, storeKey string) ([]byte, error) {
	return encrypt(passphrase, keyWorkFactor, []byte(storeKey))
}

func DecryptKeyFile(passphrase string, data []byte) (string, error) {
	plaintext, err := decrypt(passphrase, keyMaxWorkFactor, data)
	if err != nil {
		return "", err
	}
	key := string(plaintext)
	if !ValidStoreKey(key) {
		return "", fmt.Errorf("%w: the content is not a store key", ErrDamaged)
	}
	return key, nil
}

func encrypt(passphrase string, workFactor int, plaintext []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(workFactor)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decrypt(passphrase string, maxWorkFactor int, data []byte) ([]byte, error) {
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(maxWorkFactor)
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		return nil, ErrWrongKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	// age detects truncation only at the end of the stream, so no byte is
	// used before the full read succeeds.
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	return plaintext, nil
}
