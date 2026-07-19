package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// Backups are always encrypted so a leaked file never exposes bcrypt hashes,
// DNS API tokens or private keys. Two modes:
//   - password given  -> key = argon2id(password, salt); portable, restore
//     anywhere with the password.
//   - no password     -> key = per-instance key persisted at instanceKeyPath;
//     protects the file at rest, restore works on the same instance (copy the
//     key file to move it elsewhere).
const (
	backupKind      = "super-nginx-backup"
	instanceKeyPath = "/data/db/export.key"
)

type encBackup struct {
	Kind       string `json:"kind"`
	Cipher     string `json:"cipher"` // aes-256-gcm
	KDF        string `json:"kdf"`    // argon2id | instance
	Salt       []byte `json:"salt,omitempty"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func argonKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// instanceKey loads (or creates once) the per-instance backup key.
func instanceKey() ([]byte, error) {
	if b, err := os.ReadFile(instanceKeyPath); err == nil && len(b) == 32 {
		return b, nil
	}
	k, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(instanceKeyPath, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func seal(key, plain []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plain, nil), nil
}

func encryptBackup(plain []byte, password string) ([]byte, error) {
	var key []byte
	e := encBackup{Kind: backupKind, Cipher: "aes-256-gcm"}
	if password != "" {
		salt, err := randomBytes(16)
		if err != nil {
			return nil, err
		}
		key = argonKey(password, salt)
		e.KDF, e.Salt = "argon2id", salt
	} else {
		k, err := instanceKey()
		if err != nil {
			return nil, err
		}
		key, e.KDF = k, "instance"
	}
	nonce, ct, err := seal(key, plain)
	if err != nil {
		return nil, err
	}
	e.Nonce, e.Ciphertext = nonce, ct
	return json.MarshalIndent(&e, "", "  ")
}

func decryptBackup(blob []byte, password string) ([]byte, error) {
	var e encBackup
	if err := json.Unmarshal(blob, &e); err != nil {
		return nil, fmt.Errorf("not a super-nginx backup file")
	}
	if e.Kind != backupKind {
		return nil, fmt.Errorf("unexpected backup kind %q", e.Kind)
	}
	var key []byte
	switch e.KDF {
	case "argon2id":
		if password == "" {
			return nil, fmt.Errorf("this backup is password-protected — provide the password")
		}
		key = argonKey(password, e.Salt)
	case "instance":
		k, err := instanceKey()
		if err != nil {
			return nil, err
		}
		key = k
	default:
		return nil, fmt.Errorf("unknown kdf %q", e.KDF)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, e.Nonce, e.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed — wrong password or corrupt file")
	}
	return plain, nil
}
