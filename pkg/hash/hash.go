package hash

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/matchsystems/werr"
)

type Hasher interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(password string, hash string) (bool, error)
}

type hasherImpl struct {
}

type Config struct {
}

// todo: passhash, New

func NewHasher(cfg Config) Hasher {
	return &hasherImpl{}
}

func (h hasherImpl) HashPassword(password string) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write([]byte(password)); err != nil {
		return "", werr.Wrap(err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (h hasherImpl) CheckPasswordHash(password string, hash string) (bool, error) {
	hashedPassword, err := h.HashPassword(password)

	return hashedPassword == hash, err
}
