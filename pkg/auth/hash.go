package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/matchsystems/werr"
)

func hashPasswordSHA256(password string) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write([]byte(password)); err != nil {
		return "", werr.Wrap(err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkPasswordHash(password string, hash string) (bool, error) {
	hashedPassword, err := hashPasswordSHA256(password)

	return hashedPassword == hash, err
}
