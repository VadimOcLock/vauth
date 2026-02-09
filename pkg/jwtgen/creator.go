package jwtgen

import (
	"time"

	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/matchsystems/werr"
)

type Creator interface {
	CreateAccessToken(userID string) (Token, error)
	CreateRefreshToken(userID string) (Token, error)
	CreateResetToken(email string) (Token, error)
	CreateVerifyToken(email string) (Token, error)
}

type creatorImpl struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	resetTokenTTL   time.Duration
	verifyTokenTTL  time.Duration
}

var _ Creator = (*creatorImpl)(nil)

type CreatorConfig struct {
	SecretKey []byte
	TokenOpts []CreatorOption
}

func NewCreator(cfg CreatorConfig) (Creator, error) {
	if len(cfg.SecretKey) == 0 {
		return nil, werr.Wrap(errorz.ErrJWTSecretKeyRequired)
	}

	creator := &creatorImpl{
		secretKey:       cfg.SecretKey,
		accessTokenTTL:  defaultAccessTokenTTL,
		refreshTokenTTL: defaultRefreshTokenTTL,
		resetTokenTTL:   defaultResetTokenTTL,
		verifyTokenTTL:  defaultVerifyTokenTTL,
	}

	for _, opt := range cfg.TokenOpts {
		opt(creator)
	}

	return creator, nil
}

const (
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
	defaultResetTokenTTL   = 1 * time.Hour
	defaultVerifyTokenTTL  = 24 * time.Hour
)

type CreatorOption func(*creatorImpl)

func WithAccessTokenTTL(ttl time.Duration) CreatorOption {
	return func(c *creatorImpl) {
		c.accessTokenTTL = ttl
	}
}

func WithRefreshTokenTTL(ttl time.Duration) CreatorOption {
	return func(c *creatorImpl) {
		c.refreshTokenTTL = ttl
	}
}

func WithResetTokenTTL(ttl time.Duration) CreatorOption {
	return func(c *creatorImpl) {
		c.resetTokenTTL = ttl
	}
}

func WithVerifyTokenTTL(ttl time.Duration) CreatorOption {
	return func(c *creatorImpl) {
		c.verifyTokenTTL = ttl
	}
}
