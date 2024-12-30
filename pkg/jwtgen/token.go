package jwtgen

import (
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matchsystems/werr"
	"time"
)

type Creator interface {
	CreateAccessToken(userID string, permissions []string) (string, error)
	CreateRefreshToken(userID string) (string, error)
	CreateResetToken(email string) (string, error)
	CreateVerifyToken(email string) (string, error)
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

type creatorImpl struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	resetTokenTTL   time.Duration
	verifyTokenTTL  time.Duration
}

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

func (c creatorImpl) createToken(claims jwt.MapClaims, ttl time.Duration) (string, error) {
	claims["exp"] = time.Now().Add(ttl).Unix()
	claims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(c.secretKey)
	if err != nil {
		return "", werr.Wrap(err)
	}

	return signedToken, nil
}

func (c creatorImpl) CreateAccessToken(userID string, permissions []string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":     userID,
		"permissions": permissions,
	}

	return c.createToken(claims, c.accessTokenTTL)
}

func (c creatorImpl) CreateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
	}

	return c.createToken(claims, c.refreshTokenTTL)
}

func (c creatorImpl) CreateResetToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
	}

	return c.createToken(claims, c.resetTokenTTL)
}

func (c creatorImpl) CreateVerifyToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
	}

	return c.createToken(claims, c.verifyTokenTTL)
}
