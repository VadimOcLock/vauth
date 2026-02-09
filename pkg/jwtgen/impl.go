package jwtgen

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/matchsystems/werr"
)

func (c creatorImpl) createToken(claims jwt.MapClaims, ttl time.Duration) (Token, error) {
	expAt := time.Now().Add(ttl)
	claims["exp"] = expAt.Unix()
	claims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(c.secretKey)
	if err != nil {
		return Token{}, werr.Wrap(err)
	}

	return Token{
		Token:     signedToken,
		ExpiresAt: expAt,
	}, nil
}

func (c creatorImpl) CreateAccessToken(userID string) (Token, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
	}

	return c.createToken(claims, c.accessTokenTTL)
}

func (c creatorImpl) CreateRefreshToken(userID string) (Token, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
	}

	return c.createToken(claims, c.refreshTokenTTL)
}

func (c creatorImpl) CreateResetToken(email string) (Token, error) {
	claims := jwt.MapClaims{
		"email": email,
	}

	return c.createToken(claims, c.resetTokenTTL)
}

func (c creatorImpl) CreateVerifyToken(email string) (Token, error) {
	claims := jwt.MapClaims{
		"email": email,
	}

	return c.createToken(claims, c.verifyTokenTTL)
}
