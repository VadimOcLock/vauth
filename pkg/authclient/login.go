package authclient

import (
	"context"
	"errors"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
)

type LoginParams struct {
	Email    string
	Password string
}

func (dto LoginParams) Validate() error {
	if len(dto.Password) < 6 || len(dto.Password) > 256 {
		return errorz.ErrPasswordLength
	}
	if !emailRegex.MatchString(dto.Email) {
		return errorz.ErrInvalidEmailFormat
	}

	return nil
}

func (c Client) Login(ctx context.Context, dto LoginParams) (string, error) {
	if err := dto.Validate(); err != nil {
		return "", werr.Wrap(err)
	}
	user, err := c.store.FindUserByEmail(ctx, dto.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", werr.Wrap(errorz.ErrInvalidCredentials)
		}

		return "", werr.Wrap(err)
	}
	if !user.Entity().IsVerified {
		return "", werr.Wrap(errorz.ErrEmailNotConfirmed)
	}

	equals, err := c.hasher.CheckPasswordHash(dto.Password, user.PasswordHash)
	if err != nil {
		return "", werr.Wrap(err)
	}
	if !equals {
		return "", werr.Wrap(errorz.ErrInvalidCredentials)
	}

	token, err := c.jwtCreator.CreateAccessToken(user.ID.String())
	if err != nil {
		return "", werr.Wrap(err)
	}

	_, err = c.store.CreateToken(ctx, store.CreateTokenDTO{
		UserID:    user.ID,
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt,
	})
	if err != nil {
		return "", werr.Wrap(err)
	}

	return token.Token, nil
}
