package auth

import (
	"context"
	"errors"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
	"strings"
)

type LoginParams struct {
	Email    string
	Password string
}

func (dto LoginParams) Validate() error {
	if strings.TrimSpace(dto.Email) == "" {
		return errorz.ErrLoginMustNotBeEmpty
	}
	if strings.TrimSpace(dto.Password) == "" {
		return errorz.ErrPasswordMustNotBeEmpty
	}

	return nil
}

func (s Service) Login(ctx context.Context, dto LoginParams) (string, error) {
	if err := dto.Validate(); err != nil {
		return "", werr.Wrap(err)
	}
	user, err := s.store.FindUserByEmail(ctx, dto.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", werr.Wrap(errorz.ErrInvalidCredentials)
		}
		return "", werr.Wrap(err)
	}

	equals, err := checkPasswordHash(dto.Password, user.PasswordHash)
	if err != nil {
		return "", werr.Wrap(err)
	}
	if !equals {
		return "", errorz.ErrInvalidCredentials
	}

	token, err := s.jwtCreator.CreateAccessToken(user.ID.String(), user.Entity().Permissions)
	if err != nil {
		return "", werr.Wrap(err)
	}

	return token, nil
}
