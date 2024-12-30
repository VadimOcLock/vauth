package authservice

import (
	"context"
	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/matchsystems/werr"
	"strings"
)

type RegisterParams struct {
	Email       string
	Password    string
	Permissions []string
}

func (dto RegisterParams) Validate() error {
	if strings.TrimSpace(dto.Email) == "" {
		return errorz.ErrLoginMustNotBeEmpty
	}
	if strings.Contains(dto.Email, " ") {
		return errorz.ErrLoginMustNotContainsSpace
	}
	if !strings.Contains(dto.Email, "@") {
		return errorz.ErrLoginMustContainsAtSymbol
	}
	if len(dto.Password) < 6 || len(dto.Password) > 256 {
		return errorz.ErrPasswordLength
	}

	return nil
}

func (s Service) Register(ctx context.Context, dto RegisterParams) (string, error) {
	if err := dto.Validate(); err != nil {
		return "", werr.Wrap(err)
	}

	exists, err := s.store.ExistsUserByLogin(ctx, dto.Email)
	if err != nil {
		return "", werr.Wrap(err)
	}
	if exists {
		return "", werr.Wrap(errorz.ErrLoginAlreadyExists)
	}

	passHash, err := hashPasswordSHA256(dto.Password)
	if err != nil {
		return "", werr.Wrap(err)
	}

	userID, err := s.store.CreateUser(ctx, store.CreateUserDTO{
		Email:        dto.Email,
		PasswordHash: passHash,
		Permissions:  dto.Permissions,
	})
	if err != nil {
		return "", werr.Wrap(err)
	}

	token, err := s.jwtCreator.CreateAccessToken(userID.String(), dto.Permissions)
	if err != nil {
		return "", werr.Wrap(err)
	}

	return token, nil
}
