package authclient

import (
	"context"
	"regexp"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/matchsystems/werr"
)

type RegisterParams struct {
	Email    string
	Password string
}

var emailRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func (dto RegisterParams) Validate() error {
	if len(dto.Password) < 6 || len(dto.Password) > 256 {
		return errorz.ErrPasswordLength
	}
	if !emailRegex.MatchString(dto.Email) {
		return errorz.ErrInvalidEmailFormat
	}

	return nil
}

func (c Client) Register(ctx context.Context, dto RegisterParams) error {
	if err := dto.Validate(); err != nil {
		return werr.Wrap(err)
	}

	if err := c.checkUserExistence(ctx, dto.Email); err != nil {
		return werr.Wrap(err)
	}
	passHash, err := c.hasher.HashPassword(dto.Password)
	if err != nil {
		return werr.Wrap(err)
	}
	confirmCode, err := c.codeGenerator.GenerateConfirmationCode()
	if err != nil {
		return werr.Wrap(err)
	}
	if err = c.store.RegisterUserWithConfirmation(ctx, store.RegisterUserWithConfirmationDTO{
		Email:            dto.Email,
		PasswordHash:     passHash,
		ConfirmationCode: confirmCode.Code,
		ExpiresAt:        confirmCode.ExpiresAt,
	}); err != nil {
		return werr.Wrap(err)
	}
	if err = c.sendEmailFn(ctx, dto.Email, confirmCode.Code); err != nil {
		return werr.Wrap(err)
	}

	return nil
}

func (c Client) checkUserExistence(ctx context.Context, email string) error {
	exists, err := c.store.ExistsUserByLogin(ctx, email)
	if err != nil {
		return werr.Wrap(err)
	}
	if exists {
		user, uErr := c.store.FindUserByEmail(ctx, email)
		if uErr != nil {
			return werr.Wrap(uErr)
		}
		if !user.Entity().IsVerified {
			return werr.Wrap(errorz.ErrEmailNotConfirmed)
		}

		return werr.Wrap(errorz.ErrLoginAlreadyExists)
	}

	return nil
}
