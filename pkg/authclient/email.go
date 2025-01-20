package authclient

import (
	"context"
	"errors"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
)

type SendConfirmationEmailParams struct {
	Email string
}

func (dto SendConfirmationEmailParams) Validate() error {
	if !emailRegex.MatchString(dto.Email) {
		return errorz.ErrInvalidEmailFormat
	}

	return nil
}

func (c Client) SendConfirmationEmail(ctx context.Context, dto SendConfirmationEmailParams) error {
	if err := dto.Validate(); err != nil {
		return werr.Wrap(err)
	}

	user, err := c.store.FindUserByEmail(ctx, dto.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return werr.Wrap(errorz.ErrInvalidCredentials)
		}

		return werr.Wrap(err)
	}
	if user.Entity().IsVerified {
		return werr.Wrap(errorz.ErrEmailAlreadyVerified)
	}

	confirmCode, err := c.codeGenerator.GenerateConfirmationCode()
	if err != nil {
		return werr.Wrap(err)
	}

	if _, err = c.store.CreateEmailConfirmation(ctx, store.CreateEmailConfirmationDTO{
		UserID:           user.ID,
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

type ConfirmEmailParams struct {
	Code string
}

func (c Client) ConfirmEmail(ctx context.Context, dto ConfirmEmailParams) error {
	user, err := c.store.FindUserByConfirmationCode(ctx, dto.Code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return werr.Wrap(errorz.ErrInvalidCredentials)
		}

		return werr.Wrap(err)
	}

	if user.Entity().IsVerified {
		return werr.Wrap(errorz.ErrEmailAlreadyVerified)
	}

	if err = c.store.UpdateUserAsVerified(ctx, user.Entity().Email); err != nil {
		return werr.Wrap(err)
	}

	return nil
}
