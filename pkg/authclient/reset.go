package authclient

import (
	"context"
	"errors"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
)

type ForgotPasswordParams struct {
	Email string
}

func (dto ForgotPasswordParams) Validate() error {
	if !emailRegex.MatchString(dto.Email) {
		return errorz.ErrInvalidEmailFormat
	}

	return nil
}

func (c Client) ForgotPassword(ctx context.Context, dto ForgotPasswordParams) error {
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

	if !user.Entity().IsVerified {
		return werr.Wrap(errorz.ErrEmailNotConfirmed)
	}

	resetCode, err := c.codeGenerator.GenerateResetCode()
	if err != nil {
		return werr.Wrap(err)
	}

	if _, err = c.store.CreateEmailConfirmation(ctx, store.CreateEmailConfirmationDTO{
		UserID:           user.ID,
		ConfirmationCode: resetCode.Code,
		ExpiresAt:        resetCode.ExpiresAt,
	}); err != nil {
		return werr.Wrap(err)
	}

	if err = c.sendEmailFn(ctx, dto.Email, resetCode.Code); err != nil {
		return werr.Wrap(err)
	}

	return nil
}

type ResetPasswordParams struct {
	Code     string
	Password string
}

func (dto ResetPasswordParams) Validate() error {
	if len(dto.Password) < 6 || len(dto.Password) > 256 {
		return errorz.ErrPasswordLength
	}

	return nil
}

func (c Client) ResetPassword(ctx context.Context, dto ResetPasswordParams) error {
	if err := dto.Validate(); err != nil {
		return werr.Wrap(err)
	}

	user, err := c.store.FindUserByConfirmationCode(ctx, dto.Code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return werr.Wrap(errorz.ErrInvalidCredentials)
		}

		return werr.Wrap(err)
	}

	newPasswordHash, err := c.hasher.HashPassword(dto.Password)
	if err != nil {
		return werr.Wrap(err)
	}

	if err = c.store.UpdateUserPassword(ctx, store.UpdateUserPasswordDTO{
		Email:        user.Email,
		PasswordHash: newPasswordHash,
	}); err != nil {
		return werr.Wrap(err)
	}

	return nil
}
