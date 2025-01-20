package store

import (
	"context"
	"time"

	"github.com/github.com/VadimOcLock/vauth/internal/store/pgstore"
	"github.com/github.com/VadimOcLock/vauth/pkg/entity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
)

type User pgstore.User

func (m User) Entity() entity.User {
	return entity.User{
		ID:           m.ID,
		Email:        m.Email,
		PasswordHash: m.Email,
		CreatedAt:    m.CreatedAt.Time,
		UpdatedAt:    m.UpdatedAt.Time,
		IsVerified:   m.IsVerified.Bool,
	}
}

func (s Impl) ExistsUserByLogin(ctx context.Context, login string) (bool, error) {
	exists, err := s.PgStore.ExistsUserByEmail(ctx, login)

	return exists, werr.Wrap(err)
}

type CreateUserDTO struct {
	Email        string
	PasswordHash string
}

func (s Impl) CreateUser(ctx context.Context, dto CreateUserDTO) (uuid.UUID, error) {
	id := NewUUID()
	newID, err := s.PgStore.CreateUser(ctx, pgstore.CreateUserParams{
		ID:           id,
		Email:        dto.Email,
		PasswordHash: dto.PasswordHash,
	})
	if err != nil {
		return uuid.Nil, werr.Wrap(err)
	}

	return newID, nil
}

func (s Impl) FindUserByEmail(ctx context.Context, email string) (User, error) {
	user, err := s.PgStore.FindUserByEmail(ctx, email)

	return User(user), werr.Wrap(err)
}

type RegisterUserWithConfirmationDTO struct {
	Email            string
	PasswordHash     string
	ConfirmationCode string
	ExpiresAt        time.Time
}

func (s Impl) RegisterUserWithConfirmation(
	ctx context.Context,
	dto RegisterUserWithConfirmationDTO,
) error {
	return s.PgTx(ctx, func(tx pgx.Tx, stx Store) error {
		userID, err := stx.CreateUser(ctx, CreateUserDTO{
			Email:        dto.Email,
			PasswordHash: dto.PasswordHash,
		})
		if err != nil {
			return werr.Wrap(err)
		}
		if _, err = stx.CreateEmailConfirmation(ctx, CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: dto.ConfirmationCode,
			ExpiresAt:        dto.ExpiresAt,
		}); err != nil {
			return werr.Wrap(err)
		}

		return nil
	})
}

func (s Impl) UpdateUserAsVerified(ctx context.Context, email string) error {
	if _, err := s.PgStore.UpdateUserAsVerified(ctx, email); err != nil {
		return werr.Wrap(err)
	}

	return nil
}

func (s Impl) FindUserByConfirmationCode(ctx context.Context, code string) (User, error) {
	user, err := s.PgStore.FindUserByConfirmationCode(ctx, code)
	if err != nil {
		return User{}, werr.Wrap(err)
	}

	return User(user), nil
}

type UpdateUserPasswordDTO struct {
	Email        string
	PasswordHash string
}

func (s Impl) UpdateUserPassword(ctx context.Context, dto UpdateUserPasswordDTO) error {
	if _, err := s.PgStore.UpdateUserPassword(ctx, pgstore.UpdateUserPasswordParams{
		PasswordHash: dto.PasswordHash,
		Email:        dto.Email,
	}); err != nil {
		return werr.Wrap(err)
	}

	return nil
}
