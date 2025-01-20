package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Store interface {
	ExistsUserByLogin(ctx context.Context, login string) (bool, error)
	CreateUser(ctx context.Context, dto CreateUserDTO) (uuid.UUID, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
	CreateToken(ctx context.Context, dto CreateTokenDTO) (uuid.UUID, error)
	CreateEmailConfirmation(ctx context.Context, dto CreateEmailConfirmationDTO) (uuid.UUID, error)
	RegisterUserWithConfirmation(ctx context.Context, dto RegisterUserWithConfirmationDTO) error
	FindUserByConfirmationCode(ctx context.Context, code string) (User, error)
	UpdateUserAsVerified(ctx context.Context, email string) error
	UpdateUserPassword(ctx context.Context, dto UpdateUserPasswordDTO) error

	PgTx(ctx context.Context, handler func(tx pgx.Tx, stx Store) error) error
}

type Impl struct {
	PgClient
	PgStore
}

var _ Store = (*Impl)(nil)

func New(pgClient PgClient) Impl {
	return Impl{
		PgClient: pgClient,
		PgStore:  NewPgStore(pgClient),
	}
}
