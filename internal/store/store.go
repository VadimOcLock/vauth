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
