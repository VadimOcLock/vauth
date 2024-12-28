package store

import (
	"context"
	"errors"
	"github.com/github.com/VadimOcLock/vauth/internal/store/pgstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/matchsystems/werr"
)

type PgStore interface {
	pgstore.Querier
}

type PgClient interface {
	pgstore.DBTX

	Begin(ctx context.Context) (pgx.Tx, error)
}

func NewPgStore(client PgClient) PgStore {
	return PgStore(pgstore.New(client))
}

func (s Impl) PgTx(ctx context.Context, handler func(tx pgx.Tx, stx Store) error) error {
	tx, err := s.PgClient.Begin(ctx)
	if err != nil {
		return werr.Wrap(err)
	}

	s.PgStore = NewPgStore(tx)
	err = werr.Wrap(handler(tx, s))

	if err == nil {
		err = werr.Wrap(tx.Commit(ctx))
	} else {
		err = errors.Join(err, tx.Rollback(ctx))
	}

	return werr.Wrap(err)
}

func NewUUID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}
