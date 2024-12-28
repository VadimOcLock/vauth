package auth

import (
	"context"
	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/github.com/VadimOcLock/vauth/pkg/pg"
	"github.com/matchsystems/werr"
)

type Service struct {
	store      store.Store
	jwtCreator jwtgen.Creator
}

type Config struct {
	DatabaseDSN string
	JWTConfig   jwtgen.Config
}

func NewService(cfg Config) (*Service, error) {
	ctx := context.TODO()

	if cfg.DatabaseDSN == "" {
		return nil, werr.Wrap(errorz.ErrDatabaseDSNRequired)
	}

	jwtCreator, err := jwtgen.NewCreator(cfg.JWTConfig)
	if err != nil {
		return nil, werr.Wrap(err)
	}

	pgClient, err := pg.New(ctx, pg.Config{
		DSN: cfg.DatabaseDSN,
	})
	if err != nil {
		return nil, werr.Wrap(err)
	}

	return &Service{
		store:      store.New(pgClient),
		jwtCreator: jwtCreator,
	}, werr.Wrap(err)
}
