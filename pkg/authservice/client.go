package authservice

import (
	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matchsystems/werr"
)

type Service struct {
	store      store.Store
	jwtCreator jwtgen.Creator
}

type Config struct {
	PgClient  *pgxpool.Pool
	JWTConfig jwtgen.CreatorConfig
}

func NewClient(cfg Config) (*Service, error) {
	jwtCreator, err := jwtgen.NewCreator(cfg.JWTConfig)
	if err != nil {
		return nil, werr.Wrap(err)
	}

	return &Service{
		store:      store.New(cfg.PgClient),
		jwtCreator: jwtCreator,
	}, werr.Wrap(err)
}
