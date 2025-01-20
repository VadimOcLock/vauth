package authclient

import (
	"context"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	"github.com/github.com/VadimOcLock/vauth/pkg/codegen"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	"github.com/github.com/VadimOcLock/vauth/pkg/hash"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matchsystems/werr"
)

type Client struct {
	store         store.Store
	jwtCreator    jwtgen.Creator
	hasher        hash.Hasher
	codeGenerator codegen.Generator
	sendEmailFn   SendEmailFn
}

type Config struct {
	PgClient     *pgxpool.Pool
	JWTConfig    jwtgen.CreatorConfig
	HasherConfig hash.Config
	SendEmailFn  SendEmailFn
}

type SendEmailFn func(ctx context.Context, email string, code string) error

type Option func(*Client) error

func WithStore(s store.Store) Option {
	return func(c *Client) error {
		c.store = s

		return nil
	}
}

func WithJWTCreator(creator jwtgen.Creator) Option {
	return func(c *Client) error {
		c.jwtCreator = creator

		return nil
	}
}

func WithHasher(hasher hash.Hasher) Option {
	return func(c *Client) error {
		c.hasher = hasher

		return nil
	}
}

func WithCodeGenerator(codeGen codegen.Generator) Option {
	return func(c *Client) error {
		c.codeGenerator = codeGen

		return nil
	}
}

func New(cfg Config, options ...Option) (*Client, error) {
	client := &Client{
		sendEmailFn: cfg.SendEmailFn,
	}

	for _, opt := range options {
		if err := opt(client); err != nil {
			return nil, werr.Wrap(err)
		}
	}
	if client.store == nil {
		if cfg.PgClient == nil {
			return nil, werr.Wrap(errorz.ErrPostgresClientMissed)
		}
		client.store = store.New(cfg.PgClient)
	}
	if client.jwtCreator == nil {
		creator, err := jwtgen.NewCreator(cfg.JWTConfig)
		if err != nil {
			return nil, werr.Wrap(err)
		}
		client.jwtCreator = creator
	}
	if client.hasher == nil {
		client.hasher = hash.NewHasher(cfg.HasherConfig)
	}
	if client.codeGenerator == nil {
		client.codeGenerator = codegen.NewGenerator()
	}

	return client, nil
}
