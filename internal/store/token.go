package store

import (
	"context"
	"time"

	"github.com/github.com/VadimOcLock/vauth/internal/store/pgstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matchsystems/werr"
)

type CreateTokenDTO struct {
	UserID    uuid.UUID
	Token     string
	ExpiresAt time.Time
}

func (s Impl) CreateToken(ctx context.Context, dto CreateTokenDTO) (uuid.UUID, error) {
	id := NewUUID()
	newID, err := s.PgStore.CreateToken(ctx, pgstore.CreateTokenParams{
		ID:     id,
		UserID: dto.UserID,
		Token:  dto.Token,
		ExpiresAt: pgtype.Timestamp{
			Time:             dto.ExpiresAt,
			InfinityModifier: 0,
			Valid:            true,
		},
	})
	if err != nil {
		return uuid.Nil, werr.Wrap(err)
	}

	return newID, nil
}
