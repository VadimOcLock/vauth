package store

import (
	"context"
	"time"

	"github.com/github.com/VadimOcLock/vauth/internal/store/pgstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matchsystems/werr"
)

type CreateEmailConfirmationDTO struct {
	UserID           uuid.UUID
	ConfirmationCode string
	ExpiresAt        time.Time
}

func (s Impl) CreateEmailConfirmation(ctx context.Context, dto CreateEmailConfirmationDTO) (uuid.UUID, error) {
	id := NewUUID()
	newID, err := s.PgStore.CreateEmailConfirmation(ctx, pgstore.CreateEmailConfirmationParams{
		ID: id,
		UserID: uuid.NullUUID{
			UUID:  dto.UserID,
			Valid: true,
		},
		Code: dto.ConfirmationCode,
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
