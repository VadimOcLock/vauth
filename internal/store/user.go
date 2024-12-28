package store

import (
	"context"
	"encoding/json"
	"github.com/github.com/VadimOcLock/vauth/internal/store/pgstore"
	"github.com/github.com/VadimOcLock/vauth/pkg/entity"
	"github.com/google/uuid"
	"github.com/matchsystems/werr"
)

type User pgstore.User

func (m User) Entity() entity.User {
	var permissions []string
	err := json.Unmarshal(m.Permissions, &permissions)
	if err != nil {
		permissions = nil
	}

	return entity.User{
		ID:           m.ID,
		Email:        m.Email,
		PasswordHash: m.Email,
		CreatedAt:    m.CreatedAt.Time,
		UpdatedAt:    m.UpdatedAt.Time,
		Permissions:  permissions,
		IsActive:     m.IsActive.Bool,
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
	Permissions  []string
}

func (s Impl) CreateUser(ctx context.Context, dto CreateUserDTO) (uuid.UUID, error) {
	permissionsJSON, err := json.Marshal(dto.Permissions)
	if err != nil {
		return uuid.Nil, werr.Wrap(err)
	}

	id := NewUUID()
	newID, err := s.PgStore.CreateUser(ctx, pgstore.CreateUserParams{
		ID:           id,
		Email:        dto.Email,
		PasswordHash: dto.PasswordHash,
		Column4:      string(permissionsJSON),
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
