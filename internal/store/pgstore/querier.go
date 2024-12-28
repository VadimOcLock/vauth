// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package pgstore

import (
	"context"

	"github.com/google/uuid"
)

type Querier interface {
	CreateUser(ctx context.Context, arg CreateUserParams) (uuid.UUID, error)
	ExistsUserByEmail(ctx context.Context, email string) (bool, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

var _ Querier = (*Queries)(nil)