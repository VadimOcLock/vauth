package entity

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Permissions  []string
	IsActive     bool
	IsVerified   bool
}
