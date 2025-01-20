package errorz

import "errors"

var (
	ErrPasswordLength       = errors.New("password length must be longer 6 and shorter than 256 characters")
	ErrLoginAlreadyExists   = errors.New("login already exists")
	ErrJWTSecretKeyRequired = errors.New("JWT SecretKey is required")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrPostgresClientMissed = errors.New("pgClient cannot be nil when store is not provided")
	ErrInvalidEmailFormat   = errors.New("invalid email format")
	ErrEmailNotConfirmed    = errors.New("email not confirmed")
	ErrEmailAlreadyVerified = errors.New("email already verified")
)
