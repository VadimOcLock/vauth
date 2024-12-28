package errorz

import "errors"

var (
	ErrLoginMustNotBeEmpty          = errors.New("login must not be empty")
	ErrLoginMustNotContainsSpace    = errors.New("login must not contains space")
	ErrLoginMustContainsAtSymbol    = errors.New("login must contains at symbol")
	ErrPasswordLength               = errors.New("password length must be longer 6 and shorter than 256 characters")
	ErrPasswordMustNotContainsSpace = errors.New("password must not contains space")
	ErrPasswordMustNotBeEmpty       = errors.New("password must not be empty")
	ErrLoginAlreadyExists           = errors.New("login already exists")
	ErrDatabaseDSNRequired          = errors.New("DatabaseDSN is required")
	ErrJWTSecretKeyRequired         = errors.New("JWT SecretKey is required")
	ErrInvalidCredentials           = errors.New("invalid credentials")
	ErrTokenDuration                = errors.New("token durations must be greater than zero")
)
