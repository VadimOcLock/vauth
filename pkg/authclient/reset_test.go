package authclient_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	storemocks "github.com/github.com/VadimOcLock/vauth/internal/store/mocks"
	"github.com/github.com/VadimOcLock/vauth/pkg/authclient"
	"github.com/github.com/VadimOcLock/vauth/pkg/codegen"
	codegenmocks "github.com/github.com/VadimOcLock/vauth/pkg/codegen/mocks"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	hashermocks "github.com/github.com/VadimOcLock/vauth/pkg/hash/mocks"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_ForgotPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful password reset request", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
				SendEmailFn: func(ctx context.Context, email string, code string) error {
					return nil
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()
		resetCode := "654321"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		mockCodeGenerator.On("GenerateResetCode").Return(codegen.Code{
			Code:      resetCode,
			ExpiresAt: expiresAt,
		}, nil)

		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: resetCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.New(), nil)

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.NoError(t, err)
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})

	t.Run("invalid email format", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: "invalid_email",
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidEmailFormat)
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		email := "notfound@example.com"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{}, pgx.ErrNoRows)

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
	})

	t.Run("email not confirmed", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		email := "unverified@example.com"
		userID := uuid.New()

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrEmailNotConfirmed)
		mockStore.AssertExpectations(t)
	})

	t.Run("reset code generation error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		mockCodeGenerator.On("GenerateResetCode").Return(codegen.Code{}, errors.New("reset code generation error"))

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "reset code generation error")
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()
		resetCode := "654321"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		mockCodeGenerator.On("GenerateResetCode").Return(codegen.Code{
			Code:      resetCode,
			ExpiresAt: expiresAt,
		}, nil)

		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: resetCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.UUID{}, errors.New("database error"))

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})

	t.Run("email sending error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
				SendEmailFn: func(ctx context.Context, email string, code string) error {
					return errors.New("email sending error")
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()
		resetCode := "654321"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		mockCodeGenerator.On("GenerateResetCode").Return(codegen.Code{
			Code:      resetCode,
			ExpiresAt: expiresAt,
		}, nil)

		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: resetCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.New(), nil)

		err = client.ForgotPassword(ctx, authclient.ForgotPasswordParams{
			Email: email,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "email sending error")
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})
}

func TestClient_ResetPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful password reset", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		code := "123456"
		password := "newPassword123"
		userEmail := "user@example.com"
		userID := uuid.New()
		passwordHash := "hashedNewPassword"

		mockStore.On("FindUserByConfirmationCode", ctx, code).Return(store.User{
			ID:    userID,
			Email: userEmail,
		}, nil)

		mockHasher.On("HashPassword", password).Return(passwordHash, nil)

		mockStore.On("UpdateUserPassword", ctx, store.UpdateUserPasswordDTO{
			Email:        userEmail,
			PasswordHash: passwordHash,
		}).Return(nil)

		err = client.ResetPassword(ctx, authclient.ResetPasswordParams{
			Code:     code,
			Password: password,
		})

		require.NoError(t, err)
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("invalid password length", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		err = client.ResetPassword(ctx, authclient.ResetPasswordParams{
			Code:     "validCode",
			Password: "short",
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrPasswordLength)
	})

	t.Run("user not found by confirmation code", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		code := "invalidCode"

		mockStore.On("FindUserByConfirmationCode", ctx, code).Return(store.User{}, pgx.ErrNoRows)

		err = client.ResetPassword(ctx, authclient.ResetPasswordParams{
			Code:     code,
			Password: "newPassword123",
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
	})

	t.Run("password hashing error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		code := "validCode"
		password := "newPassword123"

		mockStore.On("FindUserByConfirmationCode", ctx, code).Return(store.User{
			ID:    uuid.New(),
			Email: "user@example.com",
		}, nil)

		mockHasher.On("HashPassword", password).Return("", errors.New("hashing error"))

		err = client.ResetPassword(ctx, authclient.ResetPasswordParams{
			Code:     code,
			Password: password,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "hashing error")
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("database error on password update", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		code := "validCode"
		password := "newPassword123"
		userEmail := "user@example.com"
		passwordHash := "hashedNewPassword"

		mockStore.On("FindUserByConfirmationCode", ctx, code).Return(store.User{
			ID:    uuid.New(),
			Email: userEmail,
		}, nil)

		mockHasher.On("HashPassword", password).Return(passwordHash, nil)

		mockStore.On("UpdateUserPassword", ctx, store.UpdateUserPasswordDTO{
			Email:        userEmail,
			PasswordHash: passwordHash,
		}).Return(errors.New("database error"))

		err = client.ResetPassword(ctx, authclient.ResetPasswordParams{
			Code:     code,
			Password: password,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}
