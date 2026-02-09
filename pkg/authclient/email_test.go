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
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SendConfirmationEmail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful email confirmation", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
				EmailSenderHook: func(ctx context.Context, email string, code string) error {
					return nil
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()
		confirmationCode := "123456"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(codegen.Code{
			Code:      confirmationCode,
			ExpiresAt: expiresAt,
		}, nil)
		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: confirmationCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.New(), nil)

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: email,
		})

		require.NoError(t, err)
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)

		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: "invalid_email",
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidEmailFormat)
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
			},
			authclient.WithStore(mockStore),
		)
		require.NoError(t, err)

		email := "notfound@example.com"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{}, pgx.ErrNoRows)

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: email,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
	})

	t.Run("email already verified", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)

		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		email := "verified@example.com"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: email,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrEmailAlreadyVerified)
		mockStore.AssertExpectations(t)
	})

	t.Run("confirmation code generation error", func(t *testing.T) {
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

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(codegen.Code{}, errors.New("code generation error"))

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: email,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "code generation error")
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
		confirmationCode := "123456"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(codegen.Code{
			Code:      confirmationCode,
			ExpiresAt: expiresAt,
		}, nil)
		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: confirmationCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.UUID{}, errors.New("database error"))

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
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
				EmailSenderHook: func(ctx context.Context, email string, code string) error {
					return errors.New("email sending error")
				},
			},
			authclient.WithStore(mockStore),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		userID := uuid.New()
		confirmationCode := "123456"
		expiresAt := time.Now().Add(15 * time.Minute)

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(codegen.Code{
			Code:      confirmationCode,
			ExpiresAt: expiresAt,
		}, nil)
		mockStore.On("CreateEmailConfirmation", ctx, store.CreateEmailConfirmationDTO{
			UserID:           userID,
			ConfirmationCode: confirmationCode,
			ExpiresAt:        expiresAt,
		}).Return(uuid.New(), nil)

		err = client.SendConfirmationEmail(ctx, authclient.SendConfirmationEmailParams{
			Email: email,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "email sending error")
		mockStore.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})
}

func TestClient_ConfirmEmail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful email confirmation", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		confirmationCode := "123456"
		email := "test@example.com"
		userID := uuid.New()

		mockStore.On("FindUserByConfirmationCode", ctx, confirmationCode).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)

		mockStore.On("UpdateUserAsVerified", ctx, email).Return(nil)

		err = client.ConfirmEmail(ctx, authclient.ConfirmEmailParams{
			Code: confirmationCode,
		})

		require.NoError(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("invalid confirmation code", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		confirmationCode := "invalid_code"

		mockStore.On("FindUserByConfirmationCode", ctx, confirmationCode).Return(store.User{}, pgx.ErrNoRows)

		err = client.ConfirmEmail(ctx, authclient.ConfirmEmailParams{
			Code: confirmationCode,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
	})

	t.Run("user already verified", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		confirmationCode := "123456"
		email := "test@example.com"
		userID := uuid.New()

		mockStore.On("FindUserByConfirmationCode", ctx, confirmationCode).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		err = client.ConfirmEmail(ctx, authclient.ConfirmEmailParams{
			Code: confirmationCode,
		})

		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrEmailAlreadyVerified)
		mockStore.AssertExpectations(t)
	})

	t.Run("database error when finding user", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		confirmationCode := "123456"

		mockStore.On("FindUserByConfirmationCode", ctx, confirmationCode).Return(store.User{}, errors.New("database error"))

		err = client.ConfirmEmail(ctx, authclient.ConfirmEmailParams{
			Code: confirmationCode,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		mockStore.AssertExpectations(t)
	})

	t.Run("database error when updating user", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		confirmationCode := "123456"
		email := "test@example.com"
		userID := uuid.New()

		mockStore.On("FindUserByConfirmationCode", ctx, confirmationCode).Return(store.User{
			ID:         userID,
			Email:      email,
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)

		mockStore.On("UpdateUserAsVerified", ctx, email).Return(errors.New("database error"))

		err = client.ConfirmEmail(ctx, authclient.ConfirmEmailParams{
			Code: confirmationCode,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		mockStore.AssertExpectations(t)
	})
}
