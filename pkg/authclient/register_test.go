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
	jwtmocks "github.com/github.com/VadimOcLock/vauth/pkg/jwtgen/mocks"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Register(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		sendEmailFn := func(ctx context.Context, email, code string) error { return nil }

		client, err := authclient.New(
			authclient.Config{
				EmailSenderHook: sendEmailFn,
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "securepassword"
		hashedPassword := "hashed_password"
		confirmCode := codegen.Code{
			Code:      "123456",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		mockStore.On("ExistsUserByLogin", ctx, email).Return(false, nil)
		mockHasher.On("HashPassword", password).Return(hashedPassword, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(confirmCode, nil)
		mockStore.On("RegisterUserWithConfirmation", ctx, store.RegisterUserWithConfirmationDTO{
			Email:            email,
			PasswordHash:     hashedPassword,
			ConfirmationCode: confirmCode.Code,
			ExpiresAt:        confirmCode.ExpiresAt,
		}).Return(nil)

		err = client.Register(ctx, authclient.RegisterParams{
			Email:    email,
			Password: password,
		})

		require.NoError(t, err)
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
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

		err = client.Register(ctx, authclient.RegisterParams{
			Email:    "test@example.com",
			Password: "123",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrPasswordLength)
	})

	t.Run("user already exists and not verified", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		email := "test@example.com"
		mockStore.On("ExistsUserByLogin", ctx, email).Return(true, nil)
		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			IsVerified: pgtype.Bool{Bool: false, Valid: true},
		}, nil)

		err = client.Register(ctx, authclient.RegisterParams{
			Email:    email,
			Password: "securepassword",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrEmailNotConfirmed)
		mockStore.AssertExpectations(t)
	})

	t.Run("user already exists and verified", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		client, err := authclient.New(authclient.Config{
			JWTConfig: jwtgen.CreatorConfig{
				SecretKey: []byte("secret_key"),
			},
		}, authclient.WithStore(mockStore))
		require.NoError(t, err)

		email := "test@example.com"
		mockStore.On("ExistsUserByLogin", ctx, email).Return(true, nil)
		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			IsVerified: pgtype.Bool{Bool: true, Valid: true},
		}, nil)

		err = client.Register(ctx, authclient.RegisterParams{
			Email:    email,
			Password: "securepassword",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrLoginAlreadyExists)
		mockStore.AssertExpectations(t)
	})

	t.Run("email sending failure", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockHasher := hashermocks.NewHasher(t)
		mockCodeGenerator := codegenmocks.NewGenerator(t)
		sendEmailFn := func(ctx context.Context, email, code string) error {
			return errors.New("email sending failed")
		}

		client, err := authclient.New(
			authclient.Config{
				JWTConfig: jwtgen.CreatorConfig{
					SecretKey: []byte("secret_key"),
				},
				EmailSenderHook: sendEmailFn,
			},
			authclient.WithStore(mockStore),
			authclient.WithHasher(mockHasher),
			authclient.WithCodeGenerator(mockCodeGenerator),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "securepassword"
		hashedPassword := "hashed_password"
		confirmCode := codegen.Code{
			Code:      "123456",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		mockStore.On("ExistsUserByLogin", ctx, email).Return(false, nil)
		mockHasher.On("HashPassword", password).Return(hashedPassword, nil)
		mockCodeGenerator.On("GenerateConfirmationCode").Return(confirmCode, nil)
		mockStore.On("RegisterUserWithConfirmation", ctx, store.RegisterUserWithConfirmationDTO{
			Email:            email,
			PasswordHash:     hashedPassword,
			ConfirmationCode: confirmCode.Code,
			ExpiresAt:        confirmCode.ExpiresAt,
		}).Return(nil)

		err = client.Register(ctx, authclient.RegisterParams{
			Email:    email,
			Password: password,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "email sending failed")
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		mockCodeGenerator.AssertExpectations(t)
	})
}
