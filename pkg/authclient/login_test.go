package authclient_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/github.com/VadimOcLock/vauth/internal/store"
	storemocks "github.com/github.com/VadimOcLock/vauth/internal/store/mocks"
	"github.com/github.com/VadimOcLock/vauth/pkg/authclient"
	"github.com/github.com/VadimOcLock/vauth/pkg/errorz"
	hashermocks "github.com/github.com/VadimOcLock/vauth/pkg/hash/mocks"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	jwtmocks "github.com/github.com/VadimOcLock/vauth/pkg/jwtgen/mocks"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Login(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("successful login", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "securepassword"
		hashedPassword := "hashed_password"
		userID := uuid.New()
		token := jwtgen.Token{
			Token:     "jwt_token",
			ExpiresAt: time.Now().Add(time.Minute * 15),
		}
		tokenID := uuid.New()

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:           userID,
			Email:        email,
			PasswordHash: hashedPassword,
			IsVerified: pgtype.Bool{
				Bool:  true,
				Valid: true,
			},
		}, nil)
		mockHasher.On("CheckPasswordHash", password, hashedPassword).Return(true, nil)
		mockJWTCreator.On("CreateAccessToken", userID.String()).Return(token, nil)
		mockStore.On("CreateToken", ctx, store.CreateTokenDTO{
			UserID:    userID,
			Token:     token.Token,
			ExpiresAt: token.ExpiresAt,
		}).Return(tokenID, nil)

		result, err := client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: password,
		})

		require.NoError(t, err)
		assert.Equal(t, token.Token, result)
		mockStore.AssertExpectations(t)
		mockJWTCreator.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    "invalid_email",
			Password: "123456",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidEmailFormat)
	})

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "test@example.com"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{}, pgx.ErrNoRows)

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: "securepassword",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
	})

	t.Run("invalid password", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "wrongpassword"
		hashedPassword := "hashed_password"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: hashedPassword,
			IsVerified: pgtype.Bool{
				Bool:  true,
				Valid: true,
			},
		}, nil)
		mockHasher.On("CheckPasswordHash", password, hashedPassword).Return(false, nil)

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: password,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrInvalidCredentials)
		mockStore.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("not verified email", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "inactive@example.com"
		hashedPassword := "hashed_password"

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: hashedPassword,
			IsVerified: pgtype.Bool{
				Bool:  false,
				Valid: true,
			},
		}, nil)

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: "securepassword",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, errorz.ErrEmailNotConfirmed)
		mockStore.AssertExpectations(t)
	})

	t.Run("token creation error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "securepassword"
		hashedPassword := "hashed_password"
		userID := uuid.New()

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:           userID,
			Email:        email,
			PasswordHash: hashedPassword,
			IsVerified: pgtype.Bool{
				Bool:  true,
				Valid: true,
			},
		}, nil)
		mockHasher.On("CheckPasswordHash", password, hashedPassword).Return(true, nil)
		mockJWTCreator.On("CreateAccessToken", userID.String()).Return(jwtgen.Token{}, errors.New("token creation error"))

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: password,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token creation error")
		mockStore.AssertExpectations(t)
		mockJWTCreator.AssertExpectations(t)
	})

	t.Run("database token creation error", func(t *testing.T) {
		t.Parallel()

		mockStore := storemocks.NewStore(t)
		mockJWTCreator := jwtmocks.NewCreator(t)
		mockHasher := hashermocks.NewHasher(t)
		client, err := authclient.New(
			authclient.Config{},
			authclient.WithStore(mockStore),
			authclient.WithJWTCreator(mockJWTCreator),
			authclient.WithHasher(mockHasher),
		)
		require.NoError(t, err)

		email := "test@example.com"
		password := "securepassword"
		hashedPassword := "hashed_password"
		userID := uuid.New()
		token := jwtgen.Token{
			Token:     "jwt_token",
			ExpiresAt: time.Now().Add(time.Minute * 15),
		}

		mockStore.On("FindUserByEmail", ctx, email).Return(store.User{
			ID:           userID,
			Email:        email,
			PasswordHash: hashedPassword,
			IsVerified: pgtype.Bool{
				Bool:  true,
				Valid: true,
			},
		}, nil)
		mockHasher.On("CheckPasswordHash", password, hashedPassword).Return(true, nil)
		mockJWTCreator.On("CreateAccessToken", userID.String()).Return(token, nil)
		mockStore.On("CreateToken", ctx, store.CreateTokenDTO{
			UserID:    userID,
			Token:     token.Token,
			ExpiresAt: token.ExpiresAt,
		}).Return(uuid.UUID{}, errors.New("database error"))

		_, err = client.Login(ctx, authclient.LoginParams{
			Email:    email,
			Password: password,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		mockStore.AssertExpectations(t)
		mockJWTCreator.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}
