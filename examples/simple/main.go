package main

import (
	"context"
	"github.com/github.com/VadimOcLock/vauth/pkg/auth"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"log"
	"time"
)

func main() {
	service, err := auth.NewService(auth.Config{
		DatabaseDSN: "postgres://postgres_user:postgres_password@localhost:5430/postgres_db",
		JWTConfig: jwtgen.Config{
			SecretKey:       []byte("super-secret-key"),
			AccessTokenTTL:  24 * time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
		},
	})
	if err != nil {
		log.Fatalf("Ошибка инициализации сервиса: %v", err)
	}

	ctx := context.Background()

	token, err := service.Register(ctx, auth.RegisterParams{
		Email:    "user@example.com",
		Password: "securePassword123!",
		Permissions: []string{
			"read",
			"write",
		},
	})
	if err != nil {
		log.Fatalf("Ошибка регистрации пользователя: %v", err)
	}

	log.Printf("Успешная регистрация пользователя. Сгенерированный токен: %s", token)

	token, err = service.Login(ctx, auth.LoginParams{
		Email:    "user2@example.com",
		Password: "securePassword123!",
	})
	if err != nil {
		log.Fatalf("Ошибка авторизации пользователя: %v", err)
	}

	log.Printf("Успешная авторизация пользователя. Сгенерированный токен: %s", token)
}
