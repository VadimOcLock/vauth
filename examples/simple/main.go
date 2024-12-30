package main

import (
	"context"
	"github.com/github.com/VadimOcLock/vauth/pkg/authservice"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"log"
)

func main() {

	client, err := authservice.NewClient(authservice.Config{
		PgClient:  nil,
		JWTConfig: jwtgen.CreatorConfig{},
	})
	if err != nil {
		log.Fatalf("Ошибка инициализации сервиса: %v", err)
	}

	ctx := context.Background()
	service.User.Register(ctx, userservice.RegisterParams{})

	token, err := service.Register(ctx, userservice.RegisterParams{
		Email:    "userservice@example.com",
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

	token, err = service.Login(ctx, userservice.LoginParams{
		Email:    "user2@example.com",
		Password: "securePassword123!",
	})
	if err != nil {
		log.Fatalf("Ошибка авторизации пользователя: %v", err)
	}

	log.Printf("Успешная авторизация пользователя. Сгенерированный токен: %s", token)
}
