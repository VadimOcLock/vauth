package main

import (
	"context"
	"fmt"

	"github.com/github.com/VadimOcLock/vauth/pkg/authclient"
	"github.com/github.com/VadimOcLock/vauth/pkg/jwtgen"
	"github.com/github.com/VadimOcLock/vauth/pkg/pg"
)

func main() {
	ctx := context.Background()
	conn, err := pg.New(ctx, pg.Config{
		DSN: "postgres://postgres_user:postgres_password@localhost:5430/postgres_db?sslmode=disable",
	})
	if err != nil {
		fmt.Printf("open connection error: %s", err)

		return
	}
	defer conn.Close()
	client, err := authclient.New(authclient.Config{
		PgClient: conn,
		JWTConfig: jwtgen.CreatorConfig{
			SecretKey: []byte("secret_key"),
		},
		EmailSenderHook: func(ctx context.Context, email string, code string) error {
			fmt.Println("send to mail...")

			return nil
		},
	})
	if err != nil {
		fmt.Printf("client init error: %s", err)

		return
	}
	err = client.Register(ctx, authclient.RegisterParams{
		Email:    "vadim@mail.com",
		Password: "12345678",
	})
	if err != nil {
		fmt.Printf("register error: %s", err)

		return
	}
	fmt.Printf("successfuly register user")
}
