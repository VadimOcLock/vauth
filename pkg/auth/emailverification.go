package auth

import "context"

type RequestVerifyEmailParams struct {
	Email string
}

func (s Service) RequestVerifyEmail(ctx context.Context, dto RequestVerifyEmailParams) error {
	// todo: Найти пользователя по email.
	// todo: Генерация токена на подтверждение.
	// todo: Отправка токена по email.

	return nil
}

type VerifyEmailParams struct {
	Token string
}

func (s Service) VerifyEmail(ctx context.Context, dto VerifyEmailParams) error {
	// todo: Валидация verify токена.
	// todo: Найти пользователя по email.
	// todo: Обновить статус.

	return nil
}
