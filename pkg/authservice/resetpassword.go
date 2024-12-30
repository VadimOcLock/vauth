package authservice

import "context"

type RequestResetPasswordParams struct {
	Email string
}

func (s Service) RequestResetPassword(ctx context.Context, dto RequestResetPasswordParams) error {
	// todo: Найти пользователя по email.
	// todo: Генерация токена на сброс пароля.
	// todo: Отправка токена по email.

	return nil
}

type ResetPasswordParams struct {
	ResetToken  string
	NewPassword string
}

func (s Service) ResetPassword(ctx context.Context, dto ResetPasswordParams) error {
	// todo: Валидация reset токена.
	// todo: Найти пользователя по email.
	// todo: Обновить пароль.

	return nil
}
