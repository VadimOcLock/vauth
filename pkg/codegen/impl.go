package codegen

import (
	"time"

	"github.com/matchsystems/werr"

	"github.com/google/uuid"
)

func (g generatorImpl) GenerateConfirmationCode() (Code, error) {
	code, err := uuid.NewUUID()
	if err != nil {
		return Code{}, werr.Wrap(err)
	}

	return Code{
		Code:      code.String(),
		ExpiresAt: time.Now().Add(g.confirmationCodeTTL),
	}, nil
}

func (g generatorImpl) GenerateResetCode() (Code, error) {
	code, err := uuid.NewUUID()
	if err != nil {
		return Code{}, werr.Wrap(err)
	}

	return Code{
		Code:      code.String(),
		ExpiresAt: time.Now().Add(g.confirmationCodeTTL),
	}, nil
}
