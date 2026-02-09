package codegen

import "time"

const (
	defaultConfirmationCodeTTL = 1 * time.Hour
	defaultResetCodeTTL        = 1 * time.Hour
)

type Generator interface {
	GenerateConfirmationCode() (Code, error)
	GenerateResetCode() (Code, error)
}

type generatorImpl struct {
	confirmationCodeTTL time.Duration
	resetCodeTTL        time.Duration
}

type GeneratorOption func(*generatorImpl)

func WithConfirmationCodeTTL(ttl time.Duration) GeneratorOption {
	return func(impl *generatorImpl) {
		impl.confirmationCodeTTL = ttl
	}
}

func WithResetCodeTTL(ttl time.Duration) GeneratorOption {
	return func(impl *generatorImpl) {
		impl.resetCodeTTL = ttl
	}
}

func NewGenerator(opts ...GeneratorOption) Generator {
	impl := generatorImpl{
		confirmationCodeTTL: defaultConfirmationCodeTTL,
		resetCodeTTL:        defaultResetCodeTTL,
	}

	for _, opt := range opts {
		opt(&impl)
	}

	return impl
}
