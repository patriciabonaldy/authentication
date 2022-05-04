package config

import (
	"context"

	"github.com/pkg/errors"
	"github.com/sethvargo/go-envconfig"
)

type Token struct {
	AccessTokenPrivateKeyPath  string `env:"ACCESS_TOKEN_PRIVATE_KEY_PATH"`
	AccessTokenPublicKeyPath   string `env:"ACCESS_TOKEN_PUBLIC_KEY_PATH"`
	RefreshTokenPrivateKeyPath string `env:"REFRESH_TOKEN_PRIVATE_KEY_PATH"`
	RefreshTokenPublicKeyPath  string `env:"REFRESH_TOKEN_PUBLIC_KEY_PATH"`
	JwtExpiration              int    `env:"JWT_EXPIRATION"` // in minutes
}

type DB struct {
	DBHost string `env:"DB_HOST"`
	DBName string `env:"DB_NAME"`
	DBUser string `env:"DB_USER"`
	DBPass string `env:"DB_PASSWORD"`
	DBPort string `env:"DB_PORT"`
	DBConn string `env:"DATABASE_URL"`
}

type Mail struct {
	MailVerifCodeExpiration int    `env:"MAIL_VERIFICATION_CODE_EXPIRATION"` // in hours `env:"DATABASE_DSN"`
	PassResetCodeExpiration int    `env:"PASSWORD_RESET_CODE_EXPIRATION"`    // in minutes `env:"DATABASE_DSN"`
	MailVerifTemplateID     string `env:"MAIL_VERIFICATION_TEMPLATE_ID"`
	PassResetTemplateID     string `env:"PASSWORD_RESET_TEMPLATE_ID"`
}

// Config wraps all the config variables required by the auth service
type Config struct {
	ServerAddress  string `env:"SERVER_ADDRESS"`
	DB             DB
	Token          Token
	SendGridAPIKey string `env:"SENDGRID_API_KEY"`
	Mail           Mail
}

// New initializes the config loading the configurations from environment
// variables.
func New() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process(context.Background(), cfg); err != nil {
		return nil, errors.Errorf("loading configuration: %w", err)
	}

	return cfg, nil
}
