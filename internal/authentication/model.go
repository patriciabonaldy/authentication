package authentication

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// RefreshTokenCustomClaims specifies the claims for refresh token
type RefreshTokenCustomClaims struct {
	UserID    string
	CustomKey string
	KeyType   string
	jwt.StandardClaims
}

// AccessTokenCustomClaims specifies the claims for access token
type AccessTokenCustomClaims struct {
	UserID  string
	KeyType string
	jwt.StandardClaims
}

var (
	ErrGenerateRefresh = errors.New("could not generate refresh token. please try again later")
	ErrGenerateToken   = errors.New("could not generate access token. please try again later")

	ErrInvalidToken = errors.New("invalid token: authentication failed")
	ErrSigningToken = errors.New("Unexpected signing method in auth token")
)