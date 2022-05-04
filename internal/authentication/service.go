package authentication

import (
	"encoding/base64"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/patriciabonaldy/authentication/internal"
	"github.com/patriciabonaldy/authentication/internal/config"
	"github.com/patriciabonaldy/authentication/internal/platform/logger"
)

const (
	tokenType = "refresh"
	issuer    = "bookite.auth.service"
)

// Authentication interface lists the methods that our authentication service should implement
type Authentication interface {
	Authenticate(reqUser *internal.User, user *internal.User) bool
	GenerateAccessToken(user *internal.User) (string, error)
	GenerateRefreshToken(user *internal.User) (string, error)
	GenerateCustomKey(userID string, tokenHash string) string
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, string, error)
}

// AuthService is the implementation of our Authentication
type AuthService struct {
	logger  logger.Logger
	configs *config.Token
}

// NewAuthService returns a new instance of the auth service
func NewAuthService(logger logger.Logger, configs *config.Token) Authentication {
	return &AuthService{logger, configs}
}

func (a *AuthService) Authenticate(reqUser *internal.User, user *internal.User) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		a.logger.Error("password hashes are not same")
		return false
	}

	return true
}

func (a *AuthService) GenerateAccessToken(user *internal.User) (string, error) {
	cusKey := a.GenerateCustomKey(user.ID, user.TokenHash)
	claims := RefreshTokenCustomClaims{
		user.ID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: issuer,
		},
	}

	signBytes, err := base64.StdEncoding.DecodeString(a.configs.RefreshTokenPrivateKeyPath)
	if err != nil {
		a.logger.Error("unable to read private key", "error", err)
		return "", ErrGenerateRefresh
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		a.logger.Error("unable to parse private key", "error", err)
		return "", ErrGenerateRefresh
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func (a *AuthService) GenerateRefreshToken(user *internal.User) (string, error) {
	userID := user.ID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: generateJwtExpiration(a.configs.JwtExpiration),
			Issuer:    issuer,
		},
	}

	signBytes, err := base64.StdEncoding.DecodeString(a.configs.AccessTokenPrivateKeyPath)
	if err != nil {
		a.logger.Error("unable to read private key", "error", err)
		return "", ErrGenerateToken
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		a.logger.Error("unable to parse private key", "error", err)
		return "", ErrGenerateToken
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func (a *AuthService) GenerateCustomKey(userID string, tokenHash string) string {
	// data := userID + tokenHash
	h := hmac.New(sha256.New, []byte(tokenHash))
	h.Write([]byte(userID))
	sha := hex.EncodeToString(h.Sum(nil))

	return sha
}

func (a *AuthService) ValidateAccessToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			a.logger.Error("Unexpected signing method in auth token")
			return nil, ErrSigningToken
		}

		verifyBytes, err := base64.StdEncoding.DecodeString(a.configs.AccessTokenPublicKeyPath)
		if err != nil {
			a.logger.Error("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			a.logger.Error("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		a.logger.Error("unable to parse claims", "error", err)
		return "", err
	}

	claims, ok := token.Claims.(*AccessTokenCustomClaims)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "access" {
		return "", ErrInvalidToken
	}

	return claims.UserID, nil
}

func (a *AuthService) ValidateRefreshToken(tokenString string) (string, string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			a.logger.Error("Unexpected signing method in auth token")
			return nil, ErrSigningToken
		}

		verifyBytes, err := base64.StdEncoding.DecodeString(a.configs.RefreshTokenPublicKeyPath)
		if err != nil {
			a.logger.Error("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			a.logger.Error("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		a.logger.Error("unable to parse claims", "error", err)
		return "", "", err
	}

	claims, ok := token.Claims.(*RefreshTokenCustomClaims)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "refresh" {
		a.logger.Error("could not extract claims from token")
		return "", "", ErrInvalidToken
	}

	return claims.UserID, claims.CustomKey, nil
}

func generateJwtExpiration(jwtExpiration int) int64 {
	return time.Now().Add(time.Minute * time.Duration(jwtExpiration)).Unix()
}
