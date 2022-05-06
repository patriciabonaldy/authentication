package authentication

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/patriciabonaldy/authentication/internal/mail"
	"math/rand"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"github.com/patriciabonaldy/authentication/internal"
	"github.com/patriciabonaldy/authentication/internal/config"
	"github.com/patriciabonaldy/authentication/internal/platform/logger"
)

const (
	tokenType   = "refresh"
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// Authentication interface lists the methods that our authentication service should implement
type Authentication interface {
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, string, error)
	Signup(ctx context.Context, user internal.User) error
	Login(ctx context.Context, user internal.User) (string, string, error)
	RefreshToken(ctx context.Context, user internal.User) (string, error)
}

// AuthService is the implementation of our Authentication
type AuthService struct {
	logger logger.Logger
	config *config.Token
	repo   internal.Repository
	mail   mail.Mail
}

// NewAuthService returns a new instance of the auth service
func NewAuthService(logger logger.Logger, config *config.Token, repo internal.Repository, mail mail.Mail) Authentication {
	return &AuthService{logger, config, repo, mail}
}

func (a *AuthService) Login(ctx context.Context, user internal.User) (string, string, error) {
	userDB, err := a.repo.GetUserByEmail(ctx, user.Email)
	if err != nil {
		return "", "", err
	}

	if !user.IsVerified {
		return "", "", internal.ErrUserVerifyFailed
	}

	if valid := a.authenticate(&user, userDB); !valid {
		return "", "", internal.ErrInvalidPassword
	}

	accessToken, err := a.generateAccessToken(&user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := a.refreshToken(&user)
	if err != nil {
		return "", "", err
	}

	a.logger.Info("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)

	return accessToken, refreshToken, nil
}

func (a *AuthService) RefreshToken(ctx context.Context, user internal.User) (string, error) {
	_, err := a.repo.GetUserByEmail(ctx, user.Email)
	if err != nil {
		return "", err
	}

	return a.generateToken(), nil
}

func (a *AuthService) authenticate(reqUser *internal.User, user *internal.User) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		a.logger.Error("password hashes are not same")
		return false
	}

	return true
}

func (a *AuthService) generateAccessToken(user *internal.User) (string, error) {
	cusKey := a.customKey(user.ID, user.TokenHash)
	claims := RefreshTokenCustomClaims{
		user.ID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: a.config.Issuer,
		},
	}

	signBytes, err := base64.StdEncoding.DecodeString(a.config.RefreshTokenPrivateKeyPath)
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

func (a *AuthService) refreshToken(user *internal.User) (string, error) {
	userID := user.ID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: generateJwtExpiration(a.config.JwtExpiration),
			Issuer:    a.config.Issuer,
		},
	}

	signBytes, err := base64.StdEncoding.DecodeString(a.config.AccessTokenPrivateKeyPath)
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

func (a *AuthService) customKey(userID string, tokenHash string) string {
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

		verifyBytes, err := base64.StdEncoding.DecodeString(a.config.AccessTokenPublicKeyPath)
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

		verifyBytes, err := base64.StdEncoding.DecodeString(a.config.RefreshTokenPublicKeyPath)
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

func (a *AuthService) Signup(ctx context.Context, user internal.User) error {
	pass, err := a.generatePassword(user.Password)
	if err != nil {
		return internal.ErrUserCreationFailed
	}

	user.Password = pass
	user.TokenHash = a.generateToken()
	err = a.repo.Create(ctx, &user)
	if err != nil {
		return err
	}

	return nil
}

func generateJwtExpiration(jwtExpiration int) int64 {
	return time.Now().Add(time.Minute * time.Duration(jwtExpiration)).Unix()
}

func (a *AuthService) generatePassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("unable to hash password", "error", err)
		return "", err
	}

	return string(hashedPass), nil
}

func (ah *AuthService) generateToken() string {
	sb := strings.Builder{}
	sb.Grow(12)
	for i := 0; i < 12; i++ {
		idx := rand.Int63() % int64(len(letterBytes))
		sb.WriteByte(letterBytes[idx])
	}
	return sb.String()
}
