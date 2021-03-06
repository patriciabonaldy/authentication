package internal

import (
	"context"
	"github.com/pkg/errors"
	"time"
)

// Repository is an interface for the storage implementation of the auth service
type Repository interface {
	Create(ctx context.Context, user *User) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	UpdateUsername(ctx context.Context, user *User) error
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) error
	GetVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) (*VerificationData, error)
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error
	UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error
}

var (
	ErrUserNotFound       = errors.New("no user account exists with given email. Please sign in first")
	ErrUserAlreadyExists  = errors.New("user already exists with the given email")
	ErrUserCreationFailed = errors.New("unable to create user.Please try again later")
	ErrUserVerifyFailed   = errors.New("user account is not verified")
	ErrGenerateToken      = errors.New("error generating access token")
	ErrInvalidPassword    = errors.New("Invalid password")
)

const (
	MailConfirmation VerificationDataType = iota + 1
	PassReset
)

type VerificationDataType int

// User is the data type for user object
type User struct {
	ID         string
	Email      string
	Password   string
	Username   string
	TokenHash  string
	IsVerified bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// VerificationData represents the type for the data stored for verification.
type VerificationData struct {
	Email     string
	Code      string
	ExpiresAt time.Time
	Type      VerificationDataType
}
