package postgres

import (
	"time"

	"github.com/patriciabonaldy/authentication/internal"
)

// User is the data type for user object
type User struct {
	ID         string    `json:"id" sql:"id"`
	Email      string    `json:"email" validate:"required" sql:"email"`
	Password   string    `json:"password" validate:"required" sql:"password"`
	Username   string    `json:"username" sql:"username"`
	TokenHash  string    `json:"tokenhash" sql:"tokenhash"`
	IsVerified bool      `json:"isverified" sql:"isverified"`
	CreatedAt  time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt  time.Time `json:"updatedat" sql:"updatedat"`
}

// VerificationData represents the type for the data stored for verification.
type VerificationData struct {
	Email     string    `json:"email" validate:"required" sql:"email"`
	Code      string    `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
	Type      int       `json:"type" sql:"type"`
}

func parseToUserDB(user *internal.User) User {
	userDB := User{
		ID:         user.ID,
		Email:      user.Email,
		Password:   user.Password,
		Username:   user.Username,
		TokenHash:  user.TokenHash,
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}

	return userDB
}

func parseToUser(userDB User) internal.User {
	return internal.User{
		ID:         userDB.ID,
		Email:      userDB.Email,
		Password:   userDB.Password,
		Username:   userDB.Username,
		TokenHash:  userDB.TokenHash,
		IsVerified: userDB.IsVerified,
		CreatedAt:  userDB.CreatedAt,
		UpdatedAt:  userDB.UpdatedAt,
	}
}

func parseToVerificationData(vData VerificationData) internal.VerificationData {
	return internal.VerificationData{
		Email:     vData.Email,
		Code:      vData.Code,
		ExpiresAt: vData.ExpiresAt,
		Type:      internal.VerificationDataType(vData.Type),
	}
}
