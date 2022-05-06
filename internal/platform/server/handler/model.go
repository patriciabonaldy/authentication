package handlers

import (
	"github.com/patriciabonaldy/authentication/internal"
	"time"
)

// GenericResponse is the format of our response
type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// ValidationError is a collection of validation error messages
type ValidationError struct {
	Errors []string `json:"errors"`
}

// TokenResponse data types are used for encoding and decoding b/t go types and json
type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Username     string `json:"username"`
}

type UsernameUpdate struct {
	Username string `json:"username"`
}

type CodeVerificationReq struct {
	Code string `json:"code" binding:"required"`
	Type string `json:"type" binding:"required"`
}

type PasswordResetReq struct {
	Password   string `json:"password" binding:"required"`
	PasswordRe string `json:"password_re" binding:"required"`
	Code       string `json:"code" binding:"required"`
}

// UserRequest is the data type for user object
type UserRequest struct {
	ID         string    `json:"id" sql:"id"`
	Email      string    `json:"email" validate:"required" sql:"email"`
	Password   string    `json:"password" validate:"required" sql:"password"`
	Username   string    `json:"username" sql:"username"`
	TokenHash  string    `json:"tokenhash" sql:"tokenhash"`
	IsVerified bool      `json:"isverified" sql:"isverified"`
	CreatedAt  time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt  time.Time `json:"updatedat" sql:"updatedat"`
}

func toUser(req UserRequest) internal.User {
	return internal.User{
		ID:         req.ID,
		Email:      req.Email,
		Password:   req.Password,
		Username:   req.Username,
		TokenHash:  req.TokenHash,
		IsVerified: req.IsVerified,
		CreatedAt:  req.CreatedAt,
		UpdatedAt:  req.UpdatedAt,
	}
}

func toUserRequest(user internal.User) UserRequest {
	return UserRequest{
		ID:         user.ID,
		Email:      user.Email,
		Password:   user.Password,
		Username:   user.Username,
		TokenHash:  user.TokenHash,
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}
}
