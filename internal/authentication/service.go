package authentication

import "github.com/patriciabonaldy/authentication/internal"

// Authentication interface lists the methods that our authentication service should implement
type Authentication interface {
	Authenticate(reqUser *internal.User, user *internal.User) bool
	GenerateAccessToken(user *internal.User) (string, error)
	GenerateRefreshToken(user *internal.User) (string, error)
	GenerateCustomKey(userID string, password string) string
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, string, error)
}
