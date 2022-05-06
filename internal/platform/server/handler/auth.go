package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/patriciabonaldy/authentication/internal"
	"github.com/patriciabonaldy/authentication/internal/authentication"
	"github.com/patriciabonaldy/authentication/internal/config"
	"github.com/patriciabonaldy/authentication/internal/platform/logger"
	"github.com/pkg/errors"
	"net/http"
)

// AuthHandler wraps instances needed to perform operations on user object
type AuthHandler struct {
	logger      logger.Logger
	configs     *config.Config
	authService authentication.Authentication
}

// New returns a new UserHandler instance
func New(l logger.Logger, c *config.Config, auth authentication.Authentication) *AuthHandler {
	return &AuthHandler{
		logger:      l,
		configs:     c,
		authService: auth,
	}
}

type userKey struct{}

func (ah *AuthHandler) Login() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req UserRequest
		if err := ctx.BindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}

		user := toUser(req)
		accessToken, refreshToken, err := ah.authService.Login(ctx, user)
		if err != nil {
			ah.logger.Error("error fetching the user", "error", err)
			switch err {
			case internal.ErrUserNotFound, internal.ErrUserVerifyFailed, internal.ErrInvalidPassword:
				ctx.JSON(http.StatusBadRequest, &GenericResponse{
					Status:  false,
					Message: err.Error(),
				})
			default:
				ctx.JSON(http.StatusInternalServerError, &GenericResponse{
					Status:  false,
					Message: "Unable to login. Please try again later",
				})
			}

			return
		}

		ah.logger.Info("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)
		ctx.JSON(http.StatusCreated, &GenericResponse{
			Status:  true,
			Message: "Successfully logged in",
			Data:    &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, Username: user.Username},
		})

	}
}

// Signup handles signup request
func (ah *AuthHandler) Signup() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req UserRequest
		if err := ctx.BindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}

		user := toUser(req)
		err := ah.authService.Signup(ctx, user)
		if err != nil {
			if errors.Is(err, internal.ErrUserNotFound) {
				ctx.JSON(http.StatusBadRequest, &GenericResponse{
					Status:  false,
					Message: internal.ErrUserNotFound.Error(),
				})

				return
			}

			ctx.JSON(http.StatusInternalServerError, &GenericResponse{
				Status:  false,
				Message: "Unable to retrieve user from database.Please try again later",
			})

			return
		}

		ctx.JSON(http.StatusCreated, &GenericResponse{
			Status:  true,
			Message: "Please verify your email account using the confirmation code send to your mail",
		})
	}
}

// RefreshToken handles refresh token request
func (ah *AuthHandler) RefreshToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req UserRequest
		if err := ctx.BindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}

		user := toUser(req)
		accessToken, err := ah.authService.RefreshToken(ctx, user)
		if err != nil {
			ah.logger.Error("unable to generate access token", "error", err)
			ctx.JSON(http.StatusInternalServerError, &GenericResponse{
				Status:  false,
				Message: "Unable to generate access token.Please try again later",
			})

			return
		}

		ctx.JSON(http.StatusCreated, &GenericResponse{
			Status:  true,
			Message: "Successfully generated new access token",
			Data:    &TokenResponse{AccessToken: accessToken},
		})
	}
}

