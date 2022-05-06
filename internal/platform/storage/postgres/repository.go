package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/patriciabonaldy/authentication/internal"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"

	"github.com/patriciabonaldy/authentication/internal/platform/logger"
)

var (
	PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
	PgNoRowsMsg       = "no rows in result set"
)

// Repository has the implementation of the db methods.
type Repository struct {
	db     *sqlx.DB
	logger logger.Logger
}

// NewPostgresRepository returns a new PostgresRepository instance
func NewPostgresRepository(db *sqlx.DB, logger logger.Logger) *Repository {
	return &Repository{db, logger}
}

// Create inserts the given user into the database
func (repo *Repository) Create(ctx context.Context, user *internal.User) error {
	uDB := parseToUserDB(user)
	uDB.ID = uuid.NewV4().String()
	uDB.CreatedAt = time.Now()
	uDB.UpdatedAt = time.Now()

	repo.logger.Infof("creating user %#v", user)
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := repo.db.ExecContext(ctx, query, uDB.ID, uDB.Email, uDB.Username,
		uDB.Password, uDB.TokenHash, uDB.CreatedAt, uDB.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "violates unique constraint") {
			return internal.ErrUserAlreadyExists
		}

		return err
	}

	return nil
}

// GetUserByEmail retrieves the user object having the given email, else returns error
func (repo *Repository) GetUserByEmail(ctx context.Context, email string) (*internal.User, error) {
	repo.logger.Info("querying for user with email", email)
	query := "select * from users where email = $1"
	var userDB User
	if err := repo.db.GetContext(ctx, &userDB, query, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, internal.ErrUserNotFound
		}

		return nil, err
	}
	repo.logger.Infof("read users %#v", userDB)

	user := parseToUser(userDB)
	return &user, nil
}

// GetUserByID retrieves the user object having the given ID, else returns error
func (repo *Repository) GetUserByID(ctx context.Context, userID string) (*internal.User, error) {
	repo.logger.Info("querying for user with id", userID)
	query := "select * from users where id = $1"
	var userDB User
	if err := repo.db.GetContext(ctx, &userDB, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, internal.ErrUserNotFound
		}

		return nil, err
	}

	user := parseToUser(userDB)
	return &user, nil
}

// UpdateUsername updates the username of the given user
func (repo *Repository) UpdateUsername(ctx context.Context, user *internal.User) error {
	udb := parseToUserDB(user)
	udb.UpdatedAt = time.Now()

	query := "update users set username = $1, updatedat = $2 where id = $3"
	if _, err := repo.db.ExecContext(ctx, query, udb.Username, udb.UpdatedAt, udb.ID); err != nil {
		return err
	}
	return nil
}

// UpdateUserVerificationStatus updates user verification status to true
func (repo *Repository) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {

	query := "update users set isverified = $1 where email = $2"
	if _, err := repo.db.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// StoreVerificationData adds a mail verification data to db
func (repo *Repository) StoreVerificationData(ctx context.Context, verificationData *internal.VerificationData) error {

	query := "insert into verifications(email, code, expiresat, type) values($1, $2, $3, $4)"
	_, err := repo.db.ExecContext(ctx, query, verificationData.Email, verificationData.Code, verificationData.ExpiresAt, verificationData.Type)

	return err
}

// GetVerificationData retrieves the stored verification code.
func (repo *Repository) GetVerificationData(ctx context.Context, email string, verificationDataType internal.VerificationDataType) (*internal.VerificationData, error) {
	query := "select * from verifications where email = $1 and type = $2"
	var vDB VerificationData
	if err := repo.db.GetContext(ctx, &vDB, query, email, verificationDataType); err != nil {
		return nil, err
	}

	vData := parseToVerificationData(vDB)
	return &vData, nil
}

// DeleteVerificationData deletes a used verification data
func (repo *Repository) DeleteVerificationData(ctx context.Context, email string, verificationDataType internal.VerificationDataType) error {
	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.db.ExecContext(ctx, query, email, verificationDataType)
	return err
}

// UpdatePassword updates the user password
func (repo *Repository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {
	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}
