package db

import (
	"bingo-auth/types"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DbStorage interface {
	GetUserCredentials(username string) (types.User, error)
	Add(user types.User) error
	UpdateOrCreateToken(token types.Token) error
	UpdateTokenOnRefresh(token types.Token) error
}

type DbPostgres struct {
}

var DB *sqlx.DB

//"user" (
//	id text PRIMARY KEY,
// 	username text,
// 	password_hash text,
// 	level_id int,
// 	points int,
// );

func NewDbPostgres(env types.Env) (*DbPostgres, error) {
	db, err := sqlx.Connect("postgres", env.Dbcon)
	DB = db
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DB: %w", err)
	}
	return &DbPostgres{}, nil
}

func (DbPostgres) Add(u types.User) error {
	username := ""
	err := DB.Get(&username, `SELECT username FROM usr WHERE username=$1`, u.Username)
	if err != sql.ErrNoRows && err != nil {
		return fmt.Errorf("failed to check username uniqueness: %w", err)
	}
	if username != "" {
		return types.APIError{
			Code: http.StatusConflict,
			Text: "Username already exists",
		}
	}

	_, err = DB.Exec(
		`INSERT INTO usr VALUES ($1, $2, $3, $4, $5)`,
		u.Id,
		u.Username,
		u.Hash,
		0, // points
		1, // lvl
	)

	if err != nil {
		return fmt.Errorf("failed to add user to database: %w", err)
	}
	return nil
}

func (DbPostgres) GetUserCredentials(username string) (types.User, error) {
	var usr types.User
	err := DB.Get(&usr, `SELECT id, username, password_hash FROM usr WHERE username = $1`, username)
	if err != nil {
		return types.User{}, fmt.Errorf("failed to retrieve user password from db: %w", err)
	}
	return usr, nil
}

func (DbPostgres) UpdateOrCreateToken(token types.Token) error {
	var currentToken types.Token
	err := DB.Get(&currentToken, `SELECT * FROM token WHERE usr_id = $1`, token.Id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return createToken(token)
		} else {
			return fmt.Errorf("failed to create new token: %w", err)
		}
	} else {
		return updateToken(token)
	}
}

func createToken(token types.Token) error {
	stmt := `INSERT INTO token 
	(usr_id, access_token, refresh_token, access_expires_at, refresh_expires_at, created_at) 
	VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := DB.Exec(stmt,
		token.Id,
		token.AccessToken,
		token.RefreshToken,
		token.AccessExpiresAt,
		token.RefreshExpiresAt,
		token.CreatedAt,
	)

	return err
}

func updateToken(token types.Token) error {
	stmt := `UPDATE token SET 
	access_token = $1,
	refresh_token = $2,
	access_expires_at = $3,
	refresh_expires_at = $4,
	created_at = $5
	WHERE usr_id = $6`

	_, err := DB.Exec(stmt,
		token.AccessToken,
		token.RefreshToken,
		token.AccessExpiresAt,
		token.RefreshExpiresAt,
		token.CreatedAt,
		token.Id,
	)

	return err
}

func (DbPostgres) UpdateTokenOnRefresh(token types.Token) error {
	var currentToken types.Token
	err := DB.Get(&currentToken, `SELECT * FROM token WHERE usr_id = $1`, token.Id)
	if err != nil {
		return fmt.Errorf("failed to create new token: %w", err)
	}

	if currentToken.RefreshToken != token.RefreshToken {
		return types.APIError{
			Code: http.StatusUnauthorized,
			Text: "Incorrect refresh token",
		}
	}

	currentToken.AccessToken = token.AccessToken
	currentToken.AccessExpiresAt = token.AccessExpiresAt
	return updateToken(currentToken)
}
