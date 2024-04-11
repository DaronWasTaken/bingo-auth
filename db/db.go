package db

import (
	"bingo-auth/types"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DbStorage interface {
	GetUserPassword(username string) (string, error)
	Add(user types.User) error
}

type DbPostgres struct{}

var DB *sqlx.DB

// CREATE TABLE user (
//     username text PRIMARY KEY,
//     hash text
// );

func NewDbPostgres(env *types.Env) (*DbPostgres, error) {
	db, err := sqlx.Connect("postgres", env.Dbcon)
	DB = db
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DB: %w", err)
	}
	return &DbPostgres{}, nil
}

func (db *DbPostgres) Add(u types.User) error {
	_, err := DB.Exec(`INSERT INTO "user" (username, hash) VALUES ($1, $2)`, u.Username, u.Hash)
	if err != nil {
		return fmt.Errorf("failed to add user to database: %w", err)
	}
	return nil
}

func (db *DbPostgres) GetUserPassword(username string) (string, error) {
	hash := new(string)
	err := DB.Get(hash, `SELECT hash FROM "user" WHERE username = $1`, username)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user password from db: %w", err)
	}
	return *hash, nil
}
