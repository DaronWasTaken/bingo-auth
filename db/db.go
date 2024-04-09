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

type DbPostgres struct {}

var DB *sqlx.DB

func NewDbPostgres(env *types.Env) (*DbPostgres, error){
	db, err := sqlx.Connect("postgres", env.Dbcon)
	DB = db
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DB: %w", err)
	}
	return &DbPostgres{}, nil
}

func (db *DbPostgres) Add(types.User) error {
	return nil
}

func (db *DbPostgres) GetUserPassword(username string) (string, error) {
	return "", nil
}


