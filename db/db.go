package db

import (
	"bingo-auth/types"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DbStorage interface {
	GetUserCredentials(username string) (types.User, error)
	Add(user types.User) error
}

type DbPostgres struct {
	Field1 string
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
		return types.UsernameExistsError{Message: "Username already exists"}
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
