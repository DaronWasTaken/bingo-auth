package types

import (
	"os"

	"github.com/dgrijalva/jwt-go"
)

type CredentialRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Id       string `db:"id"`
	Username string `db:"username"`
	Hash     string `db:"password_hash"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type Claims struct {
	TokenType string `json:"token_type"`
	jwt.StandardClaims
}

type Env struct {
	Dbcon  string
	Jwtkey string
}

func NewEnv() Env {
	dbcon, exists := os.LookupEnv("DB_CONN")
	if !exists {
		dbcon = "postgres://postgres:admin@localhost:5432/postgres?sslmode=disable"
	}

	jwtkey, exists := os.LookupEnv("JWT_KEY")
	if !exists {
		jwtkey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	}

	return Env{
		Dbcon:  dbcon,
		Jwtkey: jwtkey,
	}
}
