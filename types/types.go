package types

import "os"

type CredentialRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Username string
	Hash string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64 `json:"expires_in"`
}

type Env struct {
	Dbcon string
	Jwtkey string
}

func NewEnv() *Env {

	dbcon, exists := os.LookupEnv("DB_CONN")
	if !exists {
		dbcon = "postgres://postgres:admin@localhost:5432/postgres?sslmode=disable"
	}

	jwtkey, exists := os.LookupEnv("JWT_KEY")
	if !exists {
		jwtkey = "test"
	}

	return &Env{
		Dbcon: dbcon,
		Jwtkey: jwtkey,
	}
}

