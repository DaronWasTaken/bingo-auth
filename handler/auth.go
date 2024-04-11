package handler

import (
	"bingo-auth/db"
	"bingo-auth/types"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	DB db.DbStorage
}

var (
	DB  db.DbStorage
	env types.Env
)

func NewAuthHandler(db db.DbStorage, env *types.Env) *AuthHandler {
	DB = db
	env = env
	return &AuthHandler{}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {

	credentials := new(types.CredentialRequest)
	err := json.NewDecoder(r.Body).Decode(credentials)
	defer r.Body.Close()
	if err != nil {
		log.Printf("Failed to decode json: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)

	if err != nil {
		log.Printf("Failed to hash password: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	usr := types.User{
		Username: credentials.Username,
		Hash:     string(hash),
	}

	err = DB.Add(usr)
	if err != nil {
		log.Printf("Failed to add user: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.WriteHeader(204)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {

	usr := types.CredentialRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}

	usr.Username = r.FormValue("username")
	usr.Password = r.FormValue("password")

	if usr.Username == "" {
		log.Print("Username empty")
		http.Error(w, "Username empty", 400)
		return
	}

	hash, err := DB.GetUserPassword(usr.Username)
	if err != nil {
		log.Printf("Failed to retrieve user password: %s", err)
		http.Error(w, "Internal server error", 500)
		return
	}
	if hash == "" {
		log.Printf("User not found during login: %s", usr.Username)
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(usr.Username))
	if err != nil {
		log.Printf("Failed login attempt: %s", err)
		http.Error(w, "Username or password incorrect", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   usr.Username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString([]byte(env.Jwtkey))

	if err != nil {
		log.Printf("Could not sign access token: %s", err)
		http.Error(w, "Internal Server Error", 500)
	}

	resBody := types.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(expirationTime).Seconds()),
	}

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resBody)
}
