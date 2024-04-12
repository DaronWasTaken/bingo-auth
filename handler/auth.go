package handler

import (
	"bingo-auth/db"
	"bingo-auth/types"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	db.DbStorage
}

var (
	DB  db.DbStorage
	Env types.Env
)

func NewAuthHandler(db db.DbStorage, env types.Env) *AuthHandler {
	DB = db
	Env = env
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

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(usr.Password))
	if err != nil {
		log.Printf("Failed login attempt: %s", err)
		http.Error(w, "Username or password incorrect", http.StatusUnauthorized)
		return
	}

	accessToken, err := newAccessToken(usr.Username, Env.Jwtkey)
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	refreshToken, err := newRefreshToken(usr.Username, Env.Jwtkey)
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	resBody := types.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
	}

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resBody)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenInput := r.FormValue("refresh_token")
	claims := new(jwt.StandardClaims)

	_, err := jwt.ParseWithClaims(refreshTokenInput, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(Env.Jwtkey), nil
	})
	if err != nil {
		log.Printf("Failed to refresh token %s", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	accessToken, err := newAccessToken(claims.Subject, Env.Jwtkey)
	if err != nil {
		log.Printf("Failed to create token during refresh: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	resBody := types.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenInput,
		TokenType:    "Bearer",
	}

	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resBody)
	if err != nil {
		log.Printf("Failed to encode resBody in token refresh handler: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
}

func newAccessToken(username string, jwtkey string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := types.Claims{
		TokenType: "access_token",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString([]byte(jwtkey))
	if err != nil {
		return "", fmt.Errorf("could not sign access token: %w", err)
	}
	return accessToken, nil
}

func newRefreshToken(username string, jwtkey string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := types.Claims{
		TokenType: "refresh_token",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   username,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	refreshToken, err := token.SignedString([]byte(jwtkey))
	if err != nil {
		return "", fmt.Errorf("could not sign refresh token: %w", err)
	}
	return refreshToken, nil
}
