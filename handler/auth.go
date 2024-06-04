package handler

import (
	"bingo-auth/db"
	"bingo-auth/types"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
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
		Id:       string(uuid.New().String()),
		Username: credentials.Username,
		Hash:     string(hash),
	}

	err = DB.Add(usr)
	if err != nil {
		log.Printf("Failed to add user: %s", err)
		var myError types.APIError
		if ok := errors.As(err, &myError); ok {
			http.Error(w, myError.Text, myError.Code)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Write([]byte(usr.Id))
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	usr := types.CredentialRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}

	if usr.Username == "" {
		log.Print("Username empty")
		http.Error(w, "Username empty", http.StatusBadRequest)
		return
	}

	if usr.Password == "" {
		log.Print("Password empty")
		http.Error(w, "Password empty", http.StatusBadRequest)
		return
	}

	userDb, err := DB.GetUserCredentials(usr.Username)
	if err != nil {
		log.Printf("Failed to retrieve user password: %s", err)
		http.Error(w, "Internal server error", 500)
		return
	}
	if userDb.Hash == "" {
		log.Printf("User not found during login: %s", usr.Username)
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(userDb.Hash), []byte(usr.Password))
	if err != nil {
		log.Printf("Failed login attempt: %s", err)
		http.Error(w, "Username or password incorrect", http.StatusUnauthorized)
		return
	}

	accessToken, accessTokenClaims := newAccessToken(userDb.Id)
	signedAccessToken, err := accessToken.SignedString([]byte(Env.Jwtkey))
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	refreshToken, refreshTokenClaims := newRefreshToken(userDb.Id)
	signedRefreshToken, err := refreshToken.SignedString([]byte(Env.Jwtkey))
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	dbToken := types.Token{
		Id:               userDb.Id,
		AccessToken:      signedAccessToken,
		RefreshToken:     signedRefreshToken,
		AccessExpiresAt:  time.Unix(accessTokenClaims.ExpiresAt, 0),
		RefreshExpiresAt: time.Unix(refreshTokenClaims.ExpiresAt, 0),
		CreatedAt:        time.Now(),
	}

	err = DB.UpdateOrCreateToken(dbToken)
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	resBody := types.TokenResponse{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
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

	accessToken, accessTokenClaims := newAccessToken(claims.Subject)
	signedAccessToken, err := signToken(accessToken)
	if err != nil {
		log.Printf("Failed to create token during refresh: %s", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	dbToken := types.Token{
		Id:              claims.Subject,
		AccessToken:     signedAccessToken,
		RefreshToken:    refreshTokenInput,
		AccessExpiresAt: time.Unix(accessTokenClaims.ExpiresAt, 0),
	}

	err = DB.UpdateTokenOnRefresh(dbToken)
	if err != nil {
		log.Printf("Failed to create token during refresh: %s", err)
		var apiError types.APIError
		if errors.As(err, &apiError) {
			http.Error(w, apiError.Text, apiError.Code)
		} else {
			http.Error(w, "Internal Server Error", 500)
		}
		return
	}

	resBody := types.TokenResponse{
		AccessToken:  signedAccessToken,
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

func newAccessToken(userId string) (*jwt.Token, types.Claims) {
	expirationTime := time.Now().Add(time.Duration(Env.AccessTokenTime) * time.Minute)
	claims := types.Claims{
		TokenType: "access_token",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   userId,
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims), claims
}

func newRefreshToken(userId string) (*jwt.Token, types.Claims) {
	expirationTime := time.Now().Add(time.Duration(Env.RefreshTokenTime) * time.Minute)
	claims := types.Claims{
		TokenType: "refresh_token",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   userId,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims), claims
}

func signToken(token *jwt.Token) (string, error) {
	return token.SignedString([]byte(Env.Jwtkey))
}
