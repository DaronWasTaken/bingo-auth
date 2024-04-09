package api

import (
	"bingo-auth/db"
	"bingo-auth/types"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var DB db.DbStorage

type Server struct {
	listenAddr string
}

func NewServer(listenAddr string) *Server {
	db, err := db.NewDbPostgres(types.NewEnv())
	DB = db
	if err != nil {
		panic(err)
	}
	return &Server{
		listenAddr: listenAddr,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", s.register)
	// mux.HandleFunc("POST /login", login)
	// mux.HandleFunc("POST /logout", logout)
	// mux.HandleFunc("POST /refresh", refresh)

	return http.ListenAndServe(s.listenAddr, mux)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	
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

	log.Printf("Register user: %v", credentials)
	log.Printf("Added user: %v", usr)
	w.WriteHeader(201)
}
