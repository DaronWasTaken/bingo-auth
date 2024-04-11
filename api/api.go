package api

import (
	"bingo-auth/db"
	"bingo-auth/handler"
	"bingo-auth/types"
	"net/http"
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

	h := handler.NewAuthHandler(DB, types.NewEnv())

	mux.HandleFunc("POST /register", h.Register)
	mux.HandleFunc("POST /login", h.Login)

	// mux.HandleFunc("POST /logout", logout)
	// mux.HandleFunc("POST /refresh", refresh)

	server := http.Server{
		Addr:    s.listenAddr,
		Handler: handler.LoggingMiddleware(mux),
	}

	return server.ListenAndServe()
}
