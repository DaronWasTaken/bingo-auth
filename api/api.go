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
	env        types.Env
}

func NewServer(listenAddr string, env types.Env) *Server {
	db, err := db.NewDbPostgres(env)
	DB = db
	if err != nil {
		panic(err)
	}
	return &Server{
		listenAddr: listenAddr,
		env: env,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	h := handler.NewAuthHandler(DB, s.env)

	mux.HandleFunc("POST /register", h.Register)
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /refresh", h.Refresh)

	server := http.Server{
		Addr:    s.listenAddr,
		Handler: handler.LoggingMiddleware(mux),
	}

	return server.ListenAndServe()
}