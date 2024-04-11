package handler

import (
	"log"
	"net/http"
	"time"
)

func LoggingMiddleware(next http.Handler) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		start := time.Since(time.Now())
		log.Printf("%s -> [%s] %s in %s", r.Host, r.Method, r.RequestURI, start)
		next.ServeHTTP(w, r)
	}
}