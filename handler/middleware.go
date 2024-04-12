package handler

import (
	"log"
	"net/http"
	"time"
)

func LoggingMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Since(time.Now())
		customWriter := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		defer func() {
			log.Printf("%s -> [%s] %s [%v] in %s", r.Host, r.Method, r.RequestURI, customWriter.statusCode, start)
		}()
		next.ServeHTTP(customWriter, r)
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
