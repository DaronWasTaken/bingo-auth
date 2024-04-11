package main

import (
	"bingo-auth/api"
	"log"
)

func main() {
	s := api.NewServer(":8081")
	log.Printf("Server started on :8081")
	s.Start()
}
