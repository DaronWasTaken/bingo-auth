package main

import (
	"bingo-auth/api"
	"bingo-auth/types"
	"log"
)

func main() {
	s := api.NewServer(":8081", types.NewEnv())
	log.Printf("Server started on :8081")
	s.Start()
}
