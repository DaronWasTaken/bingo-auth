package main

import (
	"bingo-auth/api"
)

func main() {
	s := api.NewServer("localhost:8081")
	s.Start()
	
}
