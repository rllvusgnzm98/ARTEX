package main

import (
	"fmt"
	"os"
)

var banner = "classic"

func main() {
	if len(os.Args) != 2 {
		fmt.Println("denied")
		return
	}
	switch os.Args[1] {
	case "banner":
		fmt.Println(banner)
	case "normal":
		fmt.Println("normal")
	default:
		fmt.Println("denied")
	}
}
