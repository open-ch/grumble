package main

import (
	"log"

	"osag/tools/grumble/cmd"
)

func main() {
	if err := cmd.GetRootCommand().Execute(); err != nil {
		log.Fatalln(err)
	}
}
