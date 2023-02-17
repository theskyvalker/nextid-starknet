package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"github.com/nextdotid/proof_server/cli/generate"
	"github.com/nextdotid/proof_server/cli/query"
)

const (
	OPERATION_QUERY    = 1
	OPERATION_GENERATE = 2
)

func main() {
	input := bufio.NewScanner(os.Stdin)
	fmt.Println("Choose the process\n 1. query the exists proof\n 2. generate the signature and upload to proof service\nEnter the number of above process")

	input.Scan()
	operation, _ := strconv.Atoi(input.Text())

	switch operation {
	case OPERATION_QUERY:
		query.QueryProof()
	case OPERATION_GENERATE:
		generate.GeneratePayload()
	default:
		fmt.Printf("Unknow Operation: %s", operation)
		os.Exit(-1)
	}
}
