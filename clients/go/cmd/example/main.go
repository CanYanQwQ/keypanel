package main

import (
	"encoding/json"
	"fmt"
	"os"

	"example.com/cardkey-api-client/cardkey"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: cardkey-example verify|activate|consume|query|unbind CARD_KEY [DEVICE_ID]")
		os.Exit(2)
	}
	appID, secret, baseURL := os.Getenv("CARDKEY_APP_ID"), os.Getenv("CARDKEY_APP_SECRET"), os.Getenv("CARDKEY_BASE_URL")
	card, err := cardkey.EncryptCardKey(os.Args[2], secret, appID)
	if err != nil {
		panic(err)
	}
	input := map[string]any{"card_key": card}
	if len(os.Args) >= 4 {
		input["device_id"] = os.Args[3]
	}
	client, err := cardkey.NewClient(baseURL, appID, secret)
	if err != nil {
		panic(err)
	}
	var result cardkey.APIResponse
	switch os.Args[1] {
	case "verify":
		result, err = client.Verify(input)
	case "activate":
		result, err = client.Activate(input)
	case "consume":
		input["count"] = 1
		result, err = client.Consume(input)
	case "query":
		result, err = client.Query(input)
	case "unbind":
		input["force"] = false
		result, err = client.Unbind(input)
	default:
		panic("unknown action")
	}
	if err != nil {
		panic(err)
	}
	output, _ := json.Marshal(result)
	fmt.Println(string(output))
}
