package main

import (
	"fmt"
	"mysocks/client"
)

const (
	DefaultListenAddr = ":7786"
	DefaultRemoteAddr = "127.0.0.1:3090"
	DefaultPassword   = "12345"
)

var Config map[string]string

//lint ignore U1000 because
func main() {
	Config = make(map[string]string)
	Config["ListenAddr"] = DefaultListenAddr
	Config["RemoteAddr"] = DefaultRemoteAddr
	Config["Password"] = DefaultPassword

	socksClient, err := client.NewClient(Config)
	if err != nil {
		fmt.Printf("ERROR\t\tmain client.NewClient error, err=%v\n", err)
		return
	}

	socksClient.Listen()
}
