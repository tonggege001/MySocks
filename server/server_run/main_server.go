package main

import (
	"fmt"
	"mysocks/server"
)

const (
	DefaultListenAddr = ":3090"
	DefaultPassword   = "12345"
)

var Config map[string]string

//lint ignore U1000 because
func main() {
	Config = make(map[string]string)
	Config["ListenAddr"] = DefaultListenAddr
	Config["Password"] = DefaultPassword

	// 启动server端并监听
	socksServer, err := server.NewServer(Config)
	if err != nil {
		fmt.Printf("ERROR\t\tserver.NewServer err=%v, Config=%v\n", err, Config)
		return
	}

	socksServer.Listen()
}


