package client

import (
	"fmt"
	"mysocks/core"
	"net"
)

type SocksClient struct {
	Cipher     *core.Cipher
	ListenAddr *net.TCPAddr
	RemoteAddr *net.TCPAddr
}

func NewClient(Config map[string]string) (*SocksClient, error) {
	var password int64 = 0
	fmt.Sscanf(Config["Password"], "%d", &password)

	structListenAddr, err := net.ResolveTCPAddr("tcp", Config["ListenAddr"])
	if err != nil {
		fmt.Printf("ERROR\t\tNewClient net.ResolveTCPAddr ListenAddr=%v, err=%v\n", Config["ListenAddr"], err)
		return nil, err
	}

	structRemoteAddr, err := net.ResolveTCPAddr("tcp", Config["RemoteAddr"])
	if err != nil {
		fmt.Printf("ERROR\t\tNewClient net.ResolveRCPAddr RemoteAddr=%v, err=%v\n", Config["RemoteAddr"], err)
		return nil, err
	}

	return &SocksClient{
		Cipher:     core.NewCipher(password),
		ListenAddr: structListenAddr,
		RemoteAddr: structRemoteAddr,
	}, nil
}

func (client *SocksClient) Listen() {
	listener, err := net.ListenTCP("tcp", client.ListenAddr)
	if err != nil {
		fmt.Printf("ERROR\t\tSocketsCLient.Listen net.ListenTCP error, err=%v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf(`
		SOCKS5代理客户端启动成功, 配置如下：
		本地监听地址: \t%v,	
		远程服务地址: \t%v,
		`, client.ListenAddr, client.RemoteAddr)
	for {
		localConn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Printf("ERROR\t\tSocksClient.Listen AcceptTCP, err=%v, client=%v\n", err, client)
		}

		// localConn被关闭时直接清除所有数据 不管有没有发送的数据
		localConn.SetLinger(0)
		go handleConnection(&core.SecureSocket{
			ListenAddr: client.ListenAddr,
			RemoteAddr: client.RemoteAddr,
			Cipher:     client.Cipher,
		}, localConn)
	}
}

func handleConnection(secureSocket *core.SecureSocket, localConn *net.TCPConn) {
	defer localConn.Close()

	serverConn, err := secureSocket.DialRemote()
	if err != nil {
		fmt.Printf("ERROR\t\t client.handleConnection secureSocket.DialRemote err=%v\n", err)
		return
	}
	defer serverConn.Close()

	// 从 localUser 发送数据发送到 proxyServer，这里因为处在翻墙阶段出现网络错误的概率更大
	go func() {
		err := secureSocket.DecodeCopy(localConn, serverConn)
		if err != nil {
			// 这个log要屏蔽，因为浏览器对TCP信道复用导致代理难以保持这种状态，所以每次要发送下一个请求的时候，总是用原来的通道。
			// 结果这里关闭了，所以第一次总会ERROR， 然后建立新的通道连接
			// fmt.Printf("ERROR\t\thandleConnection secureSocket.DecodeCopy error, err=%v\n", err)
			localConn.Close()
			serverConn.Close()
		}
	}()
	secureSocket.EncodeCopy(serverConn, localConn)
}
