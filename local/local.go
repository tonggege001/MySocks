package local

import (
	"lightsocks/core"
	"log"
	"net"
)

type LsLocal struct {
	*core.SecureSocket
}

// 新建一个本地端
func New(password *core.Password, listenAddr, remoteAddr *net.TCPAddr) *LsLocal {
	return  &LsLocal{
		SecureSocket: &core.SecureSocket{
			Cipher: 	core.NewCipher(password),
			ListenAddr: listenAddr,
			RemoteAddr: remoteAddr,
		},
	}
}

// 本地端启动，接受来自本机浏览器的连接
func (local *LsLocal) Listen(didListen func(listenAddr net.Addr))error {
	listener, err := net.ListenTCP("tcp", local.ListenAddr)
	if err != nil {
		return err
	}

	defer listener.Close()
	if didListen != nil {
		didListen(listener.Addr())
	}

	for {
		userConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		// userConn 被关闭时直接清除所有数据
		userConn.SetLinger(0)
		go local.handleConn(userConn)
	}
}

func (local *LsLocal) handleConn(userConn *net.TCPConn) {
	defer userConn.Close()
	proxyServer, err := local.DialRemote()
	if err != nil {
		log.Println(err)
		return
	}
	defer proxyServer.Close()
	proxyServer.SetLinger(0)

	// 进行转发
	go func() {
		err := local.DecodeCopy(userConn, proxyServer)
		if err != nil {
			// 在copy的过程中可能会存在网络超时等error 被 return
			userConn.Close()
			proxyServer.Close()
		}
	}()
	// 从localUser发送数据到
	local.EncodeCopy(proxyServer, userConn)
}



