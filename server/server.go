package server

import (
	"encoding/binary"
	"fmt"
	"mysocks/core"
	"net"
)

type SocketServer struct {
	Cipher     *core.Cipher
	ListenAddr *net.TCPAddr
}

func NewServer(Config map[string]string) (*SocketServer, error) {
	var password int64 = 0
	fmt.Sscanf(Config["Password"], "%d", &password)

	structListenAddr, err := net.ResolveTCPAddr("tcp", Config["ListenAddr"])
	if err != nil {
		fmt.Printf("ERROR\t\tNewServer net.ResolveTCPAddr ListenAddr=%v, err=%v\n", Config["ListenAddr"], err)
		return nil, err
	}

	return &SocketServer{
		Cipher:     core.NewCipher(password),
		ListenAddr: structListenAddr,
	}, nil
}

func (server *SocketServer) Listen() {
	listener, err := net.ListenTCP("tcp", server.ListenAddr)
	if err != nil {
		fmt.Printf("ERROR\t\tSocketServer.Listen err=%v", err)
		return
	}

	defer listener.Close()
	fmt.Printf(`
		SOCKS5代理服务端启动成功，配置如下：
		本地监听地址： %v\n,
	`, server.ListenAddr)

	for {
		remoteConn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Printf("ERROR\t\tSocketServer.Listen listener.AcceptTCP, err=%v", err)
		}

		// 远程连接关闭时，不管有没有数据传输，都直接清除数据
		remoteConn.SetLinger(0)
		go handleConnection(&core.SecureSocket{
			Cipher:     server.Cipher,
			ListenAddr: server.ListenAddr,
		}, remoteConn)

	}
}

func handleConnection(secureSocket *core.SecureSocket, remoteConn *net.TCPConn) {
	// defer remoteConn.Close()
	buf := make([]byte, 256)

	/**
	   The localConn connects to the dstServer, and sends a ver
	   identifier/method selection message:
		          +----+----------+----------+
		          |VER | NMETHODS | METHODS  |
		          +----+----------+----------+
		          | 1  |    1     | 1 to 255 |
		          +----+----------+----------+
	   The VER field is set to X'05' for this ver of the protocol.  The
	   NMETHODS field contains the number of method identifier octets that
	   appear in the METHODS field.
	*/
	// 第一个字段VER代表Socks的版本，Socks5默认为0x05，其固定长度为1个字节
	n, err := secureSocket.DecodeRead(remoteConn, buf)
	if err != nil {
		// fmt.Printf("ERROR\t\thandleConnection secureSocket.DecodeRead, n=%v, buf=%v, err=%v\n", n, buf, err)
		return
	}

	if buf[0] != 0x05 {
		fmt.Printf("ERROR\t\thandleConnection cannot process version that is not 5 SOCKS, n=%v, buf=%v\n", n, buf)
		return
	}

	/**
	   The dstServer selects from one of the methods given in METHODS, and
	   sends a METHOD selection message:
		          +----+--------+
		          |VER | METHOD |
		          +----+--------+
		          | 1  |   1    |
		          +----+--------+
	*/
	// 不需要验证，直接验证通过
	secureSocket.EncodeWrite(remoteConn, []byte{0x05, 0x00})

	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/

	// 获取真正的远程服务的地址
	n, err = secureSocket.DecodeRead(remoteConn, buf)
	if err != nil || n < 7 {
		// n 最短的长度为7 情况为 ATYP=3 DST.ADDR占用1字节 值为0x0
		fmt.Printf("ERROR\t\thandleConnection secureSocket.DecodeRead err=%v, n=%v\n", err, n)
		return
	}

	// CMD代表客户端请求的类型，值长度也是1个字节，有三种类型
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// 目前只支持 CONNECT
		return
	}

	var dIP []byte
	switch buf[3] {
	case 0x01:
		// IPV4 address
		dIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		// DOMAIN NAME
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			fmt.Printf("ERROR\t\thandleConnection ResolveIPAddr, err=%v\n", err)
			return
		}
		dIP = ipAddr.IP
	case 0x04:
		// IPV6 address
		dIP = buf[4 : 4+net.IPv6len]
	default:
		fmt.Printf("ERROR\t\thandleConnection Cannot find the propoer ip address, buf=%v\n", buf)
		return
	}

	dPort := buf[n-2:]
	dstAddr := &net.TCPAddr{
		IP:   dIP,
		Port: int(binary.BigEndian.Uint16(dPort)),
	}

	// 连接真正的远程主机
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		fmt.Printf("ERROR\t\thandleConnection Dial Remote Server TCP, err=%v\n", err)
		return
	}

	// defer dstServer.Close()
	dstServer.SetLinger(0)
	// 响应客户端连接成功
	/**
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	// 响应客户端连接成功
	secureSocket.EncodeWrite(remoteConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// 进行转发
	// 从 localUser 读取数据发送到 dstServer
	go func() {
		err = secureSocket.DecodeCopy(dstServer, remoteConn)
		if err != nil {
			// 在 copy 的过程中可能会存在网络超时等 error 被 return，只要有一个发生了错误就退出本次工作
			remoteConn.Close()
			dstServer.Close()
			// fmt.Printf("ERROR\t\thandleConnection resent user conn to dstServer, err=%v\n", err)
			return
		}
	}()

	// 从 dstServer 读取数据发送到 localUser，这里因为处在翻墙阶段出现网络错误的概率更大
	secureSocket.EncodeCopy(remoteConn, dstServer)
}
