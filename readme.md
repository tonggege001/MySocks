# MySocks: A SOCKS5 Proxy  

最近在看《HTTP权威指南》，学习了一些应用层的网络知识，然后就好奇Shadowsocks的原理是怎样的，于是乎就查找资料了解。偶然在Github上看到了一个大佬对shadowsocks的讲解和简单实现([链接](https://github.com/gwuhaolin/blog/issues/12))，就跟着学习和复现了一下。  

Shadowsocks本质上就是一个加密了的SOCKS5代理，代理的位置放在了服务器端，客户端这边只监听本地的TCP请求，然后把TCP请求进行加密后转发到代理，代理进行解密然后去请求所需要的数据，接下来代理对请求后的数据进行加密发送到客户端，客户端进行解密返回给原来的请求。  

> 我个人认为这里不能用HTTP代理的原因很明显，就是HTTP的报文头是明文的，GFW能够检测出来请求的位置，这样轻而易举地就可以阻断连接；而SOCKS5代理报文的所有内容全部是加密的，所以GFW很难探测出来，不过可以根据机器学习、统计学和NLP的一些特征学习出来。（例如中文“的”，英文“the”的出现最频繁，这样如果像原作者一样采用table加密，直接统计最频繁的一些数据就能推测出这些字母）。（我没试过HTTP代理能不能用，这是我的推测，而且即使能用也只能请求个网页，对一些不是HTTP请求的处理还是无法用）

不过我思考了一下，如果真的想屏蔽所有外链，其实最简单的就是在网络层上屏蔽外网的所有IP就可以了，但是为什么没这么做，我推测是某些情况下还是要允许访问外网的（比如留学生来中国留学，他们应该是默许使用的）。  


## 一、加密部分  
这部分就是直接对从浏览器打过来的请求进行加密，原封不动地按照某种加密方式就可以了，这里可以采用Table加密，就是直接来个0-255的一一对应的映射即可。  
```go  
const PasswordLength = 256

type Password [PasswordLength]byte

type Cipher struct {
	encodePassword *Password
	decodePassword *Password
}

// 加密原数据
func (cipher *Cipher) encode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.encodePassword[v]
	}
}

// 解码原数据
func (cipher *Cipher) decode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.decodePassword[v]
	}
}

// 新建一个编解码器
func NewCipher(password int64) *Cipher {
	rand.Seed(password)
	intArr := rand.Perm(PasswordLength)

	cipher := &Cipher{
		encodePassword: new(Password),
		decodePassword: new(Password),
	}

	for i, v := range intArr {
		cipher.encodePassword[i] = byte(v)
		cipher.decodePassword[v] = byte(i)
	}

	fmt.Printf("Cifer Encode: %v, \nDecode: %v\n", cipher.encodePassword, cipher.decodePassword)
	return cipher
}

```  
当然更高级的方法还有DES, RC4, RC2等（这里不能使用RSA，不对称加密一般只是用作对称加密的密钥交换，因为RSA加密非常慢）。  

从TCP连接里加密地读和写就可以表示为：  
```go  
// 从输入流里读取加密过的数据，解密后把原数据放到bs里
func (secureSocket *SecureSocket) DecodeRead(conn *net.TCPConn, bs []byte) (n int, err error) {
	n, err = conn.Read(bs)
	if err != nil {
		return 0, fmt.Errorf("DecodeRead Error, err=%v, conn=%v", err, conn)
	}
	secureSocket.Cipher.decode(bs[:n])
	return
}

// 把放在bs里的数据加密后写入到输出流里
func (secureSocket *SecureSocket) EncodeWrite(conn *net.TCPConn, bs []byte) (int, error) {
	secureSocket.Cipher.encode(bs)
	return conn.Write(bs)
}

// 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可读
func (secureSocket *SecureSocket) EncodeCopy(dst *net.TCPConn, src *net.TCPConn) error {
	buf := make([]byte, BufSize)
	for {
		readCount, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, err := secureSocket.EncodeWrite(dst, buf[0:readCount])
			if err != nil {
				return err
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}
// 从src中源源不断读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureSocket) DecodeCopy(dst *net.TCPConn, src *net.TCPConn) error {
	buf := make([]byte, BufSize)
	for {
		readCount, err := secureSocket.DecodeRead(src, buf)
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, err := dst.Write(buf[0:readCount])
			if err != nil {
				return err
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}
```


## 二、客户端部分

客户端实际上就是监听本地的一些请求，然后将其加密转发到代理上。所以需要先配置浏览器走代理（或者直接配置计算机上所有请求都走代理，Mac的方法是系统偏好设置->网络->高级->代理）。然后代码如下：  
```go  
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
```
客户端监听ListenTCP，绑定监听地址；然后阻塞到AcceptTCP，当本机的一个请求都打进来后往下走处理逻辑。localConn.SetLinger(0)是作者的一个折中办法，后面我会讲这个socks的问题（作者发现了内存泄漏的问题，但是可能作者也没发现为什么会内存泄漏）。  

然后就是处理逻辑：  
```go  
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
```  
上面就是出现问题的所在，因为现在的浏览器都是TCP信道复用的，还有keep-alive保持连接状态的，而这个的处理逻辑是每次请求后都直接关闭，没有考虑keep-alive和TCP信道复用的问题，这样第一个请求是可以得到应答的，而第二个请求会默认使用上一个信道，然而代理这边已经关闭了信道，就会导致浏览器会默认等待应答然而TCP已经关闭，所以浏览器会发送两次一模一样的HTTP请求，而代理这边对第一次请求会显示"reused connect closed"的error，第二次才能正常发送请求（然而第二次的复用会让第三次请求error）。  

作者的一个折中办法就是SetLinger(0),每次失败关闭连接的时候都停止，然后释放所有资源，这样就不会内存溢出。但是多次请求的问题还是没有有效解决。所以keep-alive在处理代理问题上还是需要认真研究一下的。《HTTP权威指南》[4.5.6节](https://www.jianshu.com/p/88f65746201a)里有提到过HTTP的哑代理的问题，这里可以借鉴一下问题所在，而HTTP代理的解决方法是Proxy-Connection: Keep-Alive，SOCKS代理的解决方法可以是先不要提前关闭连接，直接timeout后自动释放连接，这样高峰时期的内存肯定大于BUFFER SIZE，当所有连接都timeout后会自动释放。  

另外，客户端部分不用解析和构造SOCKS5协议的报文，因为党浏览器设置好代理或者计算机设置好全局SOCKS代理后，所有的报文都会自动构造好传给客户端，但是服务端需要解析SOCKS5报文。

## 三、服务器部分

服务器部分需要解析SOCKS5协议，找到客户端想要访问的位置进行访问，然后转发给客户端。  
```go  

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
```  
SOCKS5响应逻辑是，客户端先发送一个CONNECT请求（这点和HTTP代理有点像），里面附加了版本号方法等信息，然后服务器进行认证和响应，然后返回一个Response。然后客户端再返回一个带有目标远程主机资源的地址，代理服务器请求完毕后返回给客户端。代理服务器这边也存在内存泄漏问题，原因也是TCP链路复用情况。  

以上就是主体逻辑。











