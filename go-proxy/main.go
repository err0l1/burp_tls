package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	port        int
	verbose     bool
	fingerprint string
	mode        string // "transparent" or "fingerprint"
)

// 预定义的指纹列表
var fingerprints = map[string]utls.ClientHelloID{
	"random":             utls.HelloRandomized,
	"random_per_request": utls.HelloRandomized,
	"chrome_120":         utls.HelloChrome_120,
	"chrome_110":         utls.HelloChrome_120,
	"firefox_120":        utls.HelloFirefox_120,
	"firefox_110":        utls.HelloFirefox_105,
	"safari_17":          utls.HelloSafari_16_0,
	"edge_120":           utls.HelloEdge_106,
	"ios_17":             utls.HelloIOS_14,
	"android_chrome":     utls.HelloAndroid_11_OkHttp,
	"curl":               utls.HelloGolang,
	"golang":             utls.HelloGolang,
	"okhttp":             utls.HelloAndroid_11_OkHttp,
}

// 随机指纹池
var randomFingerprintPool = []utls.ClientHelloID{
	utls.HelloChrome_120,
	utls.HelloFirefox_120,
	utls.HelloFirefox_105,
	utls.HelloSafari_16_0,
	utls.HelloEdge_106,
	utls.HelloIOS_14,
	utls.HelloRandomized,
}

func main() {
	flag.IntVar(&port, "port", 18443, "Proxy server port")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&fingerprint, "fingerprint", "chrome_120", "TLS fingerprint to use")
	flag.StringVar(&mode, "mode", "transparent", "Proxy mode: transparent or fingerprint")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	log.Printf("Starting TLS Proxy on port %d, mode: %s, fingerprint: %s", port, mode, fingerprint)

	// 启动 TCP 代理服务器
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy server listening on :%d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	// 读取第一行请求
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		if verbose {
			log.Printf("Error reading request: %v", err)
		}
		return
	}

	// 解析请求
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		if verbose {
			log.Printf("Invalid request line: %s", requestLine)
		}
		return
	}

	method := parts[0]
	target := parts[1]

	// 读取所有头部
	headers := make(map[string]string)
	var rawHeaders []string
	rawHeaders = append(rawHeaders, requestLine)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			rawHeaders = append(rawHeaders, line)
			break
		}
		rawHeaders = append(rawHeaders, line)
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			key := strings.TrimSpace(trimmed[:idx])
			value := strings.TrimSpace(trimmed[idx+1:])
			headers[key] = value
		}
	}

	if method == "CONNECT" {
		// 处理 HTTPS CONNECT 隧道
		handleConnect(clientConn, reader, target)
	} else {
		// 处理普通 HTTP 请求（直接转发）
		handleHTTP(clientConn, reader, target, headers, rawHeaders)
	}
}

func handleConnect(clientConn net.Conn, reader *bufio.Reader, target string) {
	// 解析目标地址
	host, portStr, err := parseTarget(target)
	if err != nil {
		log.Printf("Invalid target: %s", target)
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetAddr := fmt.Sprintf("%s:%s", host, portStr)

	if verbose {
		log.Printf("CONNECT to %s (mode: %s)", targetAddr, mode)
	}

	// 建立 TCP 连接到目标
	tcpConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if mode == "fingerprint" {
		// 指纹伪装模式：使用 uTLS 建立 TLS 连接
		handleConnectWithFingerprint(clientConn, tcpConn, host, targetAddr)
	} else {
		// 透明模式：直接转发
		handleConnectTransparent(clientConn, tcpConn)
	}
}

// 透明模式：直接转发 TCP 数据
func handleConnectTransparent(clientConn net.Conn, tcpConn net.Conn) {
	// 发送 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(tcpConn, clientConn)
		tcpConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, tcpConn)
	}()

	wg.Wait()
}

// 指纹伪装模式：使用 uTLS
func handleConnectWithFingerprint(clientConn net.Conn, tcpConn net.Conn, host, targetAddr string) {
	// 使用 uTLS 建立 TLS 连接
	clientHelloID := getClientHelloID(fingerprint)
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	tlsConn := utls.UClient(tcpConn, config, clientHelloID)

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake failed for %s: %v, falling back to transparent mode", targetAddr, err)
		tcpConn.Close()
		// 回退到透明模式
		newTcpConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
		if err != nil {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		handleConnectTransparent(clientConn, newTcpConn)
		return
	}

	if verbose {
		state := tlsConn.ConnectionState()
		log.Printf("TLS connected to %s (version: %x, cipher: %x)", targetAddr, state.Version, state.CipherSuite)
	}

	// 发送 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发：Burp(明文) <-> Go代理 <-> 目标(TLS)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(tlsConn, clientConn)
		tlsConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, tlsConn)
	}()

	wg.Wait()
}

func handleHTTP(clientConn net.Conn, reader *bufio.Reader, target string, headers map[string]string, rawHeaders []string) {
	// 解析 URL 获取目标主机
	host := headers["Host"]
	if host == "" {
		log.Printf("No host specified")
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 从 Host 中提取端口
	portStr := "80"
	hostOnly := host
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			hostOnly = h
			portStr = p
		}
	}

	targetAddr := fmt.Sprintf("%s:%s", hostOnly, portStr)

	if verbose {
		log.Printf("HTTP request to %s", targetAddr)
	}

	// 建立 TCP 连接（HTTP 不需要 TLS）
	destConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// 转发原始请求头
	for _, line := range rawHeaders {
		destConn.Write([]byte(line))
	}

	// 如果有请求体，转发请求体
	if contentLength := headers["Content-Length"]; contentLength != "" {
		var length int64
		fmt.Sscanf(contentLength, "%d", &length)
		if length > 0 {
			io.CopyN(destConn, reader, length)
		}
	}

	// 转发响应
	io.Copy(clientConn, destConn)
}

func parseTarget(target string) (host, port string, err error) {
	if strings.Contains(target, ":") {
		host, port, err = net.SplitHostPort(target)
		if err != nil {
			return "", "", err
		}
	} else {
		host = target
		port = "443"
	}
	return host, port, nil
}

// 使用 uTLS 建立 TLS 连接
func dialTLS(target, serverName, fingerprintID string) (net.Conn, error) {
	// 建立 TCP 连接
	tcpConn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %v", err)
	}

	// 获取 ClientHello ID
	clientHelloID := getClientHelloID(fingerprintID)

	if verbose {
		log.Printf("Using ClientHello: %v for %s", clientHelloID, target)
	}

	// 创建 uTLS 配置
	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}

	// 创建 uTLS 连接
	tlsConn := utls.UClient(tcpConn, config, clientHelloID)

	// 执行握手
	err = tlsConn.Handshake()
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	if verbose {
		state := tlsConn.ConnectionState()
		log.Printf("TLS connected to %s, version: %x, cipher: %x",
			target, state.Version, state.CipherSuite)
	}

	return tlsConn, nil
}

func getClientHelloID(fingerprintID string) utls.ClientHelloID {
	if fingerprintID == "" || fingerprintID == "random" {
		return utls.HelloRandomized
	}

	if fingerprintID == "random_per_request" {
		return randomFingerprintPool[rand.Intn(len(randomFingerprintPool))]
	}

	if fp, ok := fingerprints[fingerprintID]; ok {
		return fp
	}

	return utls.HelloChrome_120
}
