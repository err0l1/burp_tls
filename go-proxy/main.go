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
	port    int
	verbose bool
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
	flag.BoolVar(&verbose, "verbose", true, "Enable verbose logging")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	log.Printf("Starting TLS Fingerprint Proxy on port %d", port)

	// 启动 TCP 代理服务器（处理 CONNECT 隧道）
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
		log.Printf("Error reading request: %v", err)
		return
	}

	// 解析请求
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		log.Printf("Invalid request line: %s", requestLine)
		return
	}

	method := parts[0]
	target := parts[1]

	// 读取所有头部
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	// 获取指纹配置
	fingerprintID := headers["X-TLS-Fingerprint"]
	if fingerprintID == "" {
		fingerprintID = "chrome_120" // 默认使用 Chrome 指纹
	}

	if verbose {
		log.Printf("Method: %s, Target: %s, Fingerprint: %s", method, target, fingerprintID)
	}

	if method == "CONNECT" {
		// 处理 HTTPS CONNECT 隧道
		handleConnect(clientConn, target, fingerprintID)
	} else {
		// 处理普通 HTTP 请求（转发到 HTTPS）
		handleHTTPRequest(clientConn, reader, method, target, headers, fingerprintID)
	}
}

func handleConnect(clientConn net.Conn, target string, fingerprintID string) {
	// 解析目标地址
	host, port, err := parseTarget(target)
	if err != nil {
		log.Printf("Invalid target: %s", target)
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetAddr := fmt.Sprintf("%s:%s", host, port)

	if verbose {
		log.Printf("CONNECT to %s with fingerprint %s", targetAddr, fingerprintID)
	}

	// 建立到目标的 TLS 连接
	destConn, err := dialTLS(targetAddr, host, fingerprintID)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// 发送 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发数据
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(destConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, destConn)
	}()

	wg.Wait()
}

func handleHTTPRequest(clientConn net.Conn, reader *bufio.Reader, method, target string, headers map[string]string, fingerprintID string) {
	// 解析 URL
	host := headers["Host"]
	if host == "" {
		host = headers["X-TLS-Target-Host"]
	}
	if host == "" {
		log.Printf("No host specified")
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	port := "443"
	if p := headers["X-TLS-Target-Port"]; p != "" {
		port = p
	}

	targetAddr := fmt.Sprintf("%s:%s", host, port)

	if verbose {
		log.Printf("HTTP request to %s with fingerprint %s", targetAddr, fingerprintID)
	}

	// 建立 TLS 连接
	destConn, err := dialTLS(targetAddr, host, fingerprintID)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// 重建请求
	path := target
	if strings.HasPrefix(target, "http") {
		// 提取路径
		if idx := strings.Index(target[8:], "/"); idx >= 0 {
			path = target[8+idx:]
		} else {
			path = "/"
		}
	}

	// 发送请求行
	fmt.Fprintf(destConn, "%s %s HTTP/1.1\r\n", method, path)

	// 发送头部（排除自定义头）
	for key, value := range headers {
		if !strings.HasPrefix(key, "X-TLS-") && key != "Proxy-Connection" {
			fmt.Fprintf(destConn, "%s: %s\r\n", key, value)
		}
	}
	fmt.Fprintf(destConn, "\r\n")

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
