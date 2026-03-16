package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Veritas Service: Managed JSON-RPC 2.0 over TCP
type VeritasService struct {
	Proxy *ProxyServer
}

type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type SmuggleResult struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Proof    string `json:"proof"`
}

type ScanResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
}

type ProbeResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status"`
	Server     string `json:"server"`
	Title      string `json:"title"`
}

func getStealthClient(timeout int, proxyList []string) *http.Client {
	// v51.0 Apex Protocol: Custom TLS Handshake to mimic Chrome 120
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Identity Mesh: Proxy Rotation
	if len(proxyList) > 0 {
		var proxyMu sync.Mutex
		proxyIdx := 0
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			proxyMu.Lock()
			defer proxyMu.Unlock()
			p := proxyList[proxyIdx%len(proxyList)]
			proxyIdx++
			return url.Parse(p)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Millisecond,
	}
}

func main() {
	mode := flag.String("mode", "", "scan or probe")
	target := flag.String("target", "", "IP or JSON URL list")
	portsJson := flag.String("ports", "[]", "JSON port list")
	concurrency := flag.Int("c", 100, "concurrency")
	timeout := flag.Int("t", 1500, "timeout ms")
	stealth := flag.Bool("stealth", false, "Enable JA3/JA4 fingerprinting bypass")
	proxiesJson := flag.String("proxies", "[]", "JSON proxy list for Identity Mesh")
	flag.Parse()

	var proxyList []string
	json.Unmarshal([]byte(*proxiesJson), &proxyList)

	if *mode == "scan" {
		runScan(*target, *portsJson, *concurrency, *timeout)
	} else if *mode == "probe" {
		runProbe(*target, *concurrency, *timeout, *stealth, proxyList)
	} else if *mode == "race" {
		runRace(*target, *concurrency, *timeout, *portsJson, *stealth, proxyList)
	} else if *mode == "smuggle" {
		runSmuggle(*target, *timeout)
	} else if *mode == "proxy" {
		runProxy(*concurrency, *target) // port via concurrency, logfile via target
	} else if *mode == "veritas" {
		port := 50051
		fmt.Sscanf(*target, "%d", &port) // using target flag for port in veritas mode
		service := &VeritasService{}
		service.Start(port)
	} else {
		fmt.Println("Usage: nexus -mode=scan|probe|race|smuggle|proxy|veritas -target=... -ports=... -stealth -proxies='[\"http://...\", ...]'")
		os.Exit(1)
	}
}

func runSmuggle(targetURL string, timeout int) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var results []SmuggleResult
	
	// v51.0 Apex Phase 2: CL.TE Discovery Probe
	cltePayload := "POST " + u.Path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"1\r\nZ\r\n0\r\n\r\n"

	if checkSmuggle(host, u.Scheme == "https", cltePayload, timeout) {
		results = append(results, SmuggleResult{
			URL: targetURL, Type: "CL.TE Potential", Severity: "CRITICAL", Proof: "Timeout/Desync on CL.TE probe",
		})
	}

	// TE.CL Discovery Probe
	teclPayload := "POST " + u.Path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\nX"

	if checkSmuggle(host, u.Scheme == "https", teclPayload, timeout) {
		results = append(results, SmuggleResult{
			URL: targetURL, Type: "TE.CL Potential", Severity: "CRITICAL", Proof: "Timeout/Desync on TE.CL probe",
		})
	}

	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

func checkSmuggle(host string, isTLS bool, payload string, timeoutMs int) bool {
	var conn net.Conn
	var err error
	timeout := time.Duration(timeoutMs) * time.Millisecond

	if isTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", host, timeout)
	}

	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return false
	}

	start := time.Now()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if time.Since(start) >= (timeout - 100*time.Millisecond) {
				return true
			}
		}
		return false
	}
	
	// If we got a response too quickly for a probe that should time out, it's NOT smuggling (usually)
	// But in some cases, a 400 Bad Request immediately is also an indicator.
	// For simplicity, we stick to the timeout indicator for now.
	_ = n
	return false
}

func runRace(urlStr string, concurrency int, timeout int, data string, stealth bool, proxyList []string) {
	var results []ProbeResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	startGate := make(chan struct{})
	var client *http.Client
	if stealth {
		client = getStealthClient(timeout, proxyList)
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: time.Duration(timeout) * time.Millisecond,
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate 
			
			resp, err := client.Post(urlStr, "application/json", nil)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			results = append(results, ProbeResult{
				URL:        urlStr,
				StatusCode: resp.StatusCode,
				Server:     resp.Header.Get("Server"),
			})
			mu.Unlock()
		}()
	}

	close(startGate)
	wg.Wait()
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

func runScan(ip string, portsJson string, concurrency int, timeout int) {
	var ports []int
	json.Unmarshal([]byte(portsJson), &ports)

	var results []ScanResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, ScanResult{Port: p, State: "open", Service: "unknown"})
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

func runProbe(urlsJson string, concurrency int, timeout int, stealth bool, proxyList []string) {
	var urls []string
	json.Unmarshal([]byte(urlsJson), &urls)

	var results []ProbeResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)

	var client *http.Client
	if stealth {
		client = getStealthClient(timeout, proxyList)
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: time.Duration(timeout) * time.Millisecond,
		}
	}

	for _, u := range urls {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Set browser headers for stealth
			req, _ := http.NewRequest("GET", urlStr, nil)
			if stealth {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			results = append(results, ProbeResult{
				URL:        urlStr,
				StatusCode: resp.StatusCode,
				Server:     resp.Header.Get("Server"),
			})
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

// TrafficLog represents a captured HTTP request/response pair
type TrafficLog struct {
	Timestamp       int64             `json:"timestamp"`
	ID              string            `json:"id"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	ResponseStatus  int               `json:"response_stats"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
}

type ProxyServer struct {
	Port    int
	LogFile string
}

func (s *ProxyServer) Start() {
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", s.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				s.handleTunnel(w, r)
			} else {
				s.handleHTTP(w, r)
			}
		}),
	}
	fmt.Printf("[*] Nexus Proxy listening on :%d (Logging to %s)\n", s.Port, s.LogFile)
	log.Fatal(server.ListenAndServe())
}

func (s *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	traffic := TrafficLog{
		Timestamp:      time.Now().Unix(),
		Method:         r.Method,
		URL:            r.URL.String(),
		RequestHeaders: make(map[string]string),
	}
	for k, vv := range r.Header {
		traffic.RequestHeaders[k] = fmt.Sprintf("%v", vv)
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	traffic.RequestBody = string(bodyBytes)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	transport := http.DefaultTransport
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	traffic.ResponseStatus = resp.StatusCode
	traffic.ResponseHeaders = make(map[string]string)
	for k, vv := range resp.Header {
		traffic.ResponseHeaders[k] = fmt.Sprintf("%v", vv)
	}

	respBody, _ := io.ReadAll(resp.Body)
	traffic.ResponseBody = string(respBody)

	s.saveTraffic(traffic)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (s *ProxyServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}
	go s.transfer(destConn, clientConn)
	go s.transfer(clientConn, destConn)
}

func (s *ProxyServer) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (s *ProxyServer) saveTraffic(t TrafficLog) {
	f, err := os.OpenFile(s.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(t)
	f.Write(data)
	f.WriteString("\n")
}

func runProxy(port int, logFile string) {
	server := &ProxyServer{
		Port:    port,
		LogFile: logFile,
	}
	server.Start()
}

func (s *VeritasService) Start(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("[!] Veritas failed to listen: %v", err)
	}
	log.Printf("[🚀] Veritas High-Performance Bridge listening on %d", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *VeritasService) handleConnection(conn net.Conn) {
	defer conn.Close()
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req RPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		var result interface{}
		var rpcErr interface{}

		switch req.Method {
		case "start_proxy":
			var params struct {
				Port    int    `json:"port"`
				LogFile string `json:"log_file"`
			}
			json.Unmarshal(req.Params, &params)
			s.Proxy = &ProxyServer{Port: params.Port, LogFile: params.LogFile}
			go s.Proxy.Start()
			result = map[string]string{"status": "started", "port": fmt.Sprintf("%d", params.Port)}
		case "get_health":
			var r runtime.MemStats
			runtime.ReadMemStats(&r)
			result = map[string]interface{}{
				"status": "healthy",
				"workers": 1,
				"version": "3.0.0-omega",
				"ram_usage_mb": r.Alloc / 1024 / 1024,
				"num_cpu": runtime.NumCPU(),
				"num_goroutine": runtime.NumGoroutine(),
			}
		case "guard_kill_chromes":
			// Emergency kill for zombie chromium processes (Windows specific)
			exec.Command("taskkill", "/F", "/IM", "chrome.exe", "/T").Run()
			exec.Command("taskkill", "/F", "/IM", "chromium.exe", "/T").Run()
			result = map[string]string{"status": "emergency_cleanup_executed"}
		default:
			rpcErr = map[string]string{"code": "-32601", "message": "Method not found"}
		}

		encoder.Encode(RPCResponse{
			JSONRPC: "2.0",
			Result:  result,
			Error:   rpcErr,
			ID:      req.ID,
		})
	}
}
