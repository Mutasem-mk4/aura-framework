package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status"`
	ContentLength int64  `json:"length"`
	Timestamp     string `json:"timestamp"`
}

type Config struct {
	BaseURL     string
	Wordlist    string
	ProxyList   string
	Threads     int
	Timeout     int
	Extensions  []string
	StatusCodes []int
}

func main() {
	baseURL := flag.String("u", "", "Target Base URL")
	wordlist := flag.String("w", "", "Path to wordlist")
	proxyList := flag.String("p", "", "Path to proxy list (optional)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	exts := flag.String("e", "", "Comma-separated extensions (e.g. php,txt,html)")
	codes := flag.String("mc", "200,204,301,302,307,401,403", "Match status codes")
	flag.Parse()

	if *baseURL == "" || *wordlist == "" {
		flag.Usage()
		os.Exit(1)
	}

	config := Config{
		BaseURL:    strings.TrimSuffix(*baseURL, "/"),
		Wordlist:   *wordlist,
		ProxyList:  *proxyList,
		Threads:    *threads,
		Timeout:    *timeout,
		Extensions: strings.Split(*exts, ","),
	}

	for _, c := range strings.Split(*codes, ",") {
		var code int
		fmt.Sscanf(c, "%d", &code)
		config.StatusCodes = append(config.StatusCodes, code)
	}

	runFuzzer(config)
}

func runFuzzer(config Config) {
	words := make(chan string, config.Threads)
	results := make(chan Result)
	var wg sync.WaitGroup

	// Load Proxies
	var proxies []string
	if config.ProxyList != "" {
		proxies = loadLines(config.ProxyList)
	}

	// Start Workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Select Proxy for this worker session
			var transport *http.Transport
			if len(proxies) > 0 {
				proxyURL, _ := url.Parse(proxies[rand.Intn(len(proxies))])
				transport = &http.Transport{
					Proxy:           http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			} else {
				transport = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}

			client := &http.Client{
				Transport: transport,
				Timeout:   time.Duration(config.Timeout) * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			for word := range words {
				targets := []string{word}
				if len(config.Extensions) > 0 && config.Extensions[0] != "" {
					for _, ext := range config.Extensions {
						targets = append(targets, word+"."+ext)
					}
				}

				for _, target := range targets {
					fullURL := fmt.Sprintf("%s/%s", config.BaseURL, target)
					resp, err := client.Get(fullURL)
					if err != nil {
						continue
					}
					
					match := false
					for _, code := range config.StatusCodes {
						if resp.StatusCode == code {
							match = true
							break
						}
					}

					if match {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						results <- Result{
							URL:           fullURL,
							StatusCode:    resp.StatusCode,
							ContentLength: resp.ContentLength,
							Timestamp:     time.Now().Format(time.RFC3339),
						}
					} else {
						resp.Body.Close()
					}
				}
			}
		}()
	}

	// Result Printer
	go func() {
		for res := range results {
			jsonData, _ := json.Marshal(res)
			fmt.Println(string(jsonData))
		}
	}()

	// Feeder
	file, err := os.Open(config.Wordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening wordlist: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words <- scanner.Text()
	}
	close(words)

	wg.Wait()
	close(results)
}

func loadLines(path string) []string {
	var lines []string
	file, err := os.Open(path)
	if err != nil {
		return lines
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
