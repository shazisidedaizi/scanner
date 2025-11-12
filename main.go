package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"proxy-scanner/scanner"
)

func main() {
	proxyFile := flag.String("proxies", "proxies.txt", "Path to proxy list file (username:password@host:port)")
	target := flag.String("target", "", "Custom target to test: IP:PORT (e.g. 1.1.1.1:80). If empty, uses httpbin.org/ip")
	threads := flag.Int("threads", 100, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout per proxy")
	output := flag.String("output", "", "Output file (default: stdout)")
	flag.Parse()

	proxies, err := loadProxies(*proxyFile)
	if err != nil {
		fmt.Printf("Error loading proxies: %v\n", err)
		os.Exit(1)
	}

	// 构建测试目标
	testURL := "http://httpbin.org/ip"
	if *target != "" {
		if !strings.Contains(*target, ":") {
			fmt.Println("Error: -target must be IP:PORT")
			os.Exit(1)
		}
		testURL = fmt.Sprintf("http://%s", *target)
	}

	fmt.Printf("Loaded %d authenticated proxies. Scanning with %d threads...\n", len(proxies), *threads)
	fmt.Printf("Target URL: %s\n", testURL)

	results := scanner.Scan(proxies, *threads, *timeout, testURL)

	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		for _, r := range results {
			fmt.Fprintln(file, r)
		}
	} else {
		for _, r := range results {
			fmt.Println(r)
		}
	}

	fmt.Printf("Found %d valid authenticated proxies.\n", len(results))
}

func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.Contains(line, "@") && strings.Contains(line, ":") {
			proxies = append(proxies, line)
		}
	}
	return proxies, scanner.Err()
}
