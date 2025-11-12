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
	proxyFile := flag.String("proxies", "proxies.txt", "Path to proxy list file (format: username:password@host:port)")
	threads := flag.Int("threads", 100, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout")
	output := flag.String("output", "", "Output file (default: stdout)")
	flag.Parse()

	proxies, err := loadProxies(*proxyFile)
	if err != nil {
		fmt.Printf("Error loading proxies: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d authenticated proxies. Scanning with %d threads...\n", len(proxies), *threads)

	results := scanner.Scan(proxies, *threads, *timeout)

	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		for _, result := range results {
			fmt.Fprintln(file, result)
		}
	} else {
		for _, result := range results {
			fmt.Println(result)
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
		if line != "" && strings.Contains(line, "@") { // 简单检查认证格式: user:pass@host:port
			proxies = append(proxies, line)
		}
	}
	return proxies, scanner.Err()
}
