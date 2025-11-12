package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Scan 并发扫描代理，返回有效节点列表
func Scan(proxies []string, threads int, timeout time.Duration) []string {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, threads) // 信号量控制并发

	for _, proxyStr := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			protocol, addr, err := parseProxy(p)
			if err != nil {
				return
			}

			valid := testProxy(ctx, protocol, addr)
			if valid {
				mu.Lock()
				results = append(results, fmt.Sprintf("%s://%s", protocol, p))
				mu.Unlock()
			}
		}(proxyStr)
	}

	wg.Wait()
	return results
}

// parseProxy 解析代理字符串: user:pass@host:port -> protocol, host:port
func parseProxy(proxyStr string) (string, string, error) {
	parts := strings.SplitN(proxyStr, "://", 2)
	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	if protocol == "" {
		protocol = "http" // 默认
	} else {
		parts[1] = protocol + "://" + parts[1] // 重新组装
		protocol = protocol[:len(protocol)-3] // 移除 ://
	}

	u, err := url.Parse(parts[1])
	if err != nil {
		return "", "", err
	}
	addr := u.Host
	if addr == "" {
		addr = u.Path // Fallback for no host
	}
	return protocol, addr, nil
}

// testProxy 测试代理有效性（使用 httpbin.org/ip 和延迟测试）
func testProxy(ctx context.Context, protocol, addr string) bool {
	var dialer proxy.Dialer
	var err error

	switch protocol {
	case "http", "https":
		dialer, err = proxy.FromURL(&url.URL{Scheme: protocol, Host: addr}, proxy.Direct)
	case "socks4":
		dialer, err = proxy.SOCKS4("tcp", addr, nil, proxy.Direct)
	case "socks5":
		dialer, err = proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	default:
		return false
	}
	if err != nil {
		return false
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
		Proxy:       http.NoProxy,
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://httpbin.org/ip", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
