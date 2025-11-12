package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

func Scan(proxies []string, threads int, timeout time.Duration, testURL string) []string {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, threads)

	for _, p := range proxies {
		wg.Add(1)
		go func(proxyStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			protocol, addr, auth, err := parseProxy(proxyStr)
			if err != nil {
				return
			}

			if testProxy(ctx, protocol, addr, auth, testURL) {
				mu.Lock()
				results = append(results, fmt.Sprintf("%s://%s", protocol, proxyStr))
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	return results
}

// parseProxy 返回 protocol, host:port, auth (user:pass), error
func parseProxy(proxyStr string) (string, string, *proxy.Auth, error) {
	// 提取协议
	protocol := "http"
	if strings.HasPrefix(proxyStr, "http://") {
		proxyStr = strings.TrimPrefix(proxyStr, "http://")
	} else if strings.HasPrefix(proxyStr, "https://") {
		protocol = "https"
		proxyStr = strings.TrimPrefix(proxyStr, "https://")
	} else if strings.HasPrefix(proxyStr, "socks4://") {
		protocol = "socks4"
		proxyStr = strings.TrimPrefix(proxyStr, "socks4://")
	} else if strings.HasPrefix(proxyStr, "socks5://") {
		protocol = "socks5"
		proxyStr = strings.TrimPrefix(proxyStr, "socks5://")
	}

	// 提取 user:pass@host:port
	u, err := url.Parse("http://" + proxyStr)
	if err != nil {
		return "", "", nil, err
	}

	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}

	return protocol, u.Host, auth, nil
}

// testProxy 使用自定义 testURL 进行 CONNECT/GET 测试
func testProxy(ctx context.Context, protocol, addr string, auth *proxy.Auth, testURL string) bool {
	var dialer proxy.Dialer
	var err error

	switch protocol {
	case "http", "https":
		// HTTP/HTTPS 代理使用 FromURL
		scheme := "http"
		if protocol == "https" {
			scheme = "https"
		}
		u := &url.URL{Scheme: scheme, Host: addr}
		if auth != nil {
			u.User = url.UserPassword(auth.User, auth.Password)
		}
		dialer, err = proxy.FromURL(u, proxy.Direct)
	case "socks4":
		dialer, err = proxy.SOCKS4("tcp", addr, auth, proxy.Direct)
	case "socks5":
		dialer, err = proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	default:
		return false
	}
	if err != nil {
		return false
	}

	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
