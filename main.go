package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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
	"syscall"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/net/proxy"
	// "golang.org/x/sys/unix"
)

// ==================== 配置与常量 ====================
var (
	weakPasswords = [][2]string{
		{"admin", "admin"}, {"root", "root"}, {"user", "user"}, {"123", "123"},
		{"proxy", "proxy"}, {"socks5", "socks5"}, {"123456", "123456"}, {"test", "test"},
		{"guest", "guest"}, {"", "admin"}, {"admin", ""}, {"password", "password"},
		{"socks", "socks"}, {"demo", "demo"}, {"hello", "hello"}, {"qwerty", "qwerty"},
	}
	protocols        = []string{"http", "socks5", "socks4"} // https 不支持，socks4 后置
	countryCache     sync.Map                               // ip -> countryCode
	validCount       int64
	seenProxies      sync.Map                               // ip:port -> struct{}
	detailFile       *os.File
	validFile        *os.File
	detailMu         sync.Mutex
	validMu          sync.Mutex
	countryCacheFile = "country_cache.json"
)

// ==================== 主函数 ====================
func main() {
	// ==================== 命令行参数 ====================
	ipRange := flag.String("ip-range", "", "IP range: 192.168.1.1-192.168.1.255 or CIDR")
	portInput := flag.String("port", "", "Ports: 1080 / 80 8080 / 1-65535")
	threads := flag.Int("threads", 0, "Max concurrent connections")
	timeout := flag.Duration("timeout", 0, "Timeout per request (e.g. 5s)")
	flag.Parse()

	// ==================== 默认值 ====================
	defaultStart := "157.254.32.0"
	defaultEnd := "157.254.52.255"
	defaultPort := "1080"
	defaultThreads := 15000
	defaultTimeout := 5 * time.Second

	// ==================== 交互式输入 ====================
	var finalIPRange, finalPortInput string
	var finalThreads int
	var finalTimeout time.Duration

	// --- IP 范围 ---
	if *ipRange == "" {
		finalIPRange = promptIPRange(defaultStart, defaultEnd)
	} else {
		finalIPRange = *ipRange
	}

	// --- 端口 ---
	if *portInput == "" {
		finalPortInput = prompt("端口（默认: "+defaultPort+"): ", defaultPort)
	} else {
		finalPortInput = *portInput
	}

	// --- 并发数 ---
	if *threads <= 0 {
		finalThreads = promptInt("最大并发数（默认: "+strconv.Itoa(defaultThreads)+"):", defaultThreads)
	} else {
		finalThreads = *threads
	}

	// --- 超时时间 ---
	if *timeout <= 0 {
		finalTimeout = promptDuration("超时时间（如 5s，默认: 5s）: ", defaultTimeout)
	} else {
		finalTimeout = *timeout
	}

	// ==================== 配置摘要 ====================
	fmt.Printf("\n[*] 扫描范围: %s\n", finalIPRange)
	fmt.Printf("[*] 端口配置: %s\n", finalPortInput)
	fmt.Printf("[*] 最大并发: %d\n", finalThreads)
	fmt.Printf("[*] 超时时间: %v\n\n", finalTimeout)

	// ==================== 解析 IP 和端口 ====================
	ips, err := parseIPRange(finalIPRange)
	if err != nil {
		log.Fatalf("IP range error: %v", err)
	}
	ports, err := parsePorts(finalPortInput)
	if err != nil {
		log.Fatalf("Port error: %v", err)
	}

	// 计算总数用于进度条
	total := len(ips) * len(ports)
	fmt.Printf("[*] IPs: %d, Ports: %d, Total: %d\n", len(ips), len(ports), total)

	// ==================== 初始化日志 ====================
	logFile, err := os.OpenFile("scan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags)
	log.Printf("[*] 扫描开始: %s", time.Now().Format("2006-01-02 15:04:05"))

	// ==================== 初始化输出文件 ====================
	detailFile, _ = os.OpenFile("result_detail.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	validFile, _ = os.OpenFile("proxy_valid.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer detailFile.Close()
	defer validFile.Close()
	fmt.Fprintln(detailFile, "# 全协议扫描详细日志")
	fmt.Fprintln(validFile, "# scheme://[user:pass@]ip:port#CC")

	// 加载国家缓存
	loadCountryCache()

	// ==================== 后台运行支持 ====================
	signal.Ignore(syscall.SIGHUP)
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	bar := pb.StartNew(total)
	bar.SetWriter(multiWriter)
	go func() {
		<-c
		log.Println("[!] 收到中断信号，正在优雅退出...")
		cancel()
		bar.Finish()
		saveCountryCache()
		log.Printf("[+] 已保存 %d 个代理 → proxy_valid.txt", validCount)
		os.Exit(0)
	}()

	// ==================== 主循环 ====================
	sem := make(chan struct{}, finalThreads)
	var wg sync.WaitGroup

	for _, ip := range ips {
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			addr := fmt.Sprintf("%s:%d", ip, port)
			wg.Add(1)
			go func(a string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem; bar.Increment() }()
				ip, portStr, _ := strings.Cut(a, ":")
				port, _ := strconv.Atoi(portStr)
				result := scanProxy(ctx, ip, port, finalTimeout)
				if result.Scheme != "" {
					key := fmt.Sprintf("%s:%d", result.IP, result.Port)
					if _, loaded := seenProxies.LoadOrStore(key, true); !loaded {
						atomic.AddInt64(&validCount, 1)
						writeResult(result)
					}
				}
			}(addr)
		}
	}
	wg.Wait()
	bar.Finish()
	saveCountryCache()
	log.Printf("[+] 完成！发现 %d 个代理 → proxy_valid.txt", validCount)
	log.Printf("[*] 扫描结束: %s", time.Now().Format("2006-01-02 15:04:05"))
}

// ==================== 交互输入 ====================
func prompt(msg, def string) string {
	fmt.Print("请输入" + msg)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		if input != "" {
			return input
		}
	}
	return def
}

func promptInt(msg string, def int) int {
	s := prompt(msg, strconv.Itoa(def))
	i, err := strconv.Atoi(s)
	if err != nil || i <= 0 {
		return def
	}
	return i
}

func promptDuration(msg string, def time.Duration) time.Duration {
	s := prompt(msg, def.String())
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func promptIPRange(start, end string) string {
	s := prompt("起始 IP（默认: "+start+"): ", start)
	e := prompt("结束 IP（默认: "+end+"): ", end)
	return s + "-" + e
}

// ==================== 解析函数 ====================
func parseIPRange(r string) ([]string, error) {
	if strings.Contains(r, "/") {
		return parseCIDR(r)
	}
	return parseIPRangeDash(r)
}

func parseCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		if len(ips) > 0 { // 跳过网络地址
			ips = append(ips, ip.String())
		}
		if len(ips) > 1 && isBroadcast(ipnet, ip) {
			break
		}
	}
	return ips, nil
}

func isBroadcast(ipnet *net.IPNet, ip net.IP) bool {
	broadcast := make(net.IP, len(ipnet.IP))
	copy(broadcast, ipnet.IP)
	for i := range ipnet.Mask {
		broadcast[i] |= ^ipnet.Mask[i]
	}
	return broadcast.Equal(ip)
}

func parseIPRangeDash(r string) ([]string, error) {
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
	for ip := copyIP(start); compareIP(ip, end) <= 0; ip = incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) net.IP {
	ip = copyIP(ip)
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

func parsePorts(input string) ([]int, error) {
	var ports []int
	for _, p := range strings.Fields(input) {
		if strings.Contains(p, "-") {
			r := strings.Split(p, "-")
			s, _ := strconv.Atoi(r[0])
			e, _ := strconv.Atoi(r[1])
			for i := s; i <= e && i <= 65535; i++ {
				ports = append(ports, i)
			}
		} else {
			port, _ := strconv.Atoi(p)
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}

// ==================== 结果结构 ====================
type Result struct {
	IP       string
	Port     int
	Scheme   string
	Latency  int
	ExportIP string
	Country  string
	Auth     string
	IsWeak   bool
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
		if ok && isPublicIP(exportIP) {
			result.Scheme = scheme
			result.Latency = lat
			result.ExportIP = exportIP
			result.Country = getCountry(exportIP)
			if result.Country == "XX" {
				result.Country = getCountry(ip)
			}
			return result
		}
		// 2. 弱密码爆破（仅 HTTP/SOCKS5）
		if scheme == "socks4" {
			continue
		}
		for _, pair := range weakPasswords {
			if ctx.Err() != nil {
				return result
			}
			auth := &proxy.Auth{User: pair[0], Password: pair[1]}
			ok, lat, exportIP := testProxy(ctx, scheme, ip, port, auth, timeout)
			if ok && isPublicIP(exportIP) {
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

// ==================== 协议测试 ====================
func testProxy(ctx context.Context, scheme, ip string, port int, auth *proxy.Auth, timeout time.Duration) (bool, int, string) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	testURL := "http://ifconfig.me"
	var dialer func(context.Context, string, string) (net.Conn, error)
	switch scheme {
	case "http":
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
	transport := &http.Transport{DialContext: dialer}
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
	return resp.StatusCode == 200, latency, exportIP
}

// SOCKS4 手动实现
func socks4Dialer(addr string, auth *proxy.Auth) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		ip, portStr, _ := net.SplitHostPort(target)
		port, _ := strconv.Atoi(portStr)
		ipObj := net.ParseIP(ip)
		if ipObj == nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 does not support domain names")
		}
		ipBytes := ipObj.To4()
		if ipBytes == nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 requires IPv4")
		}
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
			return nil, fmt.Errorf("socks4 rejected: %d", resp[1])
		}
		return conn, nil
	}
}

// ==================== 公网 IP 判断 ====================
func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return !(ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168))
	}
	return false
}

// ==================== 国家查询 ====================
func getCountry(ip string) string {
	if v, ok := countryCache.Load(ip); ok {
		return v.(string)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	urls := []string{
		"http://ip-api.com/json/" + ip + "?fields=countryCode",
		"https://ipinfo.io/" + ip + "/country",
	}
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
		if regexp.MustCompile(`^[A-Z]{2}$`).MatchString(code) {
			countryCache.Store(ip, code)
			return code
		}
	}
	countryCache.Store(ip, "XX")
	return "XX"
}

func loadCountryCache() {
	data, err := os.ReadFile(countryCacheFile)
	if err != nil {
		return
	}
	var m map[string]string
	if json.Unmarshal(data, &m) == nil {
		for k, v := range m {
			countryCache.Store(k, v)
		}
	}
}

func saveCountryCache() {
	m := make(map[string]string)
	countryCache.Range(func(k, v interface{}) bool {
		m[k.(string)] = v.(string)
		return true
	})
	data, _ := json.MarshalIndent(m, "", " ")
	os.WriteFile(countryCacheFile, data, 0644)
}

// ==================== 输出 ====================
func writeResult(r Result) {
	detailMu.Lock()
	status := "OK"
	if r.IsWeak {
		status = "OK (Weak)"
	}
	line := fmt.Sprintf("%s:%d | %s | %s | %s | %dms | %s | %s",
		r.IP, r.Port, r.Scheme, status, r.Country, r.Latency, r.ExportIP, r.Auth)
	fmt.Fprintln(detailFile, line)
	detailMu.Unlock()

	validMu.Lock()
	authPart := ""
	if r.Auth != "" {
		authPart = r.Auth + "@"
	}
	fmtStr := fmt.Sprintf("%s://%s%s:%d#%s", r.Scheme, authPart, r.IP, r.Port, r.Country)
	if authPart == "" {
		fmtStr = strings.Replace(fmtStr, "@:", ":", 1)
	}
	fmt.Fprintln(validFile, fmtStr)
	validMu.Unlock()
}
