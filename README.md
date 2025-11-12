# Proxy Scanner Go Edition

> **Go 语言重写的全协议异步代理扫描器（v5.0+）**  
> 支持 **HTTP/HTTPS/SOCKS4/SOCKS5**  
> **自动弱密码爆破 + 国家识别 + 实时进度条**  
> **零 Python 依赖，单文件二进制，性能提升 10 倍**

---

## 功能特性

| 功能 | 说明 |
|------|------|
| 输入 IP 范围 | `157.254.32.0-157.254.52.255` |
| 输入端口 | `1080` / `80 8080` / `1-65535` |
| 自动生成所有 `IP:PORT` | Done |
| 异步测试 4 种协议 | Done |
| **弱密码爆破（数百种常见密码）** | Done |
| **输出 `scheme://user:pass@ip:port#CC`** | Done |
| **实时进度条 + 日志 + 后台运行** | Done |
| **国家代码（Country Code）查询** | Done |
| **输出文件：`proxy_valid.txt`、`result_detail.txt`** | Done |
| **无需 pip、Python、aiohttp** | Done |

---


### 步骤 1：更新系统 & 安装依赖

sudo apt update && sudo apt upgrade -y

sudo apt install -y git curl wget build-essential upx-ucl

### 步骤 2：安装 Go 语言（1.21+）
# 下载 Go 1.21.5（官方推荐）

wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# 解压到 /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 添加环境变量（永久生效）
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile

echo 'export GOPATH=$HOME/go' >> ~/.profile

source ~/.profile

# 验证安装
go version
# 输出应为：go version go1.21.5 linux/amd64

###  步骤 3：克隆项目并编译
# 克隆仓库
git clone https://github.com/yourusername/proxy-scanner.git

cd proxy-scanner

# 下载依赖
go mod tidy

# 编译生成可执行文件（优化 + 压缩）
go build -ldflags="-s -w" -o proxy-scanner

upx --best --lzma proxy-scanner

# 查看是否生成（约 2.5MB）
ls -lh proxy-scanner

###  步骤 4：运行扫描（交互式输入

./proxy-scanner

程序会提示输入：
请输入起始 IP（默认: 157.254.32.0）:
请输入结束 IP（默认: 157.254.52.255）:
请输入端口（默认: 1080）:


###  步骤 5：运行扫描（命令行参数，一键启动

./proxy-scanner \
  -ip-range 157.254.32.0-157.254.52.255 \
  -port 1080 \
  -threads 10000 \
  -timeout 6s

###  步骤 6：查看实时进度

# 实时查看扫描进度（进度条）
tail -f /dev/null  # 程序自带进度条，无需 tail
#程序运行时会显示：

[*] IPs: 5120, Ports: 1, Total: 5120

[*] Threads: 10000, Timeout: 6s

5120/5120 [==========] 100% 12s

[+] 完成！发现 23 个代理 → proxy_valid.txt

###  步骤 7：查看输出文件

# 有效代理（可直接使用）
cat proxy_valid.txt

# 详细日志
cat result_detail.txt




