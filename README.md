# Proxy Scanner Go Edition



## 功能特性

| 功能 | 说明 |
|------|------|
| 输入 IP 范围 | `默认157.254.32.0-157.254.52.255 可自定义` |
| 输入端口 | `1080` / `80 8080` / `1-65535` |
| 自动生成所有 `IP:PORT` | Done |
| 异步测试 4 种协议 | Done |
| 弱密码爆破 | Done |
| 输出 `scheme://user:pass@ip:port#CC` | Done |
| 实时进度条 + 日志 + 后台运行 | Done |
| 国家代码（Country Code）查询 | Done |
| 输出文件：`proxy_valid.txt`、`result_detail.txt` | Done |

---


### 步骤 1：更新系统 & 安装依赖

sudo apt update && sudo apt upgrade -y

sudo apt install -y git curl wget build-essential upx-ucl

### 步骤 2：安装 Go 语言
#下载 Go 1.24

wget https://go.dev/dl/go1.24.9.linux-amd64.tar.gz

#解压到 /usr/local

sudo tar -C /usr/local -xzf go1.24.9.linux-amd64.tar.gz

#清除重复配置

sed -i '/go\/bin/d' ~/.bashrc ~/.profile 2>/dev/null

#添加环境变量到 .bashrc

cat >> ~/.bashrc <<'EOF'

export PATH=/usr/local/go/bin:$PATH

export GOPATH=$HOME/go

export GOBIN=$GOPATH/bin

EOF

#立即生效

source ~/.bashrc

#验证安装

go version

#输出应为：

go version go1.24.9 linux/amd64

###  步骤 3：克隆项目并编译
#克隆仓库

git clone https://github.com/shazisidedaizi/scanner

cd scanner

#初始化 Go 模块并下载依赖（自动处理所有包）

go mod tidy

#编译生成可执行文件（优化 + 压缩）

go build -ldflags="-s -w" -o scanner

upx --best --lzma scanner

#查看是否生成（约 2.5MB）

ls -lh scanner

###  步骤 4：运行扫描（交互式输入
直接运行(不能断开终端链接

./scanner

#命令行后台运行扫描（参数都可以自定义，推荐选项

nohup ./scanner -ip-range 157.254.32.0-157.254.52.255 -port 1080 -threads 1000 -timeout 5s > scan.log 2>&1 &

#通过url获取ip进行扫描

./scanner -url=https://raw.githubusercontent.com/avotcorg/scamnet/refs/heads/main/demo.txt -threads=1000 -timeout=5s

#查看运行状态

ps aux | grep scanner

#查看实时日志

tail -f scan.log

#安全停止

pkill scanner

###  步骤 5：查看输出文件

#有效代理（可直接使用）

cat proxy_valid.txt

#详细日志

cat result_detail.txt




