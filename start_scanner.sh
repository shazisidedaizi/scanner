#!/bin/bash

# 这个脚本用于一键安装和启动 https://github.com/shazisidedaizi/scanner 项目
# 注意：该脚本假设在 Ubuntu/Debian 系统上运行，需要 root 权限安装依赖和 Go
# 请确保有足够的权限运行 sudo 命令
# 如果 Go 已安装，可以注释掉安装 Go 的部分

set -e  # 遇到错误时退出

# 步骤1: 更新系统
echo "更新系统..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential upx-ucl

# 步骤2: 检查并安装 Go（如果未安装）
if ! command -v go &> /dev/null; then
    echo "安装 Go 1.24.9..."
    wget https://go.dev/dl/go1.24.9.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.24.9.linux-amd64.tar.gz
    rm go1.24.9.linux-amd64.tar.gz
    
    # 显式设置当前 shell 的 PATH（无需依赖 .bashrc）
    export PATH=/usr/local/go/bin:$PATH
    export GOPATH=$HOME/go
    export GOBIN=$GOPATH/bin
    
    # 如果想持久化到所有 shell，也追加到 .bashrc 或 .profile
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
    fi
    
    # 验证
    go version
else
    echo "Go 已安装，版本: $(go version)"
fi

# 步骤3: 克隆仓库并构建
echo "克隆仓库并构建..."
git clone https://github.com/shazisidedaizi/scanner || true  # 如果已存在则忽略
cd scanner
go mod tidy
go build -ldflags="-s -w" -o scanner
upx --best --lzma scanner
ls -lh scanner

# 步骤4: 启动程序（交互式）
echo "启动 scanner..."
nohup ./scanner -threads 1000 -timeout 5s > scan.log 2>&1 &

echo ""
echo "============================================="
echo "🎉 scanner 已启动，并在后台运行"
echo "📌 常用运行管理命令如下："
echo "---------------------------------------------"
echo "查看运行状态：        ps aux | grep scanner"
echo "查看实时日志：        tail -f scan.log"
echo "安全停止 scanner：    pkill scanner"
echo "查看有效代理：        cat proxy_valid.txt"
echo "查看详细日志：        cat result_detail.txt"
echo "============================================="
echo ""
