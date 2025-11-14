# Socks5 Scanner Go Edition

# 免责声明 (Disclaimer)

**本项目（Proxy Scanner Go Edition）仅供教育、研究和合法网络安全测试目的使用。**

1. **合法使用要求**：  
   用户必须确保所有扫描活动仅限于您拥有或获得明确书面授权的网络和系统。未经授权的扫描、弱密码爆破或访问他人系统可能违反当地法律法规（如计算机欺诈和滥用法、数据保护法或网络安全法），并可能导致民事或刑事责任。作者强烈建议用户在进行任何操作前咨询法律专业人士，并遵守所有适用的法律、法规和道德标准。

2. **无保证**：  
   本软件按“现状”提供，不附带任何明示或暗示的保证，包括但不限于适销性、特定用途适用性或非侵权性。作者不对软件的准确性、可靠性、性能或使用结果承担任何责任。使用本软件可能导致意外后果，如网络中断、数据丢失或系统不稳定，用户需自行承担所有风险。

3. **滥用责任**：  
   作者不对用户因滥用本软件而造成的任何损害、损失或法律后果负责。禁止将本软件用于非法活动，包括但不限于未经授权的网络入侵、数据窃取、分布式拒绝服务（DDoS）或其他恶意行为。如果本软件被用于非法目的，用户将独自承担全部责任。

4. **知识产权**：  
   本软件基于开源许可（请参考仓库中的LICENSE文件）。用户可自由使用、修改和分发，但必须保留原作者信息，并遵守许可条款。

5. **更新与维护**：  
   作者保留随时修改、更新或停止本项目的权利，使用过程中如遇任何问题，请自行解决，作者不承担解答义务。

**通过使用本软件，您确认已阅读、理解并同意本免责声明。如果您不同意，请立即停止使用并删除所有相关文件。**


## 功能特性

| 功能 | 说明 |
|------|------|
|内置URL|仅支持txt格式，可自行修改|
| 输入 IP 范围 | `默认157.254.32.0-157.254.52.255 可自定义` |
| 输入端口 | `1080` / `80 8080` / `1-65535` |
| 弱密码爆破 | Done |
| 输出 `scheme://user:pass@ip:port#CC` | Done |
| 实时进度条 + 日志 + 后台运行 | Done |
| 国家代码（Country Code）查询 | Done |
| 输出文件：`proxy_valid.txt`、`result_detail.txt` | Done |

---
### 一键运行脚本

```bash
curl -s https://raw.githubusercontent.com/yourusername/yourrepo/main/start_scanner.sh | bash 
```
#fork 本仓库，并将一键脚本中的用户名与仓库名替换为您自己的，然后粘贴到 VPS 上回车运行
### 其他命令

#查看运行状态，ps aux | grep scanner

#查看实时日志，tail -f scan.log

#安全停止，pkill scanner

#有效代理（可直接使用），cat proxy_valid.txt

#详细日志，cat result_detail.txt

### 手动安装步骤

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

#验证安装(输出应为：go version go1.24.9 linux/amd64)

go version

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
直接运行(不能断开终端链接)

./scanner

#命令行后台运行扫描（参数都可以自定义，推荐选项)

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


# 感谢结语 (Acknowledgments)

感谢您对本项目（Proxy Scanner Go Edition）的关注和使用！

- **特别鸣谢**：  
 本代码修改自 OTC 大佬的项目 [https://github.com/avotcorg/scamnet](https://github.com/avotcorg/scamnet)，感谢 OTC 大佬 [@avotcorg](https://github.com/avotcorg) 的贡献。。
  
**再次感谢！如果这个项目对您有帮助，请考虑给我们一个 Star ⭐ 或分享给朋友。您的认可是我们最大的鼓励。**


