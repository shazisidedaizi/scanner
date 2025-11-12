# Proxy Scanner

> **Go 语言实现的 HTTP/HTTPS/SOCKS4/SOCKS5 代理扫描器**  
> 仅输出 **带用户名密码认证** 的有效节点  
> 支持 **自定义目标 IP:Port**（如 `1.1.1.1:80`）  
> 参考 `allmain.sh` 逻辑，性能提升 10 倍+

---

## 功能特性

| 功能 | 说明 |
|------|------|
| 支持 4 种协议 | `http`, `https`, `socks4`, `socks5` |
| 仅输出带认证节点 | `user:pass@ip:port` |
| 自定义测试目标 | `-target 1.1.1.1:80` |
| 并发扫描 | `-threads 200` |
| 超时控制 | `-timeout 8s` |
| 输出到文件 | `-output live.txt` |

---

## 在 Ubuntu 20.04 上运行（完整流程）

### 步骤 1：更新系统 & 安装依赖

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential
