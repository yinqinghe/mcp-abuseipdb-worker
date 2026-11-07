# AbuseIPDB MCP Server for Cloudflare Workers

English | [中文](#中文说明)

An edge-native [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [AbuseIPDB](https://www.abuseipdb.com/) deployed on **Cloudflare Workers**.

Provides IP reputation checking and abuse reporting capabilities to AI assistants (Claude Desktop, Cursor, Cherry Studio, LibreChat, Dify, Cline, etc.) with ultra-low latency, zero cold starts, and global edge distribution.

---

## Features

- ⚡ **Native Cloudflare Workers**: Runs globally on Cloudflare edge runtime (V8 Isolate) with 0ms cold starts.
- 🔄 **Dual Transport Protocol**:
  - **SSE (Server-Sent Events)**: Standard remote MCP protocol via `/sse` and `/message`.
  - **Streamable HTTP / Direct JSON-RPC**: Direct POST requests via `/mcp` or `/`.
- 🔍 **Check IP (`check_ip`)**: Query IP reputation score, ISP, domain, usage type, country, Tor status, and abuse categories.
- 🚨 **Report IP (`report_ip`)**: Report abusive IP addresses with specific category IDs and attack comments.
- 🌐 **Full CORS Support**: Readily accessible from Web clients and browser-based AI agents.
- 🛡️ **Secure Secret Management**: API keys managed securely using Cloudflare Secrets.

---

## Available Tools

### 1. `check_ip`
Check an IP address for abuse reports using AbuseIPDB.

**Parameters:**
- `ipAddress` (*string*, required): Valid IPv4 or IPv6 address.
- `maxAgeInDays` (*integer*, optional, default: 30): Range: 1-365.
- `verbose` (*boolean*, optional, default: true): Detailed reports breakdown.

### 2. `report_ip`
Report abusive IP activity to AbuseIPDB.

**Parameters:**
- `ip` (*string*, required): Valid IPv4 or IPv6 address.
- `categories` (*string*, required): Comma-separated category IDs (e.g., `'18,22'`).
- `comment` (*string*, optional): Description of attack without PII.
- `timestamp` (*string*, optional): ISO 8601 formatted datetime.

**Category Reference:**
| ID | Category | ID | Category |
|---|---|---|---|
| 1 | DNS Compromise | 13 | VPN IP |
| 2 | DNS Poisoning | 14 | Port Scan |
| 3 | Fraud Orders | 15 | Hacking |
| 4 | DDoS Attack | 16 | SQL Injection |
| 5 | FTP Brute-Force | 17 | Spoofing |
| 6 | Ping of Death | 18 | Brute-Force |
| 7 | Phishing | 19 | Bad Web Bot |
| 8 | Fraud VoIP | 20 | Exploited Host |
| 9 | Open Proxy | 21 | Web App Attack |
| 10 | Web Spam | 22 | SSH |
| 11 | Email Spam | 23 | IoT Targeted |
| 12 | Blog Spam | | |

---

## Quick Start (Local Development)

### 1. Install Dependencies
```bash
cd cloudflare-worker
npm install
```

### 2. Configure Environment Variable
Copy `.dev.vars.example` to `.dev.vars` and add your AbuseIPDB API Key:
```bash
cp .dev.vars.example .dev.vars
```
Edit `.dev.vars`:
```env
ABUSEIPDB_API_KEY=your_actual_abuseipdb_api_key
```

### 3. Run Locally
```bash
npm run dev
```
The server will start at `http://localhost:8787`.

Test health check:
```bash
curl http://localhost:8787/
```

Test check IP via MCP JSON-RPC:
```bash
curl -X POST http://localhost:8787/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "check_ip",
      "arguments": { "ipAddress": "1.1.1.1" }
    }
  }'
```

---

## Deployment to Cloudflare Workers

### 1. Login to Cloudflare
```bash
npx wrangler login
```

### 2. Set API Key Secret
Set your AbuseIPDB API key securely in Cloudflare:
```bash
npx wrangler secret put ABUSEIPDB_API_KEY
```
When prompted, paste your API key.

### 3. Deploy
```bash
npm run deploy
```
Once deployed, Cloudflare will output your worker URL:
```text
https://mcp-abuseipdb-worker.<your-subdomain>.workers.dev
```

---

## MCP Client Configuration

### 1. Claude Desktop (SSE or HTTP)

If using an SSE remote proxy or direct remote MCP support:

```json
{
  "mcpServers": {
    "abuseipdb": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp-abuseipdb-worker.<your-subdomain>.workers.dev/sse"
      ]
    }
  }
}
```

### 2. Cursor / Cherry Studio / LibreChat / Dify

Configure as a remote MCP server:
- **Transport**: `SSE`
- **URL**: `https://mcp-abuseipdb-worker.<your-subdomain>.workers.dev/sse`

Or for direct HTTP mode:
- **Transport**: `Streamable HTTP` / `HTTP`
- **URL**: `https://mcp-abuseipdb-worker.<your-subdomain>.workers.dev/mcp`

---

<a name="中文说明"></a>
# 中文说明

这是一个专为 **Cloudflare Workers** 打造的原生边缘无服务器 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 服务端，用于连接 [AbuseIPDB](https://www.abuseipdb.com/) 威胁情报数据库。

为各类大模型客户端（Claude Desktop、Cursor、Cherry Studio、Dify 等）提供极低延迟、全球就近接入且 0 冷启动的 IP 威胁信誉查询与滥用上报能力。

### 核心功能
- **双协议支持**：
  - **SSE 协议**：访问 `/sse` 建立长连接，通过 `/message?sessionId=...` 提交请求。
  - **HTTP 直连 / JSON-RPC**：直接 POST `/mcp` 或 `/` 即可处理请求。
- **健康检查**：浏览器或 curl 访问 `GET /` 或 `GET /health` 可直接查看服务状态及可用工具。
- **支持工具**：
  - `check_ip`：检查 IP 滥用评分、归属地、ISP、关联分类等。
  - `report_ip`：向 AbuseIPDB 上报恶意 IP 及攻击分类。

### 部署与使用步骤
1. **安装依赖**：
   ```bash
   cd cloudflare-worker
   npm install
   ```
2. **本地调试**：
   ```bash
   cp .dev.vars.example .dev.vars
   # 在 .dev.vars 中填写 ABUSEIPDB_API_KEY
   npm run dev
   ```
3. **部署至 Cloudflare**：
   ```bash
   # 绑定 API Key 机密（只需执行一次）
   npx wrangler secret put ABUSEIPDB_API_KEY

   # 部署
   npm run deploy
   ```
4. **客户端接入**：
   在支持远程 MCP 的客户端填入部署好的 Worker 链接（如 `https://mcp-abuseipdb-worker.<你的子域>.workers.dev/sse`）。
