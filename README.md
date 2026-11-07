# AbuseIPDB MCP Worker

English | [中文说明](#中文说明)

An edge-native [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [AbuseIPDB](https://www.abuseipdb.com/) deployed on **Cloudflare Workers**.

Supports dual protocols (SSE & Streamable HTTP), multi-key configuration with round-robin polling, and automatic fault-tolerant failover when a key is exhausted or invalid.

---

## Features

- ⚡ **Native Cloudflare Workers**: Runs globally on Cloudflare edge runtime (V8 Isolate) with ultra-low latency and 0ms cold starts.
- 🔄 **Dual Transport Protocol**:
  - **SSE (Server-Sent Events)**: Remote MCP via `GET /sse` and `POST /message`.
  - **Streamable HTTP / JSON-RPC**: Remote MCP via `POST /mcp` or `POST /`.
- 🔑 **Multi-Key Round-Robin & Fallback**:
  - Supports multiple API keys via `ABUSEIPDB_API_KEYS` (or single `ABUSEIPDB_API_KEY`, also compatible with `VIRUSTOTAL_API_KEYS`).
  - **Round-Robin Polling**: Distributes requests sequentially across all configured keys.
  - **Auto Fallback / Skip**: If a key hits 429 rate limit or 401/403 invalid key error, it is placed on cooldown and the request seamlessly skips to the next key.
- 🔍 **Available Tools**:
  - `check_ip`: Check IP reputation score, ISP, domain, usage type, country, Tor status, and abuse categories.
  - `report_ip`: Report abusive IP addresses with specific category IDs and attack comments.
- 🌐 **Full CORS Support**: Accessible from Web clients and browser-based AI agents.

---

## Configuration

### Multi-Key Configuration

Configure one or multiple keys (separated by commas, semicolons, or newlines):

#### 1. Cloudflare Workers (Production)
Set as a secret via Wrangler:
```bash
# 设置多个 Key（逗号分隔）
npx wrangler secret put ABUSEIPDB_API_KEYS
# 输入: key1,key2,key3
```
Or for a single key:
```bash
npx wrangler secret put ABUSEIPDB_API_KEY
```

#### 2. Local Development (.dev.vars)
Copy `.dev.vars.example` to `.dev.vars`:
```env
ABUSEIPDB_API_KEYS=your_key_1,your_key_2,your_key_3
```

---

## Commands & Deployment

### 1. Install Dependencies
```bash
npm install
```

### 2. Local Development
```bash
npm run dev # or npx wrangler dev
```
Starts locally at `http://localhost:8787`.

Test health check:
```bash
curl http://localhost:8787/
```

### 3. Deploy to Cloudflare
```bash
npm run deploy # or npx wrangler deploy
```

### 4. Typecheck
```bash
npm run typecheck
```

---

## Tools

### 1. `check_ip`
- `ipAddress` (*string*, required): Valid IPv4 or IPv6 address.
- `maxAgeInDays` (*integer*, optional, default: 30): Range: 1-365.
- `verbose` (*boolean*, optional, default: true): Detailed reports breakdown.

### 2. `report_ip`
- `ip` (*string*, required): Valid IPv4 or IPv6 address.
- `categories` (*string*, required): Comma-separated category IDs (e.g. `'18,22'`).
- `comment` (*string*, optional): Description of attack without PII.
- `timestamp` (*string*, optional): ISO 8601 formatted datetime.

---

## 中文说明

部署于 **Cloudflare Workers** 的 AbuseIPDB MCP 服务器。

- **极简架构**：纯原生 Worker，无冗余依赖，秒级冷启动。
- **多 Key 轮询与故障转移**：
  - 支持通过 `ABUSEIPDB_API_KEYS` 设置多个 Key（支持逗号、分号或换行分隔）。
  - **轮询查询**：自动在多个 Key 之间均匀轮询分配查询请求。
  - **自动跳过**：当某个 Key 遇到 429 配额用尽或 401/403 失效时，自动进入冷却并即时跳过切换至下一个可用 Key。
  - **兼容性**：支持 `ABUSEIPDB_API_KEY`，亦兼容 `VIRUSTOTAL_API_KEYS` 环境变量名称。
- **双协议支持**：
  - SSE: `GET /sse` + `POST /message?sessionId=...`
  - Streamable HTTP: `POST /mcp` 或 `POST /`

---

## License

MIT
