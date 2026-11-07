/**
 * AbuseIPDB MCP Server for Cloudflare Workers
 * 
 * Supports:
 * - MCP SSE Transport: GET /sse & POST /message?sessionId=...
 * - MCP Streamable HTTP / Direct JSON-RPC: POST /mcp, POST /, POST /sse
 * - Health check & tools metadata: GET / & GET /health
 * - Multi-Key Support & Round-Robin Polling & Auto-Fallback on invalid/rate-limited keys
 */

export interface Env {
  ABUSEIPDB_API_KEY?: string;
  ABUSEIPDB_API_KEYS?: string;
  VIRUSTOTAL_API_KEY?: string;
  VIRUSTOTAL_API_KEYS?: string;
}

// Category mapping defined by AbuseIPDB
const CATEGORIES: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

// Global in-memory map for active SSE sessions within the isolate
const sseSessions = new Map<string, WritableStreamDefaultWriter<Uint8Array>>();

// Helper to mask keys for safe logging
export function maskApiKey(key: string): string {
  if (!key) return "none";
  if (key.length <= 8) return "****";
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

// Key pool with round-robin polling and cooldown tracking
export class ApiKeyPool {
  private keys: string[] = [];
  private currentIndex = 0;
  private cooldowns = new Map<string, number>();

  constructor(keys?: string | string[]) {
    if (keys) {
      this.setKeys(keys);
    }
  }

  setKeys(input?: string | string[]): void {
    if (!input) return;
    const rawList = Array.isArray(input) ? input : [input];
    const parsed: string[] = [];
    for (const item of rawList) {
      if (!item) continue;
      const str = String(item).trim();
      if (!str) continue;
      if (str.startsWith("[") && str.endsWith("]")) {
        try {
          const arr = JSON.parse(str);
          if (Array.isArray(arr)) {
            for (const x of arr) {
              const s = String(x).trim().replace(/^['"]|['"]$/g, "");
              if (s) parsed.push(s);
            }
            continue;
          }
        } catch {}
      }
      for (const k of str.split(/[\r\n,;]+/)) {
        const clean = k.trim().replace(/^['"]|['"]$/g, "");
        if (clean) parsed.push(clean);
      }
    }
    const unique = Array.from(new Set(parsed));
    if (unique.length > 0) {
      this.keys = unique;
      if (this.currentIndex >= this.keys.length) {
        this.currentIndex = 0;
      }
    }
  }

  getKeys(): string[] {
    return this.keys;
  }

  markCooldown(key: string, durationMs: number): void {
    this.cooldowns.set(key, Date.now() + durationMs);
  }

  isCooldown(key: string): boolean {
    const expires = this.cooldowns.get(key);
    if (!expires) return false;
    if (Date.now() >= expires) {
      this.cooldowns.delete(key);
      return false;
    }
    return true;
  }

  clearCooldown(key: string): void {
    this.cooldowns.delete(key);
  }

  getNextKeyIndex(): number {
    if (this.keys.length === 0) return -1;
    const n = this.keys.length;
    const selected = this.currentIndex;
    this.currentIndex = (this.currentIndex + 1) % n;
    return selected;
  }
}

const keyPool = new ApiKeyPool();

export function getKeyPool(): ApiKeyPool {
  return keyPool;
}

export function updateKeyPoolFromEnv(env: Env): void {
  const candidateKeys = [
    env.ABUSEIPDB_API_KEYS || "",
    env.ABUSEIPDB_API_KEY || "",
    env.VIRUSTOTAL_API_KEYS || "",
    env.VIRUSTOTAL_API_KEY || "",
  ];
  keyPool.setKeys(candidateKeys);
}

// Helper to set CORS headers
function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, Key",
    "Access-Control-Expose-Headers": "Mcp-Session-Id",
  };
}

function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function textResponse(text: string, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(text, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

// Basic IP validation (IPv4 and IPv6)
function isValidIp(ip: string): boolean {
  if (!ip) return false;
  const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Pattern = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
  return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

// Validation for comma-separated category IDs
function isValidCategories(categories: string): boolean {
  if (!categories) return false;
  return /^\d+(,\d+)*$/.test(categories);
}

// Tool definitions for MCP tools/list
function getToolsDefinition() {
  return [
    {
      name: "check_ip",
      description: "Check an IP address for abuse reports using AbuseIPDB",
      inputSchema: {
        type: "object",
        properties: {
          ipAddress: {
            type: "string",
            description: "A valid IPv4 or IPv6 address to check",
          },
          maxAgeInDays: {
            type: "integer",
            description: "Only return reports within the last x days (1-365)",
            minimum: 1,
            maximum: 365,
            default: 30,
          },
          verbose: {
            type: "boolean",
            description: "Include detailed reports in the response",
            default: true,
          },
        },
        required: ["ipAddress"],
      },
    },
    {
      name: "report_ip",
      description: "Report an abusive IP address to AbuseIPDB",
      inputSchema: {
        type: "object",
        properties: {
          ip: {
            type: "string",
            description: "A valid IPv4 or IPv6 address to report",
          },
          categories: {
            type: "string",
            description: "Comma separated category IDs (e.g., '18,22')",
          },
          comment: {
            type: "string",
            description: "Descriptive text of the attack (no PII)",
          },
          timestamp: {
            type: "string",
            description: "ISO 8601 datetime of the attack (optional)",
          },
        },
        required: ["ip", "categories"],
      },
    },
  ];
}

// Request helper with retries
async function makeAbuseIPDBRequest(
  url: string,
  options: RequestInit,
  maxRetries = 2
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(url, options);
      return res;
    } catch (err) {
      lastError = err;
      if (attempt < maxRetries - 1) {
        await new Promise((resolve) => setTimeout(resolve, 500 * Math.pow(2, attempt)));
      }
    }
  }
  throw lastError;
}

// Format check_ip response (Token-optimized for AI)
function formatCheckResponse(data: any): string {
  try {
    const ipData = data?.data;
    if (!ipData) {
      return `❌ Invalid response structure from AbuseIPDB: ${JSON.stringify(data)}`;
    }

    const score = ipData.abuseConfidenceScore ?? 0;
    let riskTier = "Clean / Safe";
    let riskEmoji = "✅";
    if (score >= 75) {
      riskTier = "High Risk / Malicious";
      riskEmoji = "🚨";
    } else if (score >= 25) {
      riskTier = "Medium / Suspicious";
      riskEmoji = "⚠️";
    } else if (score > 0) {
      riskTier = "Low Risk";
      riskEmoji = "🟡";
    }

    const lines: string[] = [
      `### ${riskEmoji} AbuseIPDB IP Report: \`${ipData.ipAddress}\``,
      `- **Score**: ${score}% (${riskTier})${ipData.isWhitelisted ? " | [Whitelisted]" : ""}${ipData.isTor ? " | [Tor Exit Node]" : ""}`,
    ];

    // Network / Location in one concise line
    const geoParts = [
      ipData.countryName ? `${ipData.countryName}${ipData.countryCode ? ` (${ipData.countryCode})` : ""}` : null,
      ipData.isp ? `ISP: ${ipData.isp}` : null,
      ipData.usageType && ipData.usageType !== "N/A" ? ipData.usageType : null,
      ipData.domain && ipData.domain !== "N/A" ? `Domain: ${ipData.domain}` : null,
    ].filter(Boolean);
    if (geoParts.length > 0) {
      lines.push(`- **Network**: ${geoParts.join(" | ")}`);
    }

    // Reports summary
    const totalReports = ipData.totalReports ?? 0;
    const numUsers = ipData.numDistinctUsers;
    const reportsSummary = [
      `${totalReports} report${totalReports === 1 ? "" : "s"}`,
      numUsers ? `by ${numUsers} distinct reporter${numUsers === 1 ? "" : "s"}` : null,
      ipData.lastReportedAt ? `Last: ${ipData.lastReportedAt}` : "Last: Never",
    ].filter(Boolean).join(", ");
    lines.push(`- **Reports**: ${reportsSummary}`);

    // Categories and compact preview of comments
    const categoryNames: string[] = [];
    const recentComments: { date?: string; text: string }[] = [];

    if (Array.isArray(ipData.reports) && ipData.reports.length > 0) {
      for (const report of ipData.reports) {
        if (Array.isArray(report.categories)) {
          for (const catId of report.categories) {
            const name = CATEGORIES[catId] || String(catId);
            if (!categoryNames.includes(name)) {
              categoryNames.push(name);
            }
          }
        }
        if (report.comment && recentComments.length < 3) {
          const trimmedComment = String(report.comment).trim();
          if (trimmedComment && !recentComments.some((c) => c.text === trimmedComment)) {
            recentComments.push({
              date: report.reportedAt ? String(report.reportedAt).split("T")[0] : undefined,
              text: trimmedComment.length > 100 ? `${trimmedComment.slice(0, 97)}...` : trimmedComment,
            });
          }
        }
      }
    }

    if (categoryNames.length > 0) {
      lines.push(`- **Categories**: ${categoryNames.join(", ")}`);
    }

    // Top recent report comments (compact preview)
    if (recentComments.length > 0) {
      lines.push(`- **Recent Reports Preview**:`);
      for (const c of recentComments) {
        lines.push(`  • ${c.date ? `[${c.date}] ` : ""}${c.text}`);
      }
    }

    return lines.join("\n");
  } catch (err: any) {
    return `❌ Error formatting response: ${err.message || String(err)}`;
  }
}

// Format report_ip response (Token-optimized for AI)
function formatReportResponse(data: any): string {
  const reportData = data?.data;
  if (!reportData) {
    return `❌ Invalid response structure: ${JSON.stringify(data)}`;
  }
  return `✅ Successfully reported \`${reportData.ipAddress || "IP"}\` to AbuseIPDB. New Abuse Confidence Score: **${reportData.abuseConfidenceScore ?? "N/A"}%**`;
}

// Handle API errors and rate limiting
function handleApiError(response: Response, data: any): string {
  const status = response.status;
  if (status === 429) {
    const retryAfter = response.headers.get("Retry-After");
    const remaining = response.headers.get("X-RateLimit-Remaining");
    const limit = response.headers.get("X-RateLimit-Limit");

    let errMsg = `Rate limit exceeded (${status})`;
    if (retryAfter) errMsg += `. Retry after ${retryAfter} seconds`;
    if (limit && remaining !== null) errMsg += `. ${remaining}/${limit} requests remaining`;

    return `❌ ${errMsg}\n\nError details: ${JSON.stringify(data)}`;
  }

  let errorDetail = "Unknown API error";
  if (data && Array.isArray(data.errors) && data.errors.length > 0) {
    errorDetail = data.errors[0].detail || errorDetail;
  }

  return `❌ API Error (${status}): ${errorDetail}\n\nFull response: ${JSON.stringify(data)}`;
}

interface ApiAttemptResult {
  success: boolean;
  text: string;
  isKeyFailure?: boolean;
  status?: number;
}

// Execute with multi-key round-robin rotation and automatic fallback
async function executeWithKeyRotation(
  env: Env,
  action: (apiKey: string) => Promise<ApiAttemptResult>
): Promise<{ text: string; isError?: boolean }> {
  updateKeyPoolFromEnv(env);
  const keys = keyPool.getKeys();
  const n = keys.length;

  if (n === 0) {
    return {
      text: "❌ No API key configured. Please set ABUSEIPDB_API_KEYS (or ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEYS) via wrangler secret or .dev.vars.",
      isError: true,
    };
  }

  const startIndex = keyPool.getNextKeyIndex();
  const failureLogs: string[] = [];

  for (let attempt = 0; attempt < n; attempt++) {
    const keyIdx = (startIndex + attempt) % n;
    const currentKey = keys[keyIdx];

    // If key is on cooldown, and at least one other key is active, skip
    if (n > 1 && keyPool.isCooldown(currentKey)) {
      const anyActive = keys.some((k) => !keyPool.isCooldown(k));
      if (anyActive) {
        console.log(`[Key rotation] Key ${maskApiKey(currentKey)} is on cooldown, skipping.`);
        continue;
      }
    }

    try {
      const res = await action(currentKey);
      if (res.success) {
        keyPool.clearCooldown(currentKey);
        return { text: res.text, isError: false };
      }

      // If it's a key failure (401, 403, 429) and we have other keys to try:
      if (res.isKeyFailure && n > 1) {
        const cooldownMs = res.status === 429 ? 60 * 1000 : 300 * 1000;
        keyPool.markCooldown(currentKey, cooldownMs);
        const reason = res.status === 429 ? "Rate limit / quota exceeded" : `Auth/Key error (${res.status})`;
        console.warn(`[Key rotation] Key ${maskApiKey(currentKey)} failed: ${reason}. Trying next key...`);
        failureLogs.push(`Key [${maskApiKey(currentKey)}]: ${reason}`);
        continue;
      }

      // Non-key failure (e.g. invalid arguments): return error without rotating
      return { text: res.text, isError: true };
    } catch (err: any) {
      if (n > 1) {
        keyPool.markCooldown(currentKey, 30 * 1000);
        console.warn(`[Key rotation] Network error with key ${maskApiKey(currentKey)}: ${err.message}. Trying next key...`);
        failureLogs.push(`Key [${maskApiKey(currentKey)}]: ${err.message}`);
        continue;
      }
      return { text: `❌ Request failed: ${err.message || String(err)}`, isError: true };
    }
  }

  return {
    text: `❌ All ${n} API key(s) failed or are unavailable:\n${failureLogs.join("\n")}`,
    isError: true,
  };
}

// Tool execution logic
async function executeTool(name: string, args: any, env: Env): Promise<{ text: string; isError?: boolean }> {
  const baseUrl = "https://api.abuseipdb.com/api/v2";

  if (name === "check_ip") {
    const ipAddress = args?.ipAddress;
    const maxAgeInDays = args?.maxAgeInDays ?? 30;
    const verbose = args?.verbose ?? true;

    if (!isValidIp(ipAddress)) {
      return { text: "❌ Invalid IP address format", isError: true };
    }

    const params = new URLSearchParams({
      ipAddress,
      maxAgeInDays: String(maxAgeInDays),
    });
    if (verbose) {
      params.append("verbose", "");
    }

    return executeWithKeyRotation(env, async (apiKey) => {
      const res = await makeAbuseIPDBRequest(`${baseUrl}/check?${params.toString()}`, {
        method: "GET",
        headers: {
          Key: apiKey,
          Accept: "application/json",
          "User-Agent": "AbuseIPDB-MCP-Worker/1.3",
        },
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const isKeyErr = res.status === 401 || res.status === 403 || res.status === 429;
        return {
          success: false,
          text: handleApiError(res, data),
          isKeyFailure: isKeyErr,
          status: res.status,
        };
      }

      return { success: true, text: formatCheckResponse(data) };
    });
  }

  if (name === "report_ip") {
    const ip = args?.ip;
    const categories = args?.categories;
    const comment = args?.comment ?? "";
    const timestamp = args?.timestamp;

    if (!isValidIp(ip)) {
      return { text: "❌ Invalid IP address format", isError: true };
    }

    if (!isValidCategories(categories)) {
      return { text: "❌ Categories must be comma-separated integers", isError: true };
    }

    const formData = new URLSearchParams();
    formData.append("ip", ip);
    formData.append("categories", categories);
    formData.append("comment", comment);
    if (timestamp) {
      formData.append("timestamp", timestamp);
    }

    return executeWithKeyRotation(env, async (apiKey) => {
      const res = await makeAbuseIPDBRequest(`${baseUrl}/report`, {
        method: "POST",
        headers: {
          Key: apiKey,
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "AbuseIPDB-MCP-Worker/1.3",
        },
        body: formData.toString(),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const isKeyErr = res.status === 401 || res.status === 403 || res.status === 429;
        return {
          success: false,
          text: handleApiError(res, data),
          isKeyFailure: isKeyErr,
          status: res.status,
        };
      }

      return { success: true, text: formatReportResponse(data) };
    });
  }

  return { text: `Unknown tool: ${name}`, isError: true };
}

// JSON-RPC 2.0 Dispatcher for MCP
async function handleJsonRpc(
  rpcReq: any,
  env: Env
): Promise<any | null> {
  if (!rpcReq || typeof rpcReq !== "object") {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid Request" },
    };
  }

  const { id, method, params } = rpcReq;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case "initialize": {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {},
          },
          serverInfo: {
            name: "abuseipdb-mcp-server",
            version: "1.3.0",
          },
        },
      };
    }

    case "notifications/initialized":
    case "initialized": {
      return isNotification ? null : { jsonrpc: "2.0", id, result: {} };
    }

    case "ping": {
      return {
        jsonrpc: "2.0",
        id,
        result: {},
      };
    }

    case "tools/list": {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: getToolsDefinition(),
        },
      };
    }

    case "tools/call": {
      const toolName = params?.name;
      const toolArgs = params?.arguments ?? {};
      const { text, isError } = await executeTool(toolName, toolArgs, env);

      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text,
            },
          ],
          isError: Boolean(isError),
        },
      };
    }

    default: {
      if (isNotification) return null;
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`,
        },
      };
    }
  }
}

// Cloudflare Worker Fetch Entrypoint
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;

    // Handle CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    updateKeyPoolFromEnv(env);

    // Health / Landing check or Root SSE
    if ((url.pathname === "/" || url.pathname === "/health" || url.pathname === "/mcp") && method === "GET") {
      const acceptHeader = request.headers.get("Accept") || "";
      if (acceptHeader.includes("text/event-stream") && (url.pathname === "/" || url.pathname === "/mcp")) {
        // Fall through to SSE handler below
      } else {
        const keys = keyPool.getKeys();
        return jsonResponse({
          name: "AbuseIPDB MCP Server (Cloudflare Worker)",
          version: "1.3.0",
          status: "healthy",
          hasApiKey: keys.length > 0,
          configuredKeysCount: keys.length,
          endpoints: {
            sse: `${url.origin}/sse`,
            message: `${url.origin}/message?sessionId=:sessionId`,
            mcp: `${url.origin}/mcp`,
          },
          tools: getToolsDefinition().map((t) => ({ name: t.name, description: t.description })),
        });
      }
    }

    // --- MCP Transport 1: SSE (GET /sse or GET / with text/event-stream) ---
    if ((url.pathname === "/sse" || url.pathname === "/" || url.pathname === "/mcp") && method === "GET") {
      const keys = keyPool.getKeys();
      if (keys.length === 0) {
        return textResponse("ABUSEIPDB_API_KEYS (or ABUSEIPDB_API_KEY) is not configured", 500);
      }

      const sessionId = crypto.randomUUID();
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const encoder = new TextEncoder();

      sseSessions.set(sessionId, writer);

      // Send initial endpoint event as required by MCP SSE spec (using absolute origin URL)
      const endpointUrl = `${url.origin}/message?sessionId=${sessionId}`;
      const initEvent = `event: endpoint\ndata: ${endpointUrl}\n\n`;
      writer.write(encoder.encode(initEvent));

      // Periodic ping to keep SSE connection alive
      let keepAliveInterval: any;
      keepAliveInterval = setInterval(async () => {
        try {
          await writer.write(encoder.encode(": ping\n\n"));
        } catch {
          clearInterval(keepAliveInterval);
          sseSessions.delete(sessionId);
        }
      }, 15000);

      // Ensure cleanup if connection aborts
      request.signal.addEventListener("abort", () => {
        clearInterval(keepAliveInterval);
        sseSessions.delete(sessionId);
        try {
          writer.close();
        } catch {
          // ignore
        }
      });

      return new Response(readable, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "Mcp-Session-Id": sessionId,
          ...corsHeaders(),
        },
      });
    }

    // Helper to format MCP HTTP response respecting client Accept header
    const formatMcpResponse = (responseRpc: any, accept: string | null) => {
      if (responseRpc === null) {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (accept && accept.includes("text/event-stream")) {
        const sseBody = `event: message\ndata: ${JSON.stringify(responseRpc)}\n\n`;
        return new Response(sseBody, {
          status: 200,
          headers: {
            "Content-Type": "text/event-stream; charset=utf-8",
            "Cache-Control": "no-cache",
            ...corsHeaders(),
          },
        });
      }
      return jsonResponse(responseRpc);
    };

    // --- MCP Transport 1: SSE Message Posting (POST /message) ---
    if (url.pathname === "/message" && method === "POST") {
      const sessionId = url.searchParams.get("sessionId") || request.headers.get("Mcp-Session-Id");
      let body: any;
      try {
        body = await request.json();
      } catch {
        return textResponse("Invalid JSON body", 400);
      }

      // Process RPC message
      const responseRpc = await handleJsonRpc(body, env);

      // If active SSE writer exists in this isolate, notify it
      if (sessionId && sseSessions.has(sessionId) && responseRpc) {
        const writer = sseSessions.get(sessionId)!;
        const encoder = new TextEncoder();
        try {
          const sseData = `event: message\ndata: ${JSON.stringify(responseRpc)}\n\n`;
          writer.write(encoder.encode(sseData));
        } catch {
          sseSessions.delete(sessionId);
        }
      }

      // Return response respecting Accept header (stateless fallback ensures no 404!)
      return formatMcpResponse(responseRpc, request.headers.get("Accept"));
    }

    // --- MCP Transport 2: Streamable HTTP / Direct JSON-RPC (POST /mcp, POST /sse, or POST /) ---
    if ((url.pathname === "/mcp" || url.pathname === "/" || url.pathname === "/sse") && method === "POST") {
      let body: any;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          {
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: "Parse error: Invalid JSON" },
          },
          400
        );
      }

      const acceptHeader = request.headers.get("Accept");

      // Support batch requests
      if (Array.isArray(body)) {
        const responses = (
          await Promise.all(body.map((item) => handleJsonRpc(item, env)))
        ).filter(Boolean);
        return jsonResponse(responses);
      }

      const responseRpc = await handleJsonRpc(body, env);
      return formatMcpResponse(responseRpc, acceptHeader);
    }

    // 404 for unhandled routes
    return textResponse("Not Found", 404);
  },
};
