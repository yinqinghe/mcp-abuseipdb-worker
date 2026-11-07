/**
 * AbuseIPDB MCP Server for Cloudflare Workers
 * 
 * Supports:
 * - MCP SSE Transport: GET /sse & POST /message?sessionId=...
 * - MCP Streamable HTTP / Direct JSON-RPC: POST /mcp & POST /
 * - Health check & tools metadata: GET / & GET /health
 */

export interface Env {
  ABUSEIPDB_API_KEY?: string;
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
  maxRetries = 3
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(url, options);
      return res;
    } catch (err) {
      lastError = err;
      if (attempt < maxRetries - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
      }
    }
  }
  throw lastError;
}

// Format check_ip response
function formatCheckResponse(data: any): string {
  try {
    const ipData = data?.data;
    if (!ipData) {
      return `❌ Invalid response structure from AbuseIPDB: ${JSON.stringify(data)}`;
    }

    let result = "AbuseIPDB Check Results\n\n";
    result += `IP Address: ${ipData.ipAddress}\n`;
    result += `Abuse Confidence Score: ${ipData.abuseConfidenceScore}%\n`;
    result += `Is Public: ${ipData.isPublic ? "Yes" : "No"}\n`;
    result += `Is Whitelisted: ${ipData.isWhitelisted ? "Yes" : "No"}\n`;

    const countryName = ipData.countryName || "Unknown";
    const countryCode = ipData.countryCode || "N/A";
    result += `Country: ${countryName} (${countryCode})\n`;
    result += `ISP: ${ipData.isp || "N/A"}\n`;
    result += `Usage Type: ${ipData.usageType || "N/A"}\n`;
    result += `Domain: ${ipData.domain || "N/A"}\n`;
    result += `Total Reports: ${ipData.totalReports ?? 0}\n`;

    if (ipData.lastReportedAt) {
      result += `Last Reported: ${ipData.lastReportedAt}\n`;
    }

    if ("isTor" in ipData) {
      result += `Is Tor: ${ipData.isTor ? "Yes" : "No"}\n`;
    }

    const categoryNames: string[] = [];
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
      }
    }

    if (categoryNames.length > 0) {
      result += `Categories: ${categoryNames.join(", ")}\n`;
    } else {
      result += "Categories: N/A\n";
    }

    return result;
  } catch (err: any) {
    return `❌ Error formatting response: ${err.message || String(err)}`;
  }
}

// Format report_ip response
function formatReportResponse(data: any): string {
  const reportData = data?.data;
  if (!reportData) {
    return `❌ Invalid response structure: ${JSON.stringify(data)}`;
  }
  let result = "IP Address Reported Successfully\n\n";
  result += `IP Address: ${reportData.ipAddress || "N/A"}\n`;
  result += `Updated Abuse Confidence Score: ${reportData.abuseConfidenceScore ?? "N/A"}%\n`;
  return result;
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

// Tool execution logic
async function executeTool(name: string, args: any, apiKey?: string): Promise<{ text: string; isError?: boolean }> {
  if (!apiKey) {
    return {
      text: "❌ ABUSEIPDB_API_KEY environment variable is required. Configure it via wrangler secret or .dev.vars.",
      isError: true,
    };
  }

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

    try {
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
        return { text: handleApiError(res, data), isError: true };
      }

      return { text: formatCheckResponse(data) };
    } catch (err: any) {
      return { text: `❌ API request failed: ${err.message || String(err)}`, isError: true };
    }
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

    try {
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
        return { text: handleApiError(res, data), isError: true };
      }

      return { text: formatReportResponse(data) };
    } catch (err: any) {
      return { text: `❌ API request failed: ${err.message || String(err)}`, isError: true };
    }
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

  // Handle MCP Notifications (no response required when id is omitted)
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
      const { text, isError } = await executeTool(toolName, toolArgs, env.ABUSEIPDB_API_KEY);

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

    // Health / Landing check
    if ((url.pathname === "/" || url.pathname === "/health") && method === "GET") {
      return jsonResponse({
        name: "AbuseIPDB MCP Server (Cloudflare Worker)",
        version: "1.3.0",
        status: "healthy",
        hasApiKey: Boolean(env.ABUSEIPDB_API_KEY),
        endpoints: {
          sse: `${url.origin}/sse`,
          message: `${url.origin}/message?sessionId=:sessionId`,
          mcp: `${url.origin}/mcp`,
        },
        tools: getToolsDefinition().map((t) => ({ name: t.name, description: t.description })),
      });
    }

    // --- MCP Transport 1: SSE (GET /sse) ---
    if (url.pathname === "/sse" && method === "GET") {
      const sessionId = crypto.randomUUID();
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const encoder = new TextEncoder();

      sseSessions.set(sessionId, writer);

      // Send initial endpoint event as required by MCP SSE spec
      const endpointUrl = `/message?sessionId=${sessionId}`;
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

      // Return response respecting Accept header
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
