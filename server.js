#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import path from "path";
import http from "http";
import mime from "mime-types";
import mammoth from "mammoth";
import { createRequire } from "module";
import crypto from 'crypto';

import { GATEWAY_CONFIG } from './config.js';
import { 
    getWorkspaceDir, 
    ensureWorkspaceExists, 
    getSecurePath,
    statSafeFile,
    readSafeFile,
    streamSafeFile,
    createSafeWriteStream, 
    deleteSafeFile,
    checkNoClobber,
    commitDownload
} from './fileOps.js';

import {
    checkRateLimit,
    sanitizeHeaders,
    secureFetch,
    streamToFile,
    auditLog,
    redactUrl 
} from './safegrd.js';

const WORKSPACE_DIR = getWorkspaceDir(GATEWAY_CONFIG.workspaceOverride);

let activeTunnelUrl = GATEWAY_CONFIG.tunnelUrlFallback;
async function initializeTunnel() {
if (!activeTunnelUrl) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);

  try {
    const response = await fetch(`http://127.0.0.1:${GATEWAY_CONFIG.discoveryPort}/api/tunnels`, {
      signal: controller.signal
    });
        
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data?.tunnels)) {
        const httpsTunnel = data.tunnels.find(t => 
          typeof t.public_url === 'string' && t.public_url.startsWith('https://')
        );
        if (httpsTunnel) {
          activeTunnelUrl = httpsTunnel.public_url;
          console.error(`\n\x1b[32m[System]\x1b[0m Auto-discovered active Ngrok tunnel: ${activeTunnelUrl}\n`);
        }
      }
    }
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      console.error(`\n\x1b[33m[Warning]\x1b[0m Ngrok auto-discovery timed out on port ${GATEWAY_CONFIG.discoveryPort}.`);
    } else {
      console.error(`\n\x1b[33m[Warning]\x1b[0m PUBLIC_TUNNEL_URL is empty and local Ngrok was not detected.`);
    }
    console.error(`External download links will fail. Operating in Local-Only Mode.\n`);
  }
}
}

const require = createRequire(import.meta.url);
const pdf = require("pdf-parse");
const pkg = require("./package.json");

if (process.argv.includes('--version') || process.argv.includes('-v')) {
  console.log(`openclaw-syncralis v${pkg.version}`);
  process.exit(0);
}

function validateConfig() {
    if (!GATEWAY_CONFIG.secret ||
        Buffer.byteLength(String(GATEWAY_CONFIG.secret), 'utf8') < 32) {
        console.error('[Fatal] GATEWAY_SECRET must be at least 32 bytes of entropy.');
        process.exit(1);
    }
    const port = Number(GATEWAY_CONFIG.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        console.error(`[Fatal] Invalid port: ${GATEWAY_CONFIG.port}`);
        process.exit(1);
    }
    if (!GATEWAY_CONFIG.tavilyKey || !GATEWAY_CONFIG.braveKey) {
        console.warn('[Warning] One or more search API keys are missing. web_search will be degraded.');
    }
}

const TIMEOUT_MS = 10000;
const MAX_QUERY_LENGTH = 2000;

const MAX_DOWNLOAD_ATTEMPTS = 3;
const CONFIRM_TOKEN_TTL_MS = 5 * 60 * 1000;

const TOKEN_MAX_BYTES = 8192;
const HMAC_BYTE_LENGTH = 32;

const HTTP_MAX_CONNECTIONS = 200;
const HTTP_KEEP_ALIVE_MS = 65000;
const HTTP_HEADERS_TIMEOUT = 66000;
const HTTP_REQUEST_TIMEOUT = 30000;

const IP_RATE_WINDOW_MS = 60000;
const IP_RATE_MAX_REQS = 20;

const CB_FAILURE_THRESHOLD = 5;
const CB_RESET_TIMEOUT_MS = 60000;

const GC_INTERVAL_MS = 10 * 60000;
const SHUTDOWN_DEADLINE_MS = 10000;

const SECURITY_HEADERS = Object.freeze({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'interest-cohort=()',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'Content-Security-Policy': "default-src 'none'",
    'X-Server-Version': pkg.version
});

let requestCount = 0;

const pendingConfirmations = new Map();
const downloadAttemptTracker = new Map();

function generateRequestId() {
    return crypto.randomBytes(8).toString('hex');
}

function buildContentDisposition(filename) {
    const ascii = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\;,]/g, '_');
    const encoded = encodeURIComponent(filename);
    return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

function decodeHmacBuffer(hexStr, expectedBytes, label) {
    if (typeof hexStr !== 'string' || hexStr.length !== expectedBytes * 2) {
        throw new Error(`${label}: invalid HMAC format.`);
    }
    const buf = Buffer.from(hexStr, 'hex');
    if (buf.length !== expectedBytes) {
        throw new Error(`${label}: HMAC decode produced unexpected length.`);
    }
    return buf;
}

function issueConfirmationToken(filename, resolvedPath) {
    const payload = Buffer.from(
        JSON.stringify({ filename, resolvedPath, issuedAt: Date.now() })
    ).toString('base64url');

    const sig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                      .update(payload)
                      .digest('hex');
    
    const token = `${payload}.${sig}`;

    pendingConfirmations.set(token, { filename, resolvedPath, issuedAt: Date.now() });

    setTimeout(() => pendingConfirmations.delete(token), CONFIRM_TOKEN_TTL_MS + 2000);
    return token;
}

function consumeConfirmationToken(token, expectedFilename) {
    if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > TOKEN_MAX_BYTES) {
        throw new Error('Confirmation token is malformed or exceeds maximum length.');
    }

    const dotIdx  = token.lastIndexOf('.');
    if (dotIdx < 1) {
        throw new Error('Confirmation token is malformed.');
    }
    const payload = token.slice(0, dotIdx);
    const sig = token.slice(dotIdx + 1);
    
    const expectedSig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                              .update(payload)
                              .digest('hex');
    
    const sigBuf = decodeHmacBuffer(sig, HMAC_BYTE_LENGTH, 'token.sig');
    const expBuf = decodeHmacBuffer(expectedSig, HMAC_BYTE_LENGTH, 'expected.sig');
    
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) {
        auditLog('CONFIRM_TOKEN_INVALID_SIG', { expectedFilename });
        throw new Error('Confirmation token signature is invalid.');
    }

    if (!pendingConfirmations.has(token)) {
        auditLog('CONFIRM_TOKEN_REPLAYED_OR_EXPIRED', { expectedFilename });
        throw new Error('Confirmation token has already been used or has expired.');
    }

    let data;
    try {
        data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    } catch {
        throw new Error('Confirmation token payload is corrupted.');
    }
    
    if (Date.now() - data.issuedAt > CONFIRM_TOKEN_TTL_MS) {
        pendingConfirmations.delete(token);
        throw new Error(`Confirmation token expired after ${CONFIRM_TOKEN_TTL_MS / 60000} minutes.`);
    }
    
    if (data.filename !== expectedFilename) {
        auditLog('CONFIRM_TOKEN_FILE_MISMATCH', {
            tokenFile: data.filename,
            requestedFile: expectedFilename,
        });
        throw new Error(
            `Confirmation token was issued for "${data.filename}", not "${expectedFilename}". ` +
            `Generate a new preview for the correct file.`
        );
    }
    
    pendingConfirmations.delete(token);
    return data;
}

class CircuitBreaker {
    #name;
    #failures = 0;
    #state = 'CLOSED';
    #nextTry = 0;

    constructor(name) { this.#name = name; }

    get name()  { return this.#name; }
    get state() { return this.#state; }

    isOpen() {
        if (this.#state === 'OPEN') {
            if (Date.now() >= this.#nextTry) {
                this.#state = 'HALF_OPEN';
                console.error(`[System] Circuit half-open for provider: ${this.#name}`);
                return false;
            }
            return true;
        }
        return false;
    }

    onSuccess() {
        if (this.#state !== 'CLOSED') {
            console.error(`[System] Circuit closed (recovered) for provider: ${this.#name}`);
        }
        this.#failures = 0;
        this.#state    = 'CLOSED';
    }

    onFailure() {
        this.#failures += 1;
        if (this.#failures >= CB_FAILURE_THRESHOLD) {
            this.#state = 'OPEN';
            this.#nextTry = Date.now() + CB_RESET_TIMEOUT_MS;
            console.warn(
                `[Warning] Circuit opened for provider: ${this.#name} ` +
                `(${this.#failures} failures). Retrying in ${CB_RESET_TIMEOUT_MS / 1000}s.`
            );
        }
    }
}

const breakers = {
    tavily: new CircuitBreaker('tavily'),
    brave:  new CircuitBreaker('brave'),
};

const ipRateBuckets = new Map();

function checkIpRateLimit(ip) {
    const now    = Date.now();
    let   bucket = ipRateBuckets.get(ip);

    if (!bucket || now - bucket.windowStart >= IP_RATE_WINDOW_MS) {
        bucket = { count: 0, windowStart: now };
        ipRateBuckets.set(ip, bucket);
    }

    bucket.count += 1;
    return bucket.count <= IP_RATE_MAX_REQS;
}

let gcInterval;

function startGc() {
    gcInterval = setInterval(() => {
        const now = Date.now();
        let   n   = 0;

        for (const [k, v] of pendingConfirmations) {
            if (now - v.issuedAt > CONFIRM_TOKEN_TTL_MS + 5_000) {
                pendingConfirmations.delete(k); n++;
            }
        }
        for (const [k, v] of downloadAttemptTracker) {
            if (v.expiresAt && now > v.expiresAt + 5_000) {
                downloadAttemptTracker.delete(k); n++;
            }
        }
        for (const [k, v] of ipRateBuckets) {
            if (now - v.windowStart > IP_RATE_WINDOW_MS * 3) {
                ipRateBuckets.delete(k); n++;
            }
        }

        if (n > 0) console.error(`[GC] Evicted ${n} stale entries.`);
    }, GC_INTERVAL_MS);

    gcInterval.unref();
}

function generateSignedUrl(filename, expirationMinutes = 60) {
    if (!activeTunnelUrl) {
      throw new Error("PUBLIC_TUNNEL_URL is not configured.");
    }
    
    const safeFilename = path.basename(filename);
    const safeUrlName = encodeURIComponent(safeFilename);
    const baseUrl = activeTunnelUrl.replace(/\/$/, "");
    const expires = Date.now() + (expirationMinutes * 60 * 1000);
    const dataToSign = `${safeFilename}:${expires}`;
    
    const signature = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                            .update(dataToSign)
                            .digest('hex');

    downloadAttemptTracker.set(signature, { attempts: 0, filename: safeFilename, expiresAt: expires });
    return `${baseUrl}/${safeUrlName}?expires=${expires}&sig=${signature}`;
}

const server = new Server(
    { name: "openclaw-syncralis", version: pkg.version },
    { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "share_files",
                description: [
                    'Reads or shares workspace files.  Three actions are available:',
                    "  'read' — return file contents inline. For PDFs: " +
                    "(1) If the user specifies a page number, read that range directly using pageStart/pageEnd. " +
                    "(2) If searching for a topic, first read pages 1-10 to find the Table of Contents. " +
                    "If no TOC is found in pages 1-10, extend to pages 1-20, then check the final 10 pages as some PDFs place the index at the back. " +
                    "(3) If the PDF has no TOC, scan in 15-page chunks from the beginning until the topic is located. " +
                    "(4) Always read in chunks of 20 pages or fewer. Never request the full PDF in a single call. " +
                    "(5) If a section appears to continue beyond the chunk boundary, read the next chunk to complete it. " +
                    "(6) For PDFs under 15 pages total, reading the entire document in one call is acceptable.",
                    "  'preview'  — REQUIRED first step before sharing.  Returns file metadata",
                    '               (name, size, type, modified) and a short-lived confirmationToken.',
                    '               Present ALL metadata to the user and ask for explicit approval',
                    '               before proceeding.  Never skip this step.',
                    "  'download' — generate a public download link.  Requires the confirmationToken",
                    "               returned by a prior 'preview' call for the same file.",
                    '               A link CANNOT be generated without a valid token.',
                ].join('\n'),
                inputSchema: {
                    type: "object",
                    properties: {
                        filePath: {
                            type: "string",
                            description: "The name of the file inside the workspace (e.g., invoice.pdf)"
                        },
                        action: {
                            type: "string",
                            enum: ["read", "preview", "download"],
                            description: "read | preview | download.  Always call 'preview' before 'download'."
                        },
                        confirmationToken: {
                            type: 'string',
                            description: "Required for action=download. The token returned by the preceding 'preview' call for this exact file."
                        },
                        pageStart: {
                            type: "number",
                            description: "PDF files only. The first page to return, 1-based (page 1 = first page). Omit only if the PDF is under 15 pages total and you intend to read the whole file."
                        },
                        pageEnd: {
                            type: "number",
                            description: "PDF files only. The last page to return, inclusive and 1-based. Keep the range between pageStart and pageEnd to 20 pages or fewer to avoid context overflow. If the content you need continues beyond pageEnd, make a follow-up call with the next range. Omit only if the PDF is under 15 pages total."
                        }
                    },
                    required: ["filePath", "action"]
                }
            },
            {
                name: "download_from_url",
                description: "Downloads a file directly from a public or authenticated HTTP/HTTPS URL and saves it to the workspace.",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: {
                            type: "string",
                            description: "The direct HTTP/HTTPS URL of the file to download."
                        },
                        fileName: {
                            type: "string",
                            description: "The name to save the downloaded file as (e.g., report.pdf)."
                        },
                        headers: {
                            type: "object",
                            description: "OPTIONAL: JSON object of HTTP headers for authenticated/secure URLs."
                        }
                    },
                    required: ["url", "fileName"]
                }
            },
            {
                name: "web_search",
                description: "Searches the live internet for accurate, up-to-date information. Use for current events.",
                inputSchema: {
                    type: "object",
                    properties: {
                        query: {
                            type: "string",
                            description: "The highly specific search query to look up."
                        }
                    },
                    required: ["query"]
                }
            }
        ]
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "share_files") {
        try {
            checkRateLimit('share_files');
            const { filePath, action = "read", confirmationToken, pageStart, pageEnd } = args;
            const securePath = await getSecurePath(WORKSPACE_DIR, filePath);
            const fileName = path.basename(securePath);

            if (action === 'preview') {
                const { size, mtime, mimeType } = await statSafeFile(securePath);
                const token = issueConfirmationToken(fileName, securePath);
                auditLog('SHARE_PREVIEW', { file: fileName, size });
                return {
                    content: [{
                        type: 'text',
                        text: JSON.stringify({
                            status: 'AWAITING_CONFIRMATION',
                            filename: fileName,
                            sizeBytes: size,
                            sizeHuman: `${(size / 1024).toFixed(1)} KB`,
                            mimeType,
                            modifiedAt: mtime.toISOString(),
                            confirmationToken: token,
                            tokenExpiresInSec: CONFIRM_TOKEN_TTL_MS / 1000,
                            instruction:
                                'Present filename, size, type, and modified date to the user. ' +
                                'Ask them to explicitly confirm this is the correct file before ' +
                                "calling action=download with the confirmationToken.",
                        }, null, 2),
                    }],
                };
            }

            if (action === "download") {
                if (!confirmationToken) {
                    throw new Error(
                        'action=download requires a confirmationToken. ' +
                        "Call action=preview first, present the file details to the user, " +
                        "and only proceed once they have explicitly confirmed the correct file."
                    );
                }
                consumeConfirmationToken(confirmationToken, fileName);
                const signedLink = generateSignedUrl(fileName);
                auditLog('SHARE_LINK_GENERATED', { file: fileName });
                return {
                    content: [{
                        type: "text",
                        text: `SUCCESS. Tell the user their file is ready and output exactly this URL: ${signedLink}`
                    }]
                };
            }

            const { buffer, mimeType } = await readSafeFile(securePath);
            if (mimeType.startsWith('image/')) {
                return { content: [{ type: "image", data: buffer.toString('base64'), mimeType }] };
            }
            
            if (mimeType === 'application/pdf') {
                const pdfOptions = { max: 0 };
                const pdfData = await pdf(buffer, pdfOptions);
                let pages;
                if (pdfData.nativePageTexts && pdfData.nativePageTexts.length > 1) {
                    pages = pdfData.nativePageTexts;
                } else {
                    const ffPages = pdfData.text.split(/\f/);
                    if (ffPages.length > 1) {
                        pages = ffPages;
                    } else {
                        const CHUNK = 3000;
                        const t = pdfData.text;
                        pages = [];
                        for (let i = 0; i < t.length; i += CHUNK) pages.push(t.slice(i, i + CHUNK));
                    }
                }
                const totalPages = pages.length;
                const start = Math.max(1, parseInt(pageStart) || 1);
                const end   = Math.min(totalPages, parseInt(pageEnd) || totalPages);
                const slice = pages.slice(start - 1, end).join("\n");
                const header = `[PDF: ${fileName} | Pages ${start}–${end} of ${totalPages}]\n\n`;
                return { content: [{ type: "text", text: header + slice }] };
            }
            
            if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                const docxData = await mammoth.extractRawText({ buffer: buffer });
                return { content: [{ type: "text", text: docxData.value }] };
            }
            
            auditLog('FILE_READ', { file: fileName, mimeType });
            return { content: [{ type: "text", text: buffer.toString('utf-8') }] };

        } catch (error) {
            auditLog('SHARE_FILES_ERROR', { error: error.message });
            return { isError: true, content: [{ type: "text", text: `Error: ${error.message}` }] };
        }
    }

    else if (name === "download_from_url") {
        let targetPath;
        let tmpTargetPath;
        let downloadSucceeded = false;
        try {
            checkRateLimit('download_from_url');
            const { url, fileName, headers = {} } = args;
            const safeHeaders = sanitizeHeaders(headers);
            const safeFileName = path.basename(fileName);
            targetPath = await getSecurePath(WORKSPACE_DIR, safeFileName);
            
            await checkNoClobber(targetPath, safeFileName);
            const tmpFileName = `${safeFileName}.tmp`;
            tmpTargetPath = await getSecurePath(WORKSPACE_DIR, tmpFileName);
            
            const response = await secureFetch(url, safeHeaders);

            const serverContentType = response.headers['content-type']; 
            const expectedMimeType = mime.lookup(safeFileName);
            if (serverContentType && expectedMimeType) {
                const cleanServerType = serverContentType.split(';')[0].trim().toLowerCase();
                if (cleanServerType !== expectedMimeType && cleanServerType !== 'application/octet-stream') {
                    response.destroy(); 
                    throw new Error(`SECURITY ALERT: MIME mismatch. Expected ${expectedMimeType}, received ${cleanServerType}. Download aborted.`);
                }
            }
            
            await ensureWorkspaceExists(WORKSPACE_DIR);
            
            const fileStream = createSafeWriteStream(tmpTargetPath);
            await streamToFile(response, fileStream);
            await commitDownload(tmpTargetPath, targetPath);
            downloadSucceeded = true;
            auditLog('DOWNLOAD_SUCCESS', { url: redactUrl(url), savedAs: targetPath });

            return {
                content: [{
                    type: "text",
                    text: `SUCCESS: Securely downloaded from URL and saved to ${targetPath}.`
                }]
            };
        } catch (error) {
            if (!downloadSucceeded && tmpTargetPath) {
                await deleteSafeFile(tmpTargetPath).catch(() => {});
            }
            auditLog('DOWNLOAD_FAILED', { error: error.message });
            return { isError: true, content: [{ type: "text", text: `Fetch Error: ${error.message}` }] };
        }
    } 
    
    else if (name === "web_search") {
        try {
            checkRateLimit('web_search');
            let rawQuery = request.params.arguments?.query;
            const tavilyKey = GATEWAY_CONFIG.tavilyKey;
            const braveKey = GATEWAY_CONFIG.braveKey;

            if (!rawQuery || typeof rawQuery !== 'string') {
                return { isError: true, content: [{ type: "text", text: "Search failed: Query must be a valid string." }] };
            }
            if (!tavilyKey || !braveKey) {
                return { isError: true, content: [{ type: "text", text: "Search failed: Server configuration error (Missing API Keys)." }] };
            }

            const query = rawQuery.trim().substring(0, MAX_QUERY_LENGTH);
            if (query === '') {
                return { isError: true, content: [{ type: "text", text: "Search failed: Query cannot be empty." }] };
            }

            const isBraveTurn = (requestCount++ % 2) === 0;

            let resultText;
            if (isBraveTurn) {
                resultText = await executeSearchAttempt(query, braveKey, 'brave', fetchBrave) ?? await executeSearchAttempt(query, tavilyKey, 'tavily', fetchTavily);
            } else {
                resultText = await executeSearchAttempt(query, tavilyKey, 'tavily', fetchTavily) ?? await executeSearchAttempt(query, braveKey, 'brave', fetchBrave);
            }

            if (resultText === null) {
                return { isError: true, content: [{ type: 'text', text: 'Search failed: all providers are currently unavailable.' }] };
            }
            
            return { content: [{ type: "text", text: resultText }] };

        } catch (error) {
            auditLog('SEARCH_FAILED', { error: error.message });
            return { isError: true, content: [{ type: "text", text: `Search Error: ${error.message}` }] };
        }
    }

    throw new Error(`Tool not found: ${name}`);
});

async function executeSearchAttempt(query, apiKey, breakerKey, fetchFn) {
    const breaker = breakers[breakerKey];
    if (breaker.isOpen()) {
        console.warn(`[Warning] Search circuit open for provider: ${breakerKey}`);
        return null;
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const result = await fetchFn(query, apiKey, controller.signal);
        clearTimeout(timeoutId);
        breaker.onSuccess();
        return result;
    } catch (error) {
        clearTimeout(timeoutId);
        breaker.onFailure();
        if (error.name === 'AbortError') {
            throw new Error(`Network timeout (${TIMEOUT_MS / 1000}s).`);
        }
        throw error;
    }
}

async function fetchTavily(query, apiKey, signal) {
    const response = await fetch("https://api.tavily.com/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            api_key: apiKey,
            query: query,
            search_depth: "basic",
            include_answer: true,
            max_results: 4
        }),
        signal: signal
    });

    if (!response.ok) throw new Error(`Tavily HTTP ${response.status}`);
    const data = await response.json();

    let resultText = "";
    if (data.answer) resultText += `[DIRECT ANSWER]\n${data.answer}\n\n`;
    if (data.results?.length > 0) {
        resultText += "[SOURCE RESULTS]\n";
        resultText += data.results.map(r => `Title: ${r.title}\nSnippet: ${r.content}\nURL: ${r.url}`).join('\n\n---\n\n');
    } else {
        resultText += "No relevant results were found on Tavily.";
    }
    return resultText;
}

async function fetchBrave(query, apiKey, signal) {
    const response = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=4`, {
        headers: {
            "Accept": "application/json",
            "X-Subscription-Token": apiKey,
        },
        signal: signal
    });

    if (!response.ok) throw new Error(`Brave HTTP ${response.status}`);
    const data = await response.json();

    let resultText = "";
    if (data.web?.results?.length > 0) {
        resultText += "[SOURCE RESULTS]\n";
        resultText += data.web.results.map(r => `Title: ${r.title}\nSnippet: ${r.description}\nURL: ${r.url}`).join('\n\n---\n\n');
    } else {
        resultText += "No relevant results were found on Brave.";
    }
    return resultText;
}

let fileServerRef = null;
const activeConnections = new Set();

function startSecureFileServer() {
    const PORT = GATEWAY_CONFIG.port;
    const HOST = GATEWAY_CONFIG.host || '127.0.0.1';
    
    const fileServer = http.createServer(async (req, res) => {
        const requestId = req.headers['x-request-id']?.slice(0, 64) || generateRequestId();
        const startMs   = Date.now();
        const clientIp  = (
            req.headers['x-forwarded-for']?.split(',')[0].trim() ||
            req.socket?.remoteAddress ||
            'unknown'
        );

        for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
        res.setHeader('X-Request-Id', requestId);

        try {
            if (req.url === '/health' || req.url === '/health/') {
                const body = JSON.stringify({
                    status: 'ok',
                    version: pkg.version,
                    uptime: process.uptime(),
                    timestamp: new Date().toISOString(),
                });
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                });
                return res.end(body);
            }
            
            // Strictly enforce GET requests
            if (req.method !== 'GET') {
                res.writeHead(405, {
                    'Content-Type': 'text/plain',
                    Allow: 'GET',
                });
                return res.end('Method Not Allowed');
            }

            if (!checkIpRateLimit(clientIp)) {
                auditLog('HTTP_RATE_LIMITED', { ip: clientIp, requestId });
                res.writeHead(429, {
                    'Content-Type': 'text/plain',
                    'Retry-After':  String(Math.ceil(IP_RATE_WINDOW_MS / 1000)),
                });
                return res.end('Too Many Requests. Please wait before retrying.');
            }

            let reqUrl;
            try {
                reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
            } catch {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Bad Request');
            }
            
            const requestedFile = decodeURIComponent(reqUrl.pathname.slice(1));
            if (!requestedFile) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Bad Request');
            }

            const rawExpires = reqUrl.searchParams.get('expires');
            const providedSig = reqUrl.searchParams.get('sig');

            if (!rawExpires || !providedSig) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Bad Request: missing cryptographic parameters.');
            }

            const expires = parseInt(rawExpires, 10);
            if (!Number.isFinite(expires) || expires <= 0) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Bad Request: malformed expiry parameter.');
            }
            
            if (Date.now() > expires) {
                auditLog('LINK_EXPIRED', { requestId, ip: clientIp });
                res.writeHead(410, { 'Content-Type': 'text/plain' });
                return res.end('Gone: this secure link has expired. Please generate a new one.');
            }

            const safeFilename = path.basename(requestedFile);
            if (!safeFilename || safeFilename !== requestedFile) {
                auditLog('PATH_TRAVERSAL_BLOCKED', { file: requestedFile, requestId, ip: clientIp });
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Bad Request: invalid file path.');
            }
            const dataToVerify = `${safeFilename}:${expires}`;
            const expectedSig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                                      .update(dataToVerify)
                                      .digest('hex');

            const providedSigBuffer = decodeHmacBuffer(providedSig, HMAC_BYTE_LENGTH, 'provided.sig');
            const expectedSigBuffer = decodeHmacBuffer(expectedSig, HMAC_BYTE_LENGTH, 'expected.sig');

            if (!crypto.timingSafeEqual(providedSigBuffer, expectedSigBuffer)) {
                auditLog('SIGNATURE_MISMATCH', { file: safeFilename, requestId, ip: clientIp });
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                return res.end('Forbidden');
            }

            const tracker = downloadAttemptTracker.get(providedSig);
            if (!tracker) {
                auditLog('UNKNOWN_LINK', { file: safeFilename, requestId, ip: clientIp });
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                return res.end('Not Found: unrecognised link — please generate a new download URL.');
            }
            if (tracker.attempts >= MAX_DOWNLOAD_ATTEMPTS) {
                auditLog('DOWNLOAD_LIMIT_EXCEEDED', { file: safeFilename, attempts: tracker.attempts, ip: clientIp, requestId });
                res.writeHead(429, { 'Content-Type': 'text/plain' });
                return res.end(`Download limit reached. This link allows a maximum of ${MAX_DOWNLOAD_ATTEMPTS} download(s).\nKindly generate a new link.`);
            }
            tracker.attempts += 1;
            auditLog('DOWNLOAD_ATTEMPT', { file: safeFilename, attempt: tracker.attempts, maxAllowed: MAX_DOWNLOAD_ATTEMPTS });
            
            const securePath = await getSecurePath(WORKSPACE_DIR, requestedFile);
            const { mimeType, size } = await statSafeFile(securePath);
            
            res.writeHead(200, {
                'Content-Type': mimeType,
                'Content-Length': size,
                'Content-Disposition': buildContentDisposition(path.basename(securePath)),
                'X-Request-Id': requestId
            });

            try {
                await streamSafeFile(securePath, res);
            } catch (pipeErr) {
                if (
                    pipeErr.code === 'EPIPE' ||
                    pipeErr.code === 'ERR_STREAM_PREMATURE_CLOSE'
                ) {
                    console.error(
                        `[System] Client disconnected mid-transfer. ` +
                        `File: ${safeFilename}, RequestId: ${requestId}, IP: ${clientIp}`
                    );
                    return;
                }
                throw pipeErr;
            }

            auditLog('FILE_SERVED', { file: path.basename(securePath), size, mimeType, ip: clientIp, requestId, durationMs: Date.now() - startMs });

        } catch (error) {
            console.error(
                `[File Server Error] RequestId: ${requestId}, IP: ${clientIp}, ` +
                `Error: ${error.message}`
            );
            if (!res.headersSent) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                return res.end('Not Found');
            }
        }
    });

    fileServer.maxConnections = HTTP_MAX_CONNECTIONS;
    fileServer.keepAliveTimeout = HTTP_KEEP_ALIVE_MS;
    fileServer.headersTimeout = HTTP_HEADERS_TIMEOUT;
    fileServer.requestTimeout = HTTP_REQUEST_TIMEOUT;

    fileServer.on('connection', (socket) => {
        activeConnections.add(socket);
        socket.once('close', () => activeConnections.delete(socket));
    });

    fileServer.on('error', (err) => {
        console.error(`[HTTP Server Error] ${err.message} (code: ${err.code})`);
    });

    fileServer.listen(PORT, HOST, () => {
        console.error(`[System] Native Secure File Server bound internally to ${HOST}:${PORT}`);
    });

    fileServerRef = fileServer;
}

let isShuttingDown = false;

function gracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.error(`[System] Shutdown initiated. Signal: ${signal}, Open connections: ${activeConnections.size}`);

    clearInterval(gcInterval);

    const deadline = setTimeout(() => {
        console.warn('[Warning] Graceful shutdown deadline exceeded. Forcing exit.');
        process.exit(1);
    }, SHUTDOWN_DEADLINE_MS);
    deadline.unref();

    fileServerRef?.close(() => console.error('[System] HTTP server closed.'));

    for (const socket of activeConnections) socket.destroy();

    setImmediate(() => {
        console.error('[System] Shutdown complete.');
        clearTimeout(deadline);
        process.exit(0);
    });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
    const detail = reason instanceof Error
        ? `${reason.message}\n${reason.stack}`
        : String(reason);
    console.error(`[Unhandled Rejection] ${detail}`);
});

process.on('uncaughtException', (err) => {
    console.error(`[Fatal] Uncaught exception: ${err.message}\n${err.stack}`);
    process.exit(1);
});

async function main() {
    validateConfig();
    try {
        await initializeTunnel();
        await ensureWorkspaceExists(WORKSPACE_DIR);
        startGc();
        startSecureFileServer();
        const transport = new StdioServerTransport();
        await server.connect(transport);
        console.error(`[System] openclaw-syncralis v${pkg.version} running. Workspace: ${WORKSPACE_DIR}`);
    } catch (error) {
        console.error(`[Fatal] Startup failed: ${error.message}\n${error.stack}`);
        process.exit(1);
    }
}

main();
