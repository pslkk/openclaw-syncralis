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

const MAX_DOWNLOAD_ATTEMPTS = 3;
const downloadAttemptTracker = new Map();

const CONFIRM_TOKEN_TTL_MS = 5 * 60 * 1000;
const pendingConfirmations  = new Map();

function issueConfirmationToken(filename, resolvedPath) {
    const payload = Buffer.from(
        JSON.stringify({ filename, resolvedPath, issuedAt: Date.now() })
    ).toString('base64url');

    const sig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                      .update(payload)
                      .digest('hex');
    
    const token = `${payload}.${sig}`;

    pendingConfirmations.set(token, { filename, resolvedPath, issuedAt: Date.now() });

    setTimeout(() => pendingConfirmations.delete(token), CONFIRM_TOKEN_TTL_MS + 1000);
    return token;
}

function consumeConfirmationToken(token, expectedFilename) {
    if (typeof token !== 'string' || !token.includes('.')) {
        throw new Error('Confirmation token is malformed.');
    }

    const dotIdx  = token.lastIndexOf('.');
    const payload = token.slice(0, dotIdx);
    const sig = token.slice(dotIdx + 1);
    
    const expectedSig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                              .update(payload)
                              .digest('hex');
    
    const sigBuf = Buffer.from(sig, 'hex');
    const expBuf = Buffer.from(expectedSig, 'hex');
    
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
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
            tokenFile:     data.filename,
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
          console.log(`\n\x1b[32m[System]\x1b[0m Auto-discovered active Ngrok tunnel: ${activeTunnelUrl}\n`);
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

const TIMEOUT_MS = 10000;
const MAX_QUERY_LENGTH = 2000;
let requestCount = 0;

const require = createRequire(import.meta.url);
const pdf = require("pdf-parse");
const pkg = require("./package.json");

// Check for version flags before starting the server
if (process.argv.includes('--version') || process.argv.includes('-v')) {
  console.log(`openclaw-syncralis v${pkg.version}`);
  process.exit(0);
}

const WORKSPACE_DIR = getWorkspaceDir(GATEWAY_CONFIG.workspaceOverride);

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

    downloadAttemptTracker.set(signature, { attempts: 0, filename: safeFilename });
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
                    "  'read'     — return file contents inline (no link generated).",
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
            const { filePath, action = "read", confirmationToken } = args;
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
                const pdfData = await pdf(buffer);
                return { content: [{ type: "text", text: pdfData.text }] };
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

            const isBraveTurn = requestCount % 2 === 0;
            requestCount++;

            let resultText = "";
            if (isBraveTurn) {
                try {
                    resultText = await executeSearchAttempt(query, braveKey, fetchBrave);
                } catch (err) {
                    resultText = await executeSearchAttempt(query, tavilyKey, fetchTavily);
                }
            } else {
                try {
                    resultText = await executeSearchAttempt(query, tavilyKey, fetchTavily);
                } catch (err) {
                    resultText = await executeSearchAttempt(query, braveKey, fetchBrave);
                }
            }
            return { content: [{ type: "text", text: resultText }] };

        } catch (error) {
            auditLog('SEARCH_FAILED', { error: error.message });
            return { isError: true, content: [{ type: "text", text: `Search Error: ${error.message}` }] };
        }
    }

    throw new Error(`Tool not found: ${name}`);
});

async function executeSearchAttempt(query, apiKey, fetchFn) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const result = await fetchFn(query, apiKey, controller.signal);
        clearTimeout(timeoutId);
        return result;
    } catch (error) {
        clearTimeout(timeoutId);
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

function startSecureFileServer() {
    const PORT = GATEWAY_CONFIG.port;
    const HOST = GATEWAY_CONFIG.host || '127.0.0.1';
    
    const fileServer = http.createServer(async (req, res) => {
        try {
            // Strictly enforce GET requests
            if (req.method !== 'GET') {
                res.writeHead(405);
                return res.end('Method Not Allowed');
            }

            const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
            const requestedFile = decodeURIComponent(reqUrl.pathname.slice(1));
            if (!requestedFile) {
                res.writeHead(400);
                return res.end('Bad Request');
            }

            const expires = reqUrl.searchParams.get('expires');
            const providedSig = reqUrl.searchParams.get('sig');

            if (!expires || !providedSig) {
                throw new Error("Missing cryptographic signature.");
            }

            if (Date.now() > parseInt(expires, 10)) {
                throw new Error("This secure link has expired.");
            }

            const safeFilename = path.basename(requestedFile); 
            const dataToVerify = `${safeFilename}:${expires}`;
            const expectedSig = crypto.createHmac('sha256', GATEWAY_CONFIG.secret)
                                      .update(dataToVerify)
                                      .digest('hex');

            const providedSigBuffer = Buffer.from(providedSig);
            const expectedSigBuffer = Buffer.from(expectedSig);

            if (providedSigBuffer.length !== expectedSigBuffer.length || !crypto.timingSafeEqual(providedSigBuffer, expectedSigBuffer)) {
                throw new Error("Cryptographic signature mismatch.");
            }


            const tracker = downloadAttemptTracker.get(providedSig);
            if (!tracker) {
                throw new Error("Unrecognised link — please generate a new download URL.");
            }
            if (tracker.attempts >= MAX_DOWNLOAD_ATTEMPTS) {
                auditLog('DOWNLOAD_LIMIT_EXCEEDED', { file: safeFilename, attempts: tracker.attempts });
                res.writeHead(429, { 'Content-Type': 'text/plain' });
                return res.end(`Download limit reached. This link allows a maximum of ${MAX_DOWNLOAD_ATTEMPTS} download(s).\nKindly generate a new link.`);
            }
            tracker.attempts += 1;
            auditLog('DOWNLOAD_ATTEMPT', { file: safeFilename, attempt: tracker.attempts, maxAllowed: MAX_DOWNLOAD_ATTEMPTS });
            
            const securePath = await getSecurePath(WORKSPACE_DIR, requestedFile);
            const { buffer, mimeType, size } = await readSafeFile(securePath);
            
            res.writeHead(200, {
                'Content-Type': mimeType,
                'Content-Length': size,
                'Content-Disposition': `attachment; filename="${path.basename(securePath)}"` 
            });
            res.end(buffer);

            auditLog('FILE_SERVED', { file: path.basename(securePath), size, mimeType });

        } catch (error) {
            console.error(`[File Server Security Alert] Blocked access attempt: ${error.message}`);
            res.writeHead(404);
            res.end('File not found or access securely blocked.');
        }
    });

    fileServer.listen(PORT, HOST, () => {
        console.error(`[System] Native Secure File Server bound internally to ${HOST}:${PORT}`);
    });
}

async function main() {
    try {
        await initializeTunnel();
        await ensureWorkspaceExists(WORKSPACE_DIR);
        const transport = new StdioServerTransport();
        await server.connect(transport);
        startSecureFileServer();
        console.error("[System] openclaw-syncralis MCP running securely");
    } catch (error) {
        console.error("[Fatal] Server connection failed:", error);
        process.exit(1);
    }
}

main();
