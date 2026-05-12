import dns from 'dns/promises';
import net from 'net';
import http from 'http';
import https from 'https';

const BLOCKED_IP_RANGES = [
    /^127\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^169\.254\./,
    /^0\./,
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
    /^192\.0\.2\./,
    /^198\.51\.100\./,
    /^203\.0\.113\./,
    /^192\.88\.99\./,
    /^198\.(18|19)\./,
    /^224\./,
    /^233\.252\./,
    /^240\./,
    /^255\.255\.255\.255$/,
    /^::1$/,                                 // Loopback
    /^::$/,                                  // Unspecified
    /^fc00:/i,                               // Unique local (RFC 4193)
    /^fd[0-9a-f]{2}:/i,                      // Unique local (fd prefix)
    /^fe80:/i,                               // Link-local
    /^ff[0-9a-f]{2}:/i,                      // Multicast
    /^64:ff9b:/,                             // IPv4-mapped (RFC 6052)
    /^2002:/,                                // 6to4
];

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const BLOCKED_HEADER_NAMES = new Set([
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
    'x-forwarded-for',
    'x-real-ip',
    'proxy-authorization',
    'x-amz-security-token',
    'x-amz-session-token',
    'x-goog-api-key',
    'x-azure-token',
]);

const MAX_REDIRECTS        = 3;
const MAX_RESPONSE_BYTES   = 50 * 1024 * 1024;
const REQUEST_TIMEOUT_MS   = 10000;
const RATE_LIMIT_MAX       = 10;
const RATE_LIMIT_WINDOW_MS = 60000;

export function auditLog(event, details = {}) {
    const entry = {
        timestamp: new Date().toISOString(),
        service:   'openclaw-syncralis',
        event,
        ...details,
    };
    console.error(JSON.stringify(entry));
}

const _buckets = new Map();
export function checkRateLimit(toolName) {
    const bucket = Math.floor(Date.now() / RATE_LIMIT_WINDOW_MS);
    const key    = `${toolName}:${bucket}`;

    for (const k of _buckets.keys()) {
        if (k !== key) _buckets.delete(k);
    }

    const count = (_buckets.get(key) ?? 0) + 1;
    _buckets.set(key, count);

    if (count > RATE_LIMIT_MAX) {
        auditLog('RATE_LIMIT_EXCEEDED', { toolName, count, limit: RATE_LIMIT_MAX });
        throw new Error(
            `Rate limit exceeded for "${toolName}". ` +
            `Max ${RATE_LIMIT_MAX} calls per minute.`
        );
    }
}

export function isPrivateIP(ip) {
    return BLOCKED_IP_RANGES.some(r => r.test(ip));
}
export async function validateAndResolve(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new Error(`Malformed URL: "${rawUrl}"`);
    }

    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
        throw new Error(
            `Blocked protocol "${parsed.protocol}". ` +
            `Only http and https are permitted.`
        );
    }
  
    const blockedPorts = new Set([0, 22, 23, 25, 110, 143, 3306, 5432, 6379, 27017]);
    const port = parseInt(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'), 10);
    if (blockedPorts.has(port)) {
        throw new Error(`Blocked: port ${port} is not permitted.`);
    }

    const hostname = parsed.hostname;

    if (/^localhost$/i.test(hostname)) {
        throw new Error('Blocked: "localhost" is not permitted.');
    }

    if (net.isIP(hostname)) {
        if (isPrivateIP(hostname)) {
            auditLog('SSRF_BLOCKED', { reason: 'direct_private_ip', ip: hostname, url: rawUrl });
            throw new Error(
                `Blocked: direct connection to private/reserved IP "${hostname}" is not permitted.`
            );
        }
        return { hostname, pinnedIP: hostname, parsed };
    }

    let addresses;
    try {
        addresses = await dns.lookup(hostname, { all: true });
    } catch (err) {
        throw new Error(`DNS resolution failed for "${hostname}": ${err.message}`);
    }

    if (!addresses?.length) {
        throw new Error(`No addresses resolved for hostname "${hostname}".`);
    }

    for (const { address } of addresses) {
        if (!net.isIP(address)) {
            throw new Error(`DNS returned invalid IP "${address}" for "${hostname}".`);
        }
        if (isPrivateIP(address)) {
            auditLog('SSRF_BLOCKED', {
                reason: 'dns_resolves_to_private',
                hostname,
                resolvedIP: address,
                url: rawUrl,
            });
            throw new Error(
                `Blocked: "${hostname}" resolves to private/reserved IP "${address}".`
            );
        }
    }

    return { hostname, pinnedIP: addresses[0].address, parsed };
}

export function sanitizeHeaders(headers = {}) {
    if (typeof headers !== 'object' || Array.isArray(headers)) return {};
    const safe = {};
    for (const [k, v] of Object.entries(headers)) {
        if (typeof k !== 'string' || typeof v !== 'string') continue;
        if (BLOCKED_HEADER_NAMES.has(k.toLowerCase())) continue;
        safe[k] = v;
    }
    return safe;
}

function makePinnedRequest(rawUrl, pinnedIP, hostname, extraHeaders, protocol) {
    return new Promise((resolve, reject) => {
        const parsed      = new URL(rawUrl);
        const isHttps     = protocol === 'https:';
        const port        = parsed.port || (isHttps ? 443 : 80);
        const requestMod  = isHttps ? https : http;

        const options = {
            hostname,
            port,
            path:    parsed.pathname + parsed.search,
            method:  'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                ...extraHeaders,
                'Host': hostname,
            },
            
            agent: false,
            
            lookup: (lookupHostname, lookupOptions, lookupCallback) => {
                const finalCb = typeof lookupOptions === 'function' ? lookupOptions : lookupCallback;
                const opts = typeof lookupOptions === 'object' ? lookupOptions : {};
                const family = net.isIPv6(pinnedIP) ? 6 : 4;

                if (opts.all) {
                    finalCb(null, [{ address: pinnedIP, family }]);
                } else {
                    finalCb(null, pinnedIP, family);
                }
            },
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            timeout: REQUEST_TIMEOUT_MS,
        };

        const req = requestMod.request(options, resolve);

        req.on('timeout', () => {
            req.destroy();
            reject(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`));
        });

        req.on('error', reject);
        req.end();
    });
}

export async function secureFetch(rawUrl, extraHeaders = {}, redirectCount = 0) {
    if (redirectCount > MAX_REDIRECTS) {
        throw new Error(`Too many redirects (max ${MAX_REDIRECTS}).`);
    }

    const { hostname, pinnedIP, parsed } = await validateAndResolve(rawUrl);

    auditLog('FETCH_ATTEMPT', { url: rawUrl, resolvedIP: pinnedIP, redirectCount });

    const response = await makePinnedRequest(
        rawUrl, pinnedIP, hostname, extraHeaders, parsed.protocol
    );

    if (response.statusCode >= 300 && response.statusCode < 400) {
        const location = response.headers['location'];
        if (!location) {
            response.resume();
            throw new Error('Redirect received with no Location header.');
        }

        const redirectUrl = new URL(location, rawUrl).toString();
        auditLog('REDIRECT_FOLLOW', { from: rawUrl, to: redirectUrl, hop: redirectCount + 1 });

        response.resume();

        return secureFetch(redirectUrl, extraHeaders, redirectCount + 1);
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        throw new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`);
    }

    return response;
}

export async function streamToFile(response, fileStream) {
    return new Promise((resolve, reject) => {
        let bytesReceived = 0;

        response.on('data', (chunk) => {
            bytesReceived += chunk.length;
            if (bytesReceived > MAX_RESPONSE_BYTES) {
                response.destroy();
                fileStream.destroy();
                reject(new Error(
                    `Download aborted: exceeded ` +
                    `${MAX_RESPONSE_BYTES / 1024 / 1024}MB size limit.`
                ));
            }
        });

        response.pipe(fileStream);

        fileStream.on('finish', resolve);
        fileStream.on('error', (err) => { response.destroy(); reject(err); });
        response.on('error',   (err) => { fileStream.destroy(); reject(err); });
    });
}
