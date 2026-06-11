import { cleanEnv, str, port } from 'envalid';
import crypto from 'crypto';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { parseTrustedProxies } from './safegrd.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '.env') });

const safeEnv = globalThis['process']['env'];

export const env = cleanEnv(safeEnv, {
    NODE_ENV: str({ choices: ['development', 'test', 'production'], default: 'production' }),
    FILE_SERVER_HOST: str({ default: '' }),
    FILE_SERVER_PORT: port({ default: 8080 }),
    WORKSPACE_DIR: str({ default: '' }), 
    PUBLIC_TUNNEL_URL: str({ default: '' }), 
    NGROK_API_PORT: port({ default: 4040 }),
    URL_SIGNING_SECRET: str({ default: '' }),
    TAVILY_API_KEY: str({ default: '' }),
    BRAVE_API_KEY: str({ default: '' }),
    TRUSTED_PROXY_IPS: str({ default: '' })
});

export const signingSecret = env.URL_SIGNING_SECRET || (() => {
    if (env.NODE_ENV === 'production') {
        console.error(`\n\x1b[33m[Notice]\x1b[0m URL_SIGNING_SECRET is not configured. Auto-generating a temporary secret.`);
        console.error(`\x1b[33m[Notice]\x1b[0m Be aware: If this gateway restarts, any previously generated download links will instantly expire.\n`);
    }
    return crypto.randomBytes(32).toString('hex');
})();

export const GATEWAY_CONFIG = Object.freeze({
    host: env.FILE_SERVER_HOST,
    port: env.FILE_SERVER_PORT,
    workspaceOverride: env.WORKSPACE_DIR,
    tunnelUrlFallback: env.PUBLIC_TUNNEL_URL,
    discoveryPort: env.NGROK_API_PORT,
    tavilyKey: env.TAVILY_API_KEY,
    braveKey: env.BRAVE_API_KEY,
    trustedProxyIPs: parseTrustedProxies(env.TRUSTED_PROXY_IPS),
    secret: signingSecret
});
