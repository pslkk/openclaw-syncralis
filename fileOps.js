import fsPromises from 'fs/promises';
import fs from 'fs';
import path from 'path';
import mime from 'mime-types';
import { pipeline } from 'stream/promises';
import os from 'os';
import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKER_PATH = path.join(__dirname, 'parserWorker.js');

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;

function assertNonEmptyString(value, name) {
    if (typeof value !== 'string' || value.trim() === '') {
        throw new TypeError(
            `${name} must be a non-empty string (received ${JSON.stringify(value)}).`
        );
    }
}

const ALLOWED_WRITE_EXTENSIONS = new Set([
    '.txt', '.md', '.rtf', '.odt', '.ods',
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.xlsm', '.pptx', '.ppt',
    '.csv', '.tsv', '.json', '.jsonl', '.xml', '.yaml', '.yml',
    '.html', '.htm',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.tiff',
    '.mp4', '.mp3', '.wav', '.ogg', '.flac', '.aac',
    '.zip', '.tar', '.gz', '.bz2', '.7z',
    '.log', '.epub', '.mobi'
]);

export function checkExtensionAllowlist(filename) {
    assertNonEmptyString(filename, 'filename');
    const ext = path.extname(filename).toLowerCase();
    if (!ext) {
        throw new Error(
            `SECURITY ALERT: Files without an extension are not permitted in the workspace.`
        );
    }
    if (!ALLOWED_WRITE_EXTENSIONS.has(ext)) {
        throw new Error(
            `SECURITY ALERT: Extension "${ext}" is not permitted. ` +
            `Blocked to prevent executable or system-configuration file writes.`
        );
    }
}

export const getWorkspaceDir = (overrideDir) => {
    if (overrideDir) {
        assertNonEmptyString(overrideDir, 'overrideDir');
        return overrideDir;
    }
    return path.join(os.homedir(), '.openclaw', 'workspace');
};

export const ensureWorkspaceExists = async (workspaceDir) => {
    assertNonEmptyString(workspaceDir, 'workspaceDir');
    await fsPromises.mkdir(workspaceDir, { recursive: true });
};

export const getSecurePath = async (workspaceDir, requestedPath) => {
    assertNonEmptyString(workspaceDir, 'workspaceDir');
    assertNonEmptyString(requestedPath, 'requestedPath');
    if (path.isAbsolute(requestedPath)) {
        throw new Error('SECURITY ALERT: Absolute paths are not permitted.');
    }
    if (/[\x00-\x1f\x7f]/.test(requestedPath)) {
        throw new Error('SECURITY ALERT: Path contains invalid control characters.');
    }
    const realWorkspaceDir = await fsPromises.realpath(workspaceDir);
    const resolvedPath = path.resolve(realWorkspaceDir, requestedPath);
   
    const relativePath = path.relative(realWorkspaceDir, resolvedPath);
    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
        throw new Error(`SECURITY ALERT: Path traversal attempt blocked.`);
    }

    const safeRoot = realWorkspaceDir.endsWith(path.sep)
        ? realWorkspaceDir
        : realWorkspaceDir + path.sep;

    try {
        const realTarget = await fsPromises.realpath(resolvedPath);
        if (realTarget !== realWorkspaceDir && !realTarget.startsWith(safeRoot)) {
            throw new Error(`SECURITY ALERT: Symlink traversal blocked — path resolves outside workspace.`);
        }
        return realTarget;
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
        try {
            const realParent = await fsPromises.realpath(path.dirname(resolvedPath));
            if (realParent !== realWorkspaceDir && !realParent.startsWith(safeRoot)) {
                throw new Error(`SECURITY ALERT: Symlink traversal blocked — parent dir resolves outside workspace.`);
            }
        } catch (parentErr) {
            if (parentErr.code !== 'ENOENT') throw parentErr;
        }
        return resolvedPath;
    }
};

export const statSafeFile = async (securePath) => {
    assertNonEmptyString(securePath, 'securePath');
    const lstats = await fsPromises.lstat(securePath);
    if (lstats.isSymbolicLink()) {
        throw new Error('SECURITY ALERT: Symlink access denied.');
    }
    if (!lstats.isFile()) {
        throw new Error('Requested path is not a regular file.');
    }
    if (lstats.size > MAX_FILE_SIZE_BYTES) {
        throw new Error(
            `File size (${(lstats.size / 1_048_576).toFixed(1)} MB) exceeds the ` +
            `${MAX_FILE_SIZE_BYTES / 1_048_576} MB maximum.`
        );
    }
    const mimeType = mime.lookup(securePath) || 'application/octet-stream';
    return { size: lstats.size, mtime: lstats.mtime, mimeType };
};

export const readSafeFile = async (securePath) => {
    assertNonEmptyString(securePath, 'securePath');
    const lstats = await fsPromises.lstat(securePath);
    if (lstats.isSymbolicLink()) {
        throw new Error(`SECURITY ALERT: Symlink access denied.`);
    }
    if (!lstats.isFile()) throw new Error(`Requested path is a directory.`);
    if (lstats.size > MAX_FILE_SIZE_BYTES) throw new Error(`File exceeds max allowed size.`);

    const buffer = await fsPromises.readFile(securePath);
    const mimeType = mime.lookup(securePath) || 'application/octet-stream';
    
    return { buffer, mimeType, size: lstats.size };
};

export const streamSafeFile = async (securePath, writableStream) => {
    assertNonEmptyString(securePath, 'securePath');
    if (!writableStream || typeof writableStream.write !== 'function') {
        throw new TypeError('writableStream must be a Writable stream.');
    }

    const lstats = await fsPromises.lstat(securePath);

    if (lstats.isSymbolicLink()) {
        throw new Error('SECURITY ALERT: Symlink access denied.');
    }
    if (!lstats.isFile()) {
        throw new Error('Requested path is not a regular file.');
    }
    if (lstats.size > MAX_FILE_SIZE_BYTES) {
        throw new Error(
            `File size (${(lstats.size / 1_048_576).toFixed(1)} MB) exceeds the ` +
            `${MAX_FILE_SIZE_BYTES / 1_048_576} MB maximum.`
        );
    }

    const readStream = fs.createReadStream(securePath);
    return pipeline(readStream, writableStream);
};

export const createSafeWriteStream = (targetPath) => {
    assertNonEmptyString(targetPath, 'targetPath');
    return fs.createWriteStream(targetPath, { flags: 'wx', mode: 0o644 });
};

export const deleteSafeFile = async (targetPath) => {
    assertNonEmptyString(targetPath, 'targetPath');
    try {
        await fsPromises.unlink(targetPath);
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
    }
};

export const checkNoClobber = async (securePath, safeFileName) => {
    assertNonEmptyString(securePath, 'securePath');
    assertNonEmptyString(safeFileName, 'safeFileName');
    checkExtensionAllowlist(safeFileName);
    try {
        await fsPromises.lstat(securePath);
        throw new Error(`File "${safeFileName}" already exists. Overwrite strictly blocked.`);
    } catch (err) {
        if (err.code !== 'ENOENT') throw err; 
    }
};

export const commitDownload = async (tmpPath, finalPath) => {
    assertNonEmptyString(tmpPath, 'tmpPath');
    assertNonEmptyString(finalPath, 'finalPath');
    await fsPromises.rename(tmpPath, finalPath);
    await fsPromises.chmod(finalPath, 0o644);
};

export function runParserWorker(jobData) {
    return new Promise((resolve, reject) => {
        const worker = new Worker(WORKER_PATH);
        worker.on('message', (result) => {
            if (result.success) {
                resolve(result.text);
            } else {
                reject(new Error(result.error));
            }
            worker.terminate();
        });
        worker.on('error', (err) => {
            reject(err);
            worker.terminate();
        });
        worker.on('exit', (code) => {
            if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
        });
        worker.postMessage(jobData);
    });
}
