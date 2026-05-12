import fsPromises from 'fs/promises';
import fs from 'fs';
import path from 'path';
import mime from 'mime-types';
import os from 'os';

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;

export const getWorkspaceDir = (overrideDir) => {
    return overrideDir || path.join(os.homedir(), '.openclaw', 'workspace');
};

export const ensureWorkspaceExists = async (workspaceDir) => {
    await fsPromises.mkdir(workspaceDir, { recursive: true });
};

export const getSecurePath = async (workspaceDir, requestedPath) => {
    const isAbsolutePath = path.isAbsolute(requestedPath);
    const targetPath = isAbsolutePath ? requestedPath : path.join(workspaceDir, requestedPath);
    const resolvedPath = path.resolve(targetPath);
   
    const relativePath = path.relative(workspaceDir, resolvedPath);
    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
        throw new Error(`SECURITY ALERT: Path traversal attempt blocked.`);
    }
    return resolvedPath;
};

export const readSafeFile = async (securePath) => {
    const stats = await fsPromises.stat(securePath);
    if (!stats.isFile()) throw new Error(`Requested path is a directory.`);
    if (stats.size > MAX_FILE_SIZE_BYTES) throw new Error(`File exceeds max allowed size.`);

    const buffer = await fsPromises.readFile(securePath);
    const mimeType = mime.lookup(securePath) || 'application/octet-stream';
    
    return { buffer, mimeType, size: stats.size };
};

export const createSafeWriteStream = (targetPath) => {
    return fs.createWriteStream(targetPath);
};

export const deleteSafeFile = async (targetPath) => {
    await fsPromises.unlink(targetPath).catch(() => {});
};

export const checkNoClobber = async (securePath, safeFileName) => {
    try {
        await fsPromises.access(securePath);
        throw new Error(`File "${safeFileName}" already exists. Overwrite strictly blocked.`);
    } catch (err) {
        if (err.code !== 'ENOENT') throw err; 
    }
};

export const commitDownload = async (tmpPath, finalPath) => {
    await fsPromises.rename(tmpPath, finalPath);
};
