# Node.js Core Modules - Complete Mastery Guide

## 📚 Table of Contents
- [1. fs - File System](#1-fs---file-system)
- [2. path](#2-path)
- [3. events](#3-events)
- [4. http/https](#4-httphttps)
- [5. os](#5-os)
- [6. process](#6-process)
- [7. url](#7-url)
- [8. crypto](#8-crypto)
- [9. stream](#9-stream)
- [10. zlib](#10-zlib)

---

## 1. fs - File System

### In-depth Explanation

The `fs` module provides file system operations with both synchronous and asynchronous APIs. It's one of the most frequently used core modules in Node.js.

**Key Concepts:**
- **Async vs Sync**: All methods have async (callback/promise) and sync versions
- **File Descriptors**: Low-level file access
- **Streaming**: `fs.createReadStream()` and `fs.createWriteStream()`
- **Watch API**: Monitor file changes

**Modern fs/promises API:**
```javascript
import { promises as fs } from 'fs';
// OR
const fs = require('fs').promises;
```

**Common Operations:**

```javascript
const fs = require('fs');
const fsPromises = require('fs').promises;

// 1. File reading (multiple ways)
fs.readFile('/path/to/file', 'utf8', (err, data) => {
  if (err) throw err;
  console.log(data);
});

// With promises
async function readFileAsync() {
  try {
    const data = await fsPromises.readFile('/path/to/file', 'utf8');
    console.log(data);
  } catch (err) {
    console.error(err);
  }
}

// 2. File writing
fs.writeFile('/path/to/file', 'content', 'utf8', (err) => {
  if (err) throw err;
  console.log('File written');
});

// 3. File stats (metadata)
fs.stat('/path/to/file', (err, stats) => {
  if (err) throw err;
  console.log(`Is file: ${stats.isFile()}`);
  console.log(`Size: ${stats.size} bytes`);
  console.log(`Created: ${stats.birthtime}`);
  console.log(`Modified: ${stats.mtime}`);
});

// 4. Directory operations
fs.mkdir('/path/to/dir', { recursive: true }, (err) => {
  if (err) throw err;
  console.log('Directory created');
});

// 5. File watching
const watcher = fs.watch('/path/to/dir', (eventType, filename) => {
  console.log(`Event type: ${eventType}`);
  console.log(`Filename: ${filename}`);
});

// Stop watching after 10 seconds
setTimeout(() => watcher.close(), 10000);
```

**Advanced File Operations:**
```javascript
// Copy with progress using streams
async function copyFileWithProgress(src, dest) {
  return new Promise((resolve, reject) => {
    const readStream = fs.createReadStream(src);
    const writeStream = fs.createWriteStream(dest);
    
    let bytesRead = 0;
    const stats = fs.statSync(src);
    const totalBytes = stats.size;
    
    readStream.on('data', (chunk) => {
      bytesRead += chunk.length;
      const progress = (bytesRead / totalBytes * 100).toFixed(2);
      console.log(`Copy progress: ${progress}%`);
    });
    
    readStream.on('error', reject);
    writeStream.on('error', reject);
    writeStream.on('finish', resolve);
    
    readStream.pipe(writeStream);
  });
}

// Atomic file write (prevents partial writes)
async function atomicWrite(filepath, content) {
  const tmpPath = `${filepath}.${Date.now()}.tmp`;
  
  try {
    // Write to temp file first
    await fsPromises.writeFile(tmpPath, content, 'utf8');
    // Atomic rename (OS-level operation)
    await fsPromises.rename(tmpPath, filepath);
  } catch (error) {
    // Cleanup temp file on error
    try {
      await fsPromises.unlink(tmpPath);
    } catch (cleanupError) {
      // Ignore cleanup errors
    }
    throw error;
  }
}

// Recursive directory operations
async function findFiles(dir, pattern) {
  const files = [];
  
  async function scan(currentDir) {
    const entries = await fsPromises.readdir(currentDir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = require('path').join(currentDir, entry.name);
      
      if (entry.isDirectory()) {
        await scan(fullPath);
      } else if (entry.isFile() && entry.name.match(pattern)) {
        files.push(fullPath);
      }
    }
  }
  
  await scan(dir);
  return files;
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `fs.readFile()` and `fs.createReadStream()`?
2. How do you handle large files that don't fit in memory?
3. Explain the difference between `fs.writeFile()` and `fs.appendFile()`.
4. What is a file descriptor and when would you use it?

**Senior Level:**
5. How would you implement a file-based cache system with TTL (time-to-live)?
6. Explain the performance implications of synchronous vs asynchronous fs operations.
7. How would you handle concurrent file access in a multi-process environment?
8. What are the security considerations when working with user-provided file paths?

### 🌍 Real-World Scenarios

**Scenario 1: Log Rotation System**
> Implement a log rotation system that:
> 1. Writes logs to a file
> 2. Rotates when file reaches 10MB
> 3. Keeps last 5 rotated files
> 4. Compresses old logs

**Solution:**
```javascript
const fs = require('fs').promises;
const path = require('path');
const zlib = require('zlib');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);

class LogRotator {
  constructor(logDir, maxSize = 10 * 1024 * 1024, maxFiles = 5) {
    this.logDir = logDir;
    this.maxSize = maxSize;
    this.maxFiles = maxFiles;
    this.currentFile = null;
    this.currentSize = 0;
    this.writer = null;
  }
  
  async initialize() {
    await fs.mkdir(this.logDir, { recursive: true });
    
    // Find latest log file
    const files = await fs.readdir(this.logDir);
    const logFiles = files.filter(f => f.startsWith('app.log'));
    
    if (logFiles.length > 0) {
      const latest = logFiles.sort().reverse()[0];
      this.currentFile = path.join(this.logDir, latest);
      
      const stats = await fs.stat(this.currentFile);
      this.currentSize = stats.size;
      
      // Check if needs rotation
      if (this.currentSize >= this.maxSize) {
        await this.rotate();
      }
    } else {
      this.currentFile = path.join(this.logDir, 'app.log');
    }
    
    // Create write stream
    this.writer = fs.createWriteStream(this.currentFile, {
      flags: 'a', // append
      encoding: 'utf8'
    });
  }
  
  async log(message) {
    const logEntry = `${new Date().toISOString()} - ${message}\n`;
    const entrySize = Buffer.byteLength(logEntry, 'utf8');
    
    // Check if rotation needed
    if (this.currentSize + entrySize >= this.maxSize) {
      await this.rotate();
    }
    
    return new Promise((resolve, reject) => {
      this.writer.write(logEntry, (err) => {
        if (err) {
          reject(err);
        } else {
          this.currentSize += entrySize;
          resolve();
        }
      });
    });
  }
  
  async rotate() {
    if (this.writer) {
      await new Promise(resolve => this.writer.end(resolve));
    }
    
    // Rename current file
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const newName = `app.log.${timestamp}`;
    const newPath = path.join(this.logDir, newName);
    
    await fs.rename(this.currentFile, newPath);
    
    // Compress the rotated file
    await this.compressFile(newPath);
    
    // Cleanup old files
    await this.cleanupOldFiles();
    
    // Create new log file
    this.currentFile = path.join(this.logDir, 'app.log');
    this.currentSize = 0;
    this.writer = fs.createWriteStream(this.currentFile, {
      flags: 'a',
      encoding: 'utf8'
    });
  }
  
  async compressFile(filePath) {
    const content = await fs.readFile(filePath);
    const compressed = await gzip(content);
    
    await fs.writeFile(`${filePath}.gz`, compressed);
    await fs.unlink(filePath); // Remove uncompressed file
  }
  
  async cleanupOldFiles() {
    const files = await fs.readdir(this.logDir);
    const compressedFiles = files
      .filter(f => f.endsWith('.gz'))
      .sort()
      .reverse();
    
    // Remove files beyond maxFiles limit
    for (let i = this.maxFiles - 1; i < compressedFiles.length; i++) {
      const fileToRemove = path.join(this.logDir, compressedFiles[i]);
      await fs.unlink(fileToRemove);
    }
  }
}
```

**Scenario 2: Config File Management**
> Create a configuration manager that:
> 1. Loads config from file
> 2. Watches for changes
> 3. Supports environment-specific configs
> 4. Validates schema

**Solution:**
```javascript
const fs = require('fs').promises;
const EventEmitter = require('events');
const path = require('path');
const Ajv = require('ajv');

class ConfigManager extends EventEmitter {
  constructor(configDir = './config') {
    super();
    this.configDir = configDir;
    this.config = {};
    this.watchers = new Map();
    this.ajv = new Ajv();
    this.schema = {
      type: 'object',
      properties: {
        database: {
          type: 'object',
          properties: {
            host: { type: 'string' },
            port: { type: 'number' },
            username: { type: 'string' },
            password: { type: 'string' }
          },
          required: ['host', 'port']
        },
        server: {
          type: 'object',
          properties: {
            port: { type: 'number', minimum: 1, maximum: 65535 },
            timeout: { type: 'number', minimum: 0 }
          }
        }
      }
    };
  }
  
  async load(env = process.env.NODE_ENV || 'development') {
    try {
      // Load base config
      const baseConfig = await this.loadFile('config.json');
      
      // Load environment-specific config
      let envConfig = {};
      try {
        envConfig = await this.loadFile(`config.${env}.json`);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      
      // Load local overrides (gitignored)
      let localConfig = {};
      try {
        localConfig = await this.loadFile('config.local.json');
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      
      // Merge configs (local > env > base)
      this.config = this.deepMerge(baseConfig, envConfig);
      this.config = this.deepMerge(this.config, localConfig);
      
      // Validate
      this.validate(this.config);
      
      // Watch for changes
      await this.setupWatchers();
      
      this.emit('loaded', this.config);
      return this.config;
      
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }
  
  async loadFile(filename) {
    const filepath = path.join(this.configDir, filename);
    const content = await fs.readFile(filepath, 'utf8');
    
    try {
      return JSON.parse(content);
    } catch (parseError) {
      throw new Error(`Invalid JSON in ${filename}: ${parseError.message}`);
    }
  }
  
  async setupWatchers() {
    const files = ['config.json'];
    
    if (process.env.NODE_ENV) {
      files.push(`config.${process.env.NODE_ENV}.json`);
    }
    
    files.push('config.local.json');
    
    for (const file of files) {
      const filepath = path.join(this.configDir, file);
      
      try {
        await fs.access(filepath);
        
        const watcher = fs.watch(filepath, async (eventType) => {
          if (eventType === 'change') {
            console.log(`Config file changed: ${file}`);
            
            // Debounce reload
            clearTimeout(this.reloadTimeout);
            this.reloadTimeout = setTimeout(async () => {
              try {
                await this.load(process.env.NODE_ENV);
                this.emit('reloaded', this.config);
              } catch (error) {
                this.emit('reloadError', error);
              }
            }, 1000);
          }
        });
        
        this.watchers.set(file, watcher);
        
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    }
  }
  
  validate(config) {
    const validate = this.ajv.compile(this.schema);
    const valid = validate(config);
    
    if (!valid) {
      const errors = validate.errors.map(err => 
        `${err.instancePath} ${err.message}`
      ).join(', ');
      
      throw new Error(`Config validation failed: ${errors}`);
    }
  }
  
  deepMerge(target, source) {
    const output = Object.assign({}, target);
    
    if (this.isObject(target) && this.isObject(source)) {
      Object.keys(source).forEach(key => {
        if (this.isObject(source[key])) {
          if (!(key in target)) {
            Object.assign(output, { [key]: source[key] });
          } else {
            output[key] = this.deepMerge(target[key], source[key]);
          }
        } else {
          Object.assign(output, { [key]: source[key] });
        }
      });
    }
    
    return output;
  }
  
  isObject(item) {
    return item && typeof item === 'object' && !Array.isArray(item);
  }
  
  get(key, defaultValue = null) {
    return key.split('.').reduce((obj, part) => 
      obj && obj[part] !== undefined ? obj[part] : defaultValue
    , this.config);
  }
  
  async stop() {
    for (const [file, watcher] of this.watchers) {
      watcher.close();
    }
    this.watchers.clear();
  }
}
```

---

## 2. path

### In-depth Explanation

The `path` module provides utilities for working with file and directory paths. It handles cross-platform differences in path separators and normalization.

**Key Methods:**
- **path.join()**: Join path segments (platform-aware)
- **path.resolve()**: Resolve absolute path
- **path.relative()**: Get relative path between two paths
- **path.parse()**: Parse path into components
- **path.format()**: Format object into path string

**Platform Differences:**
```javascript
const path = require('path');

// Windows vs Unix paths
console.log(path.sep); // '\' on Windows, '/' on Unix
console.log(path.delimiter); // ';' on Windows, ':' on Unix

// Normalization examples
console.log(path.normalize('/foo/bar//baz/asdf/quux/..'));
// Output: /foo/bar/baz/asdf

// Joining paths
console.log(path.join('/foo', 'bar', 'baz/asdf', 'quux', '..'));
// Output: /foo/bar/baz/asdf

// Resolving paths
console.log(path.resolve('/foo/bar', './baz'));
// Output: /foo/bar/baz
console.log(path.resolve('/foo/bar', '/tmp/file/'));
// Output: /tmp/file
console.log(path.resolve('wwwroot', 'static_files/png/', '../gif/image.gif'));
// Output: /current/working/dir/wwwroot/static_files/gif/image.gif

// Parsing paths
const parsed = path.parse('/home/user/dir/file.txt');
console.log(parsed);
// {
//   root: '/',
//   dir: '/home/user/dir',
//   base: 'file.txt',
//   ext: '.txt',
//   name: 'file'
// }

// Formatting from object
const formatted = path.format({
  dir: '/home/user/dir',
  base: 'file.txt'
});
console.log(formatted); // /home/user/dir/file.txt

// Relative paths
console.log(path.relative('/data/orandea/test/aaa', '/data/orandea/impl/bbb'));
// Output: ../../impl/bbb

// Working with extensions
console.log(path.extname('index.html')); // .html
console.log(path.basename('/foo/bar/baz/asdf/quux.html', '.html')); // quux
console.log(path.basename('/foo/bar/baz/asdf/quux.html')); // quux.html
```

**Advanced Path Operations:**
```javascript
// Safe path resolution (prevent directory traversal)
function safeResolve(baseDir, userPath) {
  const normalizedPath = path.normalize(userPath);
  const resolvedPath = path.resolve(baseDir, normalizedPath);
  
  // Ensure resolved path is within base directory
  if (!resolvedPath.startsWith(path.resolve(baseDir))) {
    throw new Error('Path traversal attempt detected');
  }
  
  return resolvedPath;
}

// Platform-aware path handling
class PlatformAwarePath {
  static normalizeForPlatform(pathString, targetPlatform = process.platform) {
    if (targetPlatform === 'win32') {
      // Convert to Windows path
      return pathString.replace(/\//g, '\\');
    } else {
      // Convert to Unix path
      return pathString.replace(/\\/g, '/');
    }
  }
  
  static isAbsolute(pathString) {
    // Check if path is absolute for current platform
    return path.isAbsolute(pathString);
  }
  
  static splitPath(pathString) {
    // Split path into components
    const parts = [];
    let current = pathString;
    
    while (current && current !== path.dirname(current)) {
      parts.unshift(path.basename(current));
      current = path.dirname(current);
    }
    
    if (current) {
      parts.unshift(current);
    }
    
    return parts;
  }
}

// Path pattern matching (glob-like)
function matchPath(pattern, filePath) {
  const patternParts = pattern.split(path.sep);
  const pathParts = filePath.split(path.sep);
  
  if (patternParts.length !== pathParts.length) {
    return false;
  }
  
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i] === '*') {
      continue; // Matches any single component
    }
    
    if (patternParts[i].startsWith('**')) {
      // Handle double star pattern
      return true;
    }
    
    if (patternParts[i] !== pathParts[i]) {
      return false;
    }
  }
  
  return true;
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `path.join()` and `path.resolve()`?
2. Why should you use `path.join()` instead of string concatenation?
3. How does `path.normalize()` help prevent path traversal attacks?
4. What does `path.relative()` return and when is it useful?

**Senior Level:**
5. How would you implement a cross-platform path resolution that prevents directory traversal?
6. Explain how you would handle Windows UNC paths vs Unix paths.
7. What are the performance considerations when working with path operations in high-frequency code?
8. How would you implement pattern matching for file paths (like glob patterns)?

### 🌍 Real-World Scenarios

**Scenario 1: Multi-platform Build System**
> Create a build system that works on Windows, Linux, and macOS, handling path differences correctly.

**Solution:**
```javascript
const path = require('path');
const fs = require('fs').promises;

class CrossPlatformBuilder {
  constructor(baseDir) {
    this.baseDir = path.resolve(baseDir);
    this.pathCache = new Map();
  }
  
  // Convert path to platform-specific format
  toPlatformPath(inputPath, targetPlatform = process.platform) {
    const cacheKey = `${inputPath}|${targetPlatform}`;
    
    if (this.pathCache.has(cacheKey)) {
      return this.pathCache.get(cacheKey);
    }
    
    let normalized = path.normalize(inputPath);
    
    if (targetPlatform === 'win32') {
      // Handle Windows paths
      if (normalized.startsWith('/')) {
        // Unix-style absolute path
        normalized = `C:${normalized}`;
      }
      normalized = normalized.replace(/\//g, '\\');
      
      // Handle UNC paths
      if (normalized.startsWith('\\\\')) {
        // Already UNC path
      } else if (normalized.includes(':')) {
        // Drive letter path
      }
    } else {
      // Unix-like platforms
      normalized = normalized.replace(/\\/g, '/');
      
      // Remove Windows drive letter if present
      if (/^[A-Za-z]:/.test(normalized)) {
        normalized = normalized.slice(2);
      }
    }
    
    this.pathCache.set(cacheKey, normalized);
    return normalized;
  }
  
  // Resolve path relative to base directory
  resolve(relativePath) {
    const resolved = path.resolve(this.baseDir, relativePath);
    
    // Security check: ensure path is within base directory
    if (!resolved.startsWith(this.baseDir)) {
      throw new Error(`Path traversal attempt: ${relativePath}`);
    }
    
    return resolved;
  }
  
  // Create directory structure
  async createDirStructure(structure) {
    for (const [dirPath, contents] of Object.entries(structure)) {
      const fullPath = this.resolve(dirPath);
      const platformPath = this.toPlatformPath(fullPath);
      
      await fs.mkdir(path.dirname(platformPath), { recursive: true });
      
      if (typeof contents === 'string') {
        // File with content
        await fs.writeFile(platformPath, contents, 'utf8');
      } else if (Array.isArray(contents)) {
        // Directory with files
        await fs.mkdir(platformPath, { recursive: true });
        
        for (const file of contents) {
          const filePath = path.join(platformPath, file.name);
          await fs.writeFile(filePath, file.content || '', 'utf8');
        }
      }
    }
  }
  
  // Find files by pattern
  async findFiles(pattern) {
    const results = [];
    const patternParts = pattern.split(/[\\/]/);
    
    await this._traverse(this.baseDir, patternParts, 0, results);
    
    return results.map(p => this.toPlatformPath(p));
  }
  
  async _traverse(currentDir, patternParts, depth, results) {
    try {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        
        if (entry.isDirectory()) {
          await this._traverse(fullPath, patternParts, depth + 1, results);
        } else if (entry.isFile()) {
          if (this._matchesPattern(entry.name, patternParts[depth])) {
            results.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Skip directories we can't read
      if (error.code !== 'EACCES') {
        throw error;
      }
    }
  }
  
  _matchesPattern(filename, pattern) {
    if (pattern === '*') return true;
    if (pattern === '**') return true;
    
    // Simple glob pattern matching
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(filename);
  }
}
```

**Scenario 2: Virtual File System**
> Implement a virtual file system that overlays paths for testing or sandboxing.

**Solution:**
```javascript
const path = require('path');
const EventEmitter = require('events');

class VirtualFileSystem extends EventEmitter {
  constructor() {
    super();
    this.files = new Map();
    this.directories = new Set(['/']);
    this.mountPoints = new Map();
  }
  
  // Mount a real directory to virtual path
  mount(virtualPath, realPath) {
    const normalizedVirtual = path.normalize(virtualPath);
    const normalizedReal = path.resolve(realPath);
    
    this.mountPoints.set(normalizedVirtual, normalizedReal);
    
    // Create virtual directory structure
    this._ensureDirectory(normalizedVirtual);
    
    this.emit('mount', { virtual: normalizedVirtual, real: normalizedReal });
  }
  
  // Create virtual file
  createFile(filepath, content = '', options = {}) {
    const normalizedPath = path.normalize(filepath);
    const dirname = path.dirname(normalizedPath);
    
    this._ensureDirectory(dirname);
    
    const file = {
      content: typeof content === 'string' ? content : JSON.stringify(content),
      stats: {
        isFile: () => true,
        isDirectory: () => false,
        size: Buffer.byteLength(content, 'utf8'),
        birthtime: new Date(),
        mtime: new Date(),
        ctime: new Date(),
        atime: new Date()
      },
      ...options
    };
    
    this.files.set(normalizedPath, file);
    this.emit('create', normalizedPath);
    
    return file;
  }
  
  // Read virtual file
  readFile(filepath, encoding = 'utf8') {
    const normalizedPath = path.normalize(filepath);
    
    // Check mount points first
    const mountedPath = this._resolveMountedPath(normalizedPath);
    if (mountedPath) {
      const fs = require('fs').promises;
      return fs.readFile(mountedPath, encoding);
    }
    
    // Check virtual files
    const file = this.files.get(normalizedPath);
    if (!file) {
      throw new Error(`File not found: ${filepath}`);
    }
    
    file.stats.atime = new Date();
    
    if (encoding === 'utf8' || encoding === 'utf-8') {
      return Promise.resolve(file.content);
    } else if (encoding === 'buffer' || !encoding) {
      return Promise.resolve(Buffer.from(file.content, 'utf8'));
    } else {
      throw new Error(`Unsupported encoding: ${encoding}`);
    }
  }
  
  // List directory contents
  async readdir(dirpath) {
    const normalizedPath = path.normalize(dirpath);
    
    if (!this.directories.has(normalizedPath)) {
      throw new Error(`Directory not found: ${dirpath}`);
    }
    
    const entries = [];
    
    // Add subdirectories
    for (const dir of this.directories) {
      if (dir !== normalizedPath && dir.startsWith(normalizedPath + path.sep)) {
        const nextSep = dir.indexOf(path.sep, normalizedPath.length + 1);
        if (nextSep === -1) {
          // Immediate child directory
          entries.push({
            name: path.basename(dir),
            isDirectory: () => true,
            isFile: () => false
          });
        }
      }
    }
    
    // Add files
    for (const [filepath, file] of this.files) {
      if (path.dirname(filepath) === normalizedPath) {
        entries.push({
          name: path.basename(filepath),
          isDirectory: () => false,
          isFile: () => true,
          size: file.stats.size
        });
      }
    }
    
    // Add mounted directory contents
    for (const [mountPoint, realPath] of this.mountPoints) {
      if (normalizedPath.startsWith(mountPoint)) {
        const relativePath = path.relative(mountPoint, normalizedPath);
        const realFullPath = path.join(realPath, relativePath);
        
        try {
          const fs = require('fs').promises;
          const realEntries = await fs.readdir(realFullPath, { withFileTypes: true });
          
          for (const entry of realEntries) {
            entries.push({
              name: entry.name,
              isDirectory: () => entry.isDirectory(),
              isFile: () => entry.isFile(),
              isMounted: true
            });
          }
        } catch (error) {
          // Skip if real directory doesn't exist
          if (error.code !== 'ENOENT') throw error;
        }
      }
    }
    
    return entries;
  }
  
  // Resolve path (virtual + real)
  resolve(...paths) {
    const joined = path.join(...paths);
    const normalized = path.normalize(joined);
    
    // Check if path is within a mount point
    const mounted = this._resolveMountedPath(normalized);
    if (mounted) {
      return mounted;
    }
    
    return normalized;
  }
  
  _ensureDirectory(dirpath) {
    let current = dirpath;
    
    while (current && current !== path.dirname(current)) {
      this.directories.add(current);
      current = path.dirname(current);
    }
    
    this.directories.add('/');
  }
  
  _resolveMountedPath(virtualPath) {
    for (const [mountPoint, realPath] of this.mountPoints) {
      if (virtualPath.startsWith(mountPoint)) {
        const relative = path.relative(mountPoint, virtualPath);
        return path.join(realPath, relative);
      }
    }
    
    return null;
  }
}
```

---

## 3. events

### In-depth Explanation

The `events` module provides the EventEmitter class, which is fundamental to Node.js's event-driven architecture. Many core modules inherit from EventEmitter.

**Key Concepts:**
- **Event Emitters**: Objects that emit named events
- **Event Listeners**: Functions that respond to events
- **Once vs On**: `once()` for one-time listeners
- **Error Events**: Special handling for 'error' events

**Basic Usage:**
```javascript
const EventEmitter = require('events');

class MyEmitter extends EventEmitter {}

const myEmitter = new MyEmitter();

// Add listener
myEmitter.on('event', (arg1, arg2) => {
  console.log('Event fired with:', arg1, arg2);
});

// Emit event
myEmitter.emit('event', 'arg1', 'arg2');

// Once listener
myEmitter.once('once-event', () => {
  console.log('This will only fire once');
});

// Error handling
myEmitter.on('error', (err) => {
  console.error('Error occurred:', err.message);
});

// Emit error
myEmitter.emit('error', new Error('Something went wrong'));
```

**Advanced Event Patterns:**
```javascript
const EventEmitter = require('events');

// 1. Async event listeners
class AsyncEmitter extends EventEmitter {
  async emitAsync(event, ...args) {
    const listeners = this.listeners(event);
    
    if (listeners.length === 0) {
      return [];
    }
    
    const results = [];
    for (const listener of listeners) {
      try {
        const result = await listener(...args);
        results.push({ success: true, result });
      } catch (error) {
        results.push({ success: false, error });
      }
    }
    
    return results;
  }
}

// 2. Event batching (debounce/throttle)
class BatchedEmitter extends EventEmitter {
  constructor() {
    super();
    this.batchTimers = new Map();
    this.batchData = new Map();
    this.batchTimeout = 100; // ms
  }
  
  emitBatched(event, data) {
    if (!this.batchData.has(event)) {
      this.batchData.set(event, []);
    }
    
    this.batchData.get(event).push(data);
    
    if (!this.batchTimers.has(event)) {
      this.batchTimers.set(event, setTimeout(() => {
        const batch = this.batchData.get(event);
        super.emit(event, batch);
        
        this.batchData.delete(event);
        this.batchTimers.delete(event);
      }, this.batchTimeout));
    }
  }
}

// 3. Event filtering
class FilteredEmitter extends EventEmitter {
  constructor() {
    super();
    this.filters = new Map();
  }
  
  addFilter(event, filterFn) {
    if (!this.filters.has(event)) {
      this.filters.set(event, []);
    }
    this.filters.get(event).push(filterFn);
  }
  
  emit(event, ...args) {
    const filters = this.filters.get(event) || [];
    
    for (const filter of filters) {
      try {
        if (filter(...args) === false) {
          // Filter rejected the event
          return false;
        }
      } catch (error) {
        this.emit('filterError', error, event, args);
      }
    }
    
    return super.emit(event, ...args);
  }
}

// 4. Event correlation (request/response pattern)
class RequestEmitter extends EventEmitter {
  constructor() {
    super();
    this.pendingRequests = new Map();
    this.requestId = 0;
  }
  
  request(event, data, timeout = 5000) {
    return new Promise((resolve, reject) => {
      const requestId = ++this.requestId;
      const responseEvent = `${event}:response:${requestId}`;
      
      // Setup response listener
      this.once(responseEvent, (response) => {
        this.pendingRequests.delete(requestId);
        resolve(response);
      });
      
      // Setup timeout
      const timeoutId = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        this.removeAllListeners(responseEvent);
        reject(new Error(`Request timeout for ${event}`));
      }, timeout);
      
      // Store pending request
      this.pendingRequests.set(requestId, { timeoutId, event: responseEvent });
      
      // Emit request
      this.emit(event, { requestId, data });
    });
  }
  
  respond(requestId, response) {
    const pending = this.pendingRequests.get(requestId);
    if (pending) {
      clearTimeout(pending.timeoutId);
      this.emit(pending.event, response);
    }
  }
}
```

**Memory Management & Performance:**
```javascript
// Memory leak prevention
class SafeEmitter extends EventEmitter {
  constructor(maxListeners = 10) {
    super();
    this.setMaxListeners(maxListeners);
    this.listenerCounts = new Map();
  }
  
  on(event, listener) {
    this._trackListener(event);
    return super.on(event, listener);
  }
  
  once(event, listener) {
    this._trackListener(event);
    return super.once(event, listener);
  }
  
  removeListener(event, listener) {
    const removed = super.removeListener(event, listener);
    if (removed) {
      this._untrackListener(event);
    }
    return removed;
  }
  
  removeAllListeners(event) {
    if (event) {
      this.listenerCounts.delete(event);
    } else {
      this.listenerCounts.clear();
    }
    return super.removeAllListeners(event);
  }
  
  _trackListener(event) {
    const count = this.listenerCounts.get(event) || 0;
    this.listenerCounts.set(event, count + 1);
    
    // Warn if too many listeners
    if (count + 1 > this.getMaxListeners()) {
      console.warn(`Possible memory leak: ${event} has ${count + 1} listeners`);
    }
  }
  
  _untrackListener(event) {
    const count = this.listenerCounts.get(event) || 1;
    this.listenerCounts.set(event, count - 1);
  }
}

// Event profiling
class ProfiledEmitter extends EventEmitter {
  constructor() {
    super();
    this.metrics = {
      eventsEmitted: new Map(),
      listenerExecutionTime: new Map(),
      errors: []
    };
  }
  
  emit(event, ...args) {
    // Track event count
    const count = this.metrics.eventsEmitted.get(event) || 0;
    this.metrics.eventsEmitted.set(event, count + 1);
    
    // Profile listener execution
    const listeners = this.listeners(event);
    const startTime = process.hrtime.bigint();
    
    try {
      const result = super.emit(event, ...args);
      
      const endTime = process.hrtime.bigint();
      const executionTime = Number(endTime - startTime) / 1_000_000; // ms
      
      // Track execution time
      const totalTime = this.metrics.listenerExecutionTime.get(event) || 0;
      this.metrics.listenerExecutionTime.set(event, totalTime + executionTime);
      
      return result;
    } catch (error) {
      this.metrics.errors.push({
        event,
        error,
        timestamp: new Date()
      });
      throw error;
    }
  }
  
  getMetrics() {
    return {
      eventsEmitted: Object.fromEntries(this.metrics.eventsEmitted),
      averageExecutionTime: Object.fromEntries(
        Array.from(this.metrics.listenerExecutionTime.entries()).map(([event, time]) => [
          event,
          time / (this.metrics.eventsEmitted.get(event) || 1)
        ])
      ),
      errors: this.metrics.errors.length
    };
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `on()` and `once()` methods?
2. How do you handle errors in EventEmitter?
3. What is the "max listeners" warning and how do you fix it?
4. How would you implement an event-driven state machine?

**Senior Level:**
5. How would you implement event batching/debouncing in an EventEmitter?
6. Explain the memory leak risks with EventEmitter and how to prevent them.
7. How would you implement request/response pattern using events?
8. What are the performance implications of having many event listeners?

### 🌍 Real-World Scenarios

**Scenario 1: Real-time Stock Ticker**
> Implement a stock ticker that:
> 1. Receives price updates from multiple sources
> 2. Aggregates and filters updates
> 3. Broadcasts to connected clients
> 4. Throttles high-frequency updates

**Solution:**
```javascript
const EventEmitter = require('events');

class StockTicker extends EventEmitter {
  constructor() {
    super();
    this.stocks = new Map(); // symbol -> {price, volume, timestamp}
    this.subscriptions = new Map(); // clientId -> Set(symbols)
    this.updateQueue = new Map(); // symbol -> [updates]
    this.batchTimers = new Map();
    this.batchInterval = 100; // ms
    
    // Internal event bus for processing
    this.internalEmitter = new EventEmitter();
    this.setupProcessingPipeline();
  }
  
  // Subscribe to stock symbols
  subscribe(clientId, symbols) {
    if (!this.subscriptions.has(clientId)) {
      this.subscriptions.set(clientId, new Set());
    }
    
    const clientSubs = this.subscriptions.get(clientId);
    symbols.forEach(symbol => clientSubs.add(symbol));
    
    // Send current state for subscribed symbols
    const currentState = {};
    symbols.forEach(symbol => {
      if (this.stocks.has(symbol)) {
        currentState[symbol] = this.stocks.get(symbol);
      }
    });
    
    this.emitToClient(clientId, 'initialState', currentState);
  }
  
  // Unsubscribe from symbols
  unsubscribe(clientId, symbols) {
    const clientSubs = this.subscriptions.get(clientId);
    if (clientSubs) {
      symbols.forEach(symbol => clientSubs.delete(symbol));
    }
  }
  
  // Receive price update from data source
  updatePrice(symbol, price, volume, source) {
    const update = {
      symbol,
      price,
      volume,
      source,
      timestamp: Date.now()
    };
    
    // Queue update for batching
    if (!this.updateQueue.has(symbol)) {
      this.updateQueue.set(symbol, []);
    }
    this.updateQueue.get(symbol).push(update);
    
    // Start batch timer if not already running
    if (!this.batchTimers.has(symbol)) {
      this.batchTimers.set(symbol, setTimeout(() => {
        this.processBatch(symbol);
      }, this.batchInterval));
    }
  }
  
  // Process batched updates for a symbol
  processBatch(symbol) {
    const updates = this.updateQueue.get(symbol) || [];
    if (updates.length === 0) {
      this.batchTimers.delete(symbol);
      return;
    }
    
    // Clear queue
    this.updateQueue.delete(symbol);
    this.batchTimers.delete(symbol);
    
    // Process updates through pipeline
    this.internalEmitter.emit('processBatch', symbol, updates);
  }
  
  setupProcessingPipeline() {
    // Step 1: Validate updates
    this.internalEmitter.on('processBatch', (symbol, updates) => {
      const validUpdates = updates.filter(update => 
        update.price > 0 && update.volume >= 0
      );
      
      if (validUpdates.length > 0) {
        this.internalEmitter.emit('aggregateUpdates', symbol, validUpdates);
      }
    });
    
    // Step 2: Aggregate (average price, sum volume)
    this.internalEmitter.on('aggregateUpdates', (symbol, updates) => {
      const totalVolume = updates.reduce((sum, u) => sum + u.volume, 0);
      const weightedPrice = updates.reduce((sum, u) => 
        sum + (u.price * u.volume), 0
      ) / totalVolume;
      
      const latestUpdate = updates[updates.length - 1];
      
      const aggregated = {
        symbol,
        price: weightedPrice,
        volume: totalVolume,
        timestamp: latestUpdate.timestamp,
        updateCount: updates.length
      };
      
      this.internalEmitter.emit('updateStock', aggregated);
    });
    
    // Step 3: Update stock state and notify
    this.internalEmitter.on('updateStock', (aggregated) => {
      const previous = this.stocks.get(aggregated.symbol);
      this.stocks.set(aggregated.symbol, aggregated);
      
      // Calculate price change
      const change = previous ? 
        ((aggregated.price - previous.price) / previous.price) * 100 : 0;
      
      const notification = {
        ...aggregated,
        change: parseFloat(change.toFixed(2))
      };
      
      // Broadcast to subscribed clients
      this.broadcastUpdate(aggregated.symbol, notification);
      
      // Emit public event
      this.emit('stockUpdate', notification);
    });
  }
  
  // Broadcast update to subscribed clients
  broadcastUpdate(symbol, data) {
    for (const [clientId, symbols] of this.subscriptions) {
      if (symbols.has(symbol)) {
        this.emitToClient(clientId, 'update', data);
      }
    }
  }
  
  emitToClient(clientId, event, data) {
    // In real implementation, this would send over WebSocket
    console.log(`To ${clientId}: ${event}`, data);
  }
  
  // Get current state
  getState() {
    return Object.fromEntries(this.stocks);
  }
  
  // Cleanup
  cleanup() {
    for (const timer of this.batchTimers.values()) {
      clearTimeout(timer);
    }
    this.batchTimers.clear();
    this.updateQueue.clear();
  }
}
```

**Scenario 2: Plugin System with Event Hooks**
> Build a plugin system where plugins can hook into application events and modify behavior.

**Solution:**
```javascript
const EventEmitter = require('events');
const { AsyncLocalStorage } = require('async_hooks');

class HookableEmitter extends EventEmitter {
  constructor() {
    super();
    this.hooks = new Map(); // event -> [hook functions]
    this.middleware = new Map(); // event -> [middleware functions]
    this.asyncStorage = new AsyncLocalStorage();
    this.contexts = new WeakMap();
  }
  
  // Register a hook for an event
  addHook(event, hookFn, priority = 100) {
    if (!this.hooks.has(event)) {
      this.hooks.set(event, []);
    }
    
    const hooks = this.hooks.get(event);
    hooks.push({ fn: hookFn, priority });
    
    // Sort by priority (lower number = higher priority)
    hooks.sort((a, b) => a.priority - b.priority);
  }
  
  // Register middleware for an event
  addMiddleware(event, middlewareFn) {
    if (!this.middleware.has(event)) {
      this.middleware.set(event, []);
    }
    
    this.middleware.get(event).push(middlewareFn);
  }
  
  // Enhanced emit with hooks and middleware
  async emitAsync(event, ...args) {
    const context = {
      event,
      args,
      timestamp: Date.now(),
      hookResults: new Map(),
      modifiedArgs: [...args]
    };
    
    // Store context for hooks
    this.contexts.set(this, context);
    
    try {
      // Run middleware (can modify args)
      await this.runMiddleware(event, context);
      
      // Run before hooks
      await this.runHooks('before', event, context);
      
      // Run main event listeners
      const listeners = this.listeners(event);
      const results = [];
      
      for (const listener of listeners) {
        try {
          const result = await listener(...context.modifiedArgs);
          results.push({ success: true, result });
        } catch (error) {
          results.push({ success: false, error });
          
          // Run error hooks
          await this.runHooks('error', event, { ...context, error });
        }
      }
      
      // Run after hooks
      await this.runHooks('after', event, context);
      
      return results;
      
    } finally {
      this.contexts.delete(this);
    }
  }
  
  async runMiddleware(event, context) {
    const middlewareChain = this.middleware.get(event) || [];
    
    for (const middleware of middlewareChain) {
      try {
        const newArgs = await middleware(...context.modifiedArgs);
        if (newArgs !== undefined) {
          context.modifiedArgs = Array.isArray(newArgs) ? newArgs : [newArgs];
        }
      } catch (error) {
        console.error(`Middleware error for ${event}:`, error);
        // Continue with other middleware
      }
    }
  }
  
  async runHooks(phase, event, context) {
    const hookEvent = `${phase}:${event}`;
    const hooks = this.hooks.get(hookEvent) || [];
    
    for (const hook of hooks) {
      try {
        const result = await hook.fn(context);
        context.hookResults.set(`${phase}:${event}:${hook.fn.name}`, result);
      } catch (error) {
        console.error(`Hook error for ${hookEvent}:`, error);
        // Continue with other hooks
      }
    }
  }
  
  // Create a scoped emitter with context
  createScopedEmitter(contextData = {}) {
    const scopeId = Symbol('scope');
    
    return {
      emit: async (event, ...args) => {
        return this.asyncStorage.run(
          { ...contextData, scopeId },
          () => this.emitAsync(event, ...args)
        );
      },
      
      on: (event, listener) => {
        // Store listener with scope context
        const scopedListener = async (...args) => {
          const store = this.asyncStorage.getStore();
          if (store && store.scopeId === scopeId) {
            return listener(...args);
          }
        };
        
        return this.on(event, scopedListener);
      }
    };
  }
}

// Plugin manager using hookable emitter
class PluginManager extends HookableEmitter {
  constructor() {
    super();
    this.plugins = new Map();
    this.pluginHooks = new Map();
  }
  
  registerPlugin(name, plugin) {
    if (this.plugins.has(name)) {
      throw new Error(`Plugin ${name} already registered`);
    }
    
    this.plugins.set(name, plugin);
    
    // Register plugin hooks
    if (plugin.hooks) {
      for (const [event, hookFn] of Object.entries(plugin.hooks)) {
        this.addHook(event, hookFn.bind(plugin));
        this.pluginHooks.set(`${name}:${event}`, hookFn);
      }
    }
    
    // Initialize plugin
    if (plugin.initialize) {
      plugin.initialize(this);
    }
    
    this.emit('plugin:registered', { name, plugin });
  }
  
  unregisterPlugin(name) {
    const plugin = this.plugins.get(name);
    if (!plugin) return false;
    
    // Cleanup plugin
    if (plugin.cleanup) {
      plugin.cleanup();
    }
    
    // Remove plugin hooks
    for (const [key, hookFn] of this.pluginHooks) {
      if (key.startsWith(`${name}:`)) {
        // Need to remove from hooks map (simplified)
        this.pluginHooks.delete(key);
      }
    }
    
    this.plugins.delete(name);
    this.emit('plugin:unregistered', { name });
    
    return true;
  }
  
  async executeWithPlugins(event, ...args) {
    // Run pre-plugin hooks
    await this.runHooks('before:all', event, { event, args });
    
    // Execute main event with plugin middleware
    const results = await this.emitAsync(event, ...args);
    
    // Run post-plugin hooks
    await this.runHooks('after:all', event, { event, args, results });
    
    return results;
  }
}
```

---

## 4. http/https

### In-depth Explanation

The `http` and `https` modules provide HTTP server and client functionality. They are the foundation for web servers, APIs, and HTTP communication in Node.js.

**Key Components:**
- **http.Server**: HTTP server
- **http.ClientRequest**: HTTP client requests
- **http.IncomingMessage**: Request/response objects
- **http.ServerResponse**: Response object

**Basic HTTP Server:**
```javascript
const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  // Parse URL
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  // Set response headers
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Powered-By', 'Node.js');
  
  // Handle routes
  if (pathname === '/api/users') {
    if (req.method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({ users: [] }));
    } else if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        res.writeHead(201);
        res.end(JSON.stringify({ message: 'User created' }));
      });
    } else {
      res.writeHead(405);
      res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  } else {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

**Advanced HTTP Server Features:**
```javascript
const http = require('http');
const https = require('https');
const fs = require('fs');
const { pipeline } = require('stream');

class AdvancedHTTPServer {
  constructor(options = {}) {
    this.options = {
      port: options.port || 3000,
      ssl: options.ssl || false,
      timeout: options.timeout || 30000,
      maxHeadersCount: options.maxHeadersCount || 2000,
      keepAliveTimeout: options.keepAliveTimeout || 5000
    };
    
    this.routes = new Map();
    this.middleware = [];
    this.server = null;
  }
  
  // Add route handler
  route(method, path, handler) {
    const key = `${method}:${path}`;
    this.routes.set(key, handler);
  }
  
  // Add middleware
  use(middleware) {
    this.middleware.push(middleware);
  }
  
  // Start server
  start() {
    const requestHandler = async (req, res) => {
      // Apply middleware
      for (const middleware of this.middleware) {
        const shouldContinue = await middleware(req, res);
        if (shouldContinue === false) {
          return; // Middleware handled the request
        }
      }
      
      // Find route handler
      const key = `${req.method}:${req.url}`;
      const handler = this.routes.get(key);
      
      if (handler) {
        try {
          await handler(req, res);
        } catch (error) {
          this.handleError(error, req, res);
        }
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    };
    
    if (this.options.ssl) {
      // HTTPS server
      const sslOptions = {
        key: fs.readFileSync(this.options.ssl.key),
        cert: fs.readFileSync(this.options.ssl.cert),
        ...this.options.ssl.options
      };
      
      this.server = https.createServer(sslOptions, requestHandler);
    } else {
      // HTTP server
      this.server = http.createServer(requestHandler);
    }
    
    // Configure server
    this.server.timeout = this.options.timeout;
    this.server.maxHeadersCount = this.options.maxHeadersCount;
    this.server.keepAliveTimeout = this.options.keepAliveTimeout;
    
    // Handle server errors
    this.server.on('error', (error) => {
      console.error('Server error:', error);
    });
    
    // Handle client errors
    this.server.on('clientError', (error, socket) => {
      console.error('Client error:', error);
      if (socket.writable) {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      }
    });
    
    // Start listening
    this.server.listen(this.options.port, () => {
      console.log(`Server listening on port ${this.options.port}`);
    });
    
    return this.server;
  }
  
  // Graceful shutdown
  async stop() {
    if (!this.server) return;
    
    return new Promise((resolve) => {
      this.server.close(() => {
        console.log('Server stopped');
        resolve();
      });
      
      // Force close after timeout
      setTimeout(() => {
        console.log('Forcing server close');
        this.server.close();
        resolve();
      }, 10000);
    });
  }
  
  // Handle errors
  handleError(error, req, res) {
    console.error('Request error:', error);
    
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : undefined
      }));
    }
  }
  
  // Streaming response
  static streamFile(filePath, req, res) {
    const fileStream = fs.createReadStream(filePath);
    
    fileStream.on('error', (error) => {
      if (error.code === 'ENOENT') {
        res.writeHead(404);
        res.end('File not found');
      } else {
        res.writeHead(500);
        res.end('Internal server error');
      }
    });
    
    // Handle range requests (partial content)
    const range = req.headers.range;
    const stats = fs.statSync(filePath);
    
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;
      const chunksize = (end - start) + 1;
      
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${stats.size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'application/octet-stream'
      });
      
      const fileStream = fs.createReadStream(filePath, { start, end });
      fileStream.pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': stats.size,
        'Content-Type': 'application/octet-stream'
      });
      
      pipeline(fileStream, res, (error) => {
        if (error) console.error('Stream error:', error);
      });
    }
  }
  
  // HTTP/2 support (with spdy or http2 module)
  static createHTTP2Server(options) {
    const http2 = require('http2');
    const fs = require('fs');
    
    const serverOptions = {
      key: fs.readFileSync(options.key),
      cert: fs.readFileSync(options.cert)
    };
    
    const server = http2.createSecureServer(serverOptions);
    
    server.on('stream', (stream, headers) => {
      // Handle HTTP/2 streams
      stream.respond({
        'content-type': 'application/json',
        ':status': 200
      });
      
      stream.end(JSON.stringify({ message: 'Hello HTTP/2' }));
    });
    
    return server;
  }
}
```

**HTTP Client with Advanced Features:**
```javascript
const http = require('http');
const https = require('https');
const { URL } = require('url');

class AdvancedHTTPClient {
  constructor(options = {}) {
    this.defaultOptions = {
      timeout: options.timeout || 30000,
      maxRedirects: options.maxRedirects || 5,
      retry: options.retry || {
        attempts: 3,
        delay: 1000,
        statusCodes: [500, 502, 503, 504]
      },
      pool: options.pool || {
        maxSockets: 50,
        maxFreeSockets: 10,
        timeout: 60000
      }
    };
    
    // Configure agent for connection pooling
    this.agent = new http.Agent(this.defaultOptions.pool);
    this.sslAgent = new https.Agent(this.defaultOptions.pool);
  }
  
  // Make request with retry logic
  async request(url, options = {}, data = null) {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const agent = isHttps ? this.sslAgent : this.agent;
    
    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      agent,
      timeout: this.defaultOptions.timeout,
      ...options
    };
    
    let attempts = 0;
    const maxAttempts = this.defaultOptions.retry.attempts;
    
    while (attempts < maxAttempts) {
      attempts++;
      
      try {
        const result = await this._makeRequest(requestOptions, data, isHttps);
        
        // Check if retry is needed
        if (this.shouldRetry(result.statusCode) && attempts < maxAttempts) {
          await this.delay(this.defaultOptions.retry.delay * attempts);
          continue;
        }
        
        return result;
      } catch (error) {
        if (attempts === maxAttempts) {
          throw error;
        }
        
        // Only retry on network errors, not application errors
        if (this.isNetworkError(error)) {
          await this.delay(this.defaultOptions.retry.delay * attempts);
        } else {
          throw error;
        }
      }
    }
  }
  
  // Make single request
  _makeRequest(options, data, isHttps) {
    return new Promise((resolve, reject) => {
      const module = isHttps ? https : http;
      const req = module.request(options, (res) => {
        const chunks = [];
        
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const response = {
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks)
          };
          
          // Handle redirects
          if (this.isRedirect(response.statusCode) && res.headers.location) {
            this.handleRedirect(res.headers.location, options, data)
              .then(resolve)
              .catch(reject);
          } else {
            resolve(response);
          }
        });
      });
      
      req.on('error', reject);
      req.setTimeout(options.timeout, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      
      if (data) {
        if (typeof data === 'object' && !Buffer.isBuffer(data)) {
          req.write(JSON.stringify(data));
        } else {
          req.write(data);
        }
      }
      
      req.end();
    });
  }
  
  // Handle redirects
  async handleRedirect(location, originalOptions, data) {
    const redirectCount = (originalOptions._redirectCount || 0) + 1;
    
    if (redirectCount > this.defaultOptions.maxRedirects) {
      throw new Error('Too many redirects');
    }
    
    const newOptions = { ...originalOptions, _redirectCount: redirectCount };
    return this.request(location, newOptions, data);
  }
  
  // Helper methods
  shouldRetry(statusCode) {
    return this.defaultOptions.retry.statusCodes.includes(statusCode);
  }
  
  isRedirect(statusCode) {
    return [301, 302, 303, 307, 308].includes(statusCode);
  }
  
  isNetworkError(error) {
    return [
      'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED',
      'ENOTFOUND', 'EAI_AGAIN'
    ].includes(error.code);
  }
  
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // Convenience methods
  async get(url, options = {}) {
    return this.request(url, { ...options, method: 'GET' });
  }
  
  async post(url, data, options = {}) {
    return this.request(url, { 
      ...options, 
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    }, data);
  }
  
  // Stream request
  stream(url, options = {}) {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const module = isHttps ? https : http;
    
    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      agent: isHttps ? this.sslAgent : this.agent
    };
    
    return module.request(requestOptions);
  }
  
  // Cleanup
  destroy() {
    this.agent.destroy();
    this.sslAgent.destroy();
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `http.createServer()` and using the `http` module directly?
2. How do you handle different HTTP methods (GET, POST, etc.) in a server?
3. What are HTTP keep-alive connections and how does Node.js handle them?
4. How do you parse query parameters from a URL?

**Senior Level:**
5. How would you implement connection pooling for HTTP clients?
6. Explain how to handle file uploads with progress tracking.
7. How would you implement HTTP/2 server push in Node.js?
8. What are the security considerations when building an HTTP server?

### 🌍 Real-World Scenarios

**Scenario 1: Reverse Proxy with Load Balancing**
> Build a reverse proxy that:
> 1. Distributes requests to multiple backend servers
> 2. Supports health checks
> 3. Implements circuit breakers
> 4. Handles WebSocket connections

**Solution:**
```javascript
const http = require('http');
const https = require('https');
const httpProxy = require('http-proxy');
const { URL } = require('url');
const EventEmitter = require('events');

class LoadBalancer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.backends = options.backends || [];
    this.strategy = options.strategy || 'round-robin';
    this.healthCheckInterval = options.healthCheckInterval || 10000;
    this.circuitBreaker = options.circuitBreaker || {
      failureThreshold: 5,
      resetTimeout: 30000,
      halfOpenMaxAttempts: 3
    };
    
    this.currentIndex = 0;
    this.backendStatus = new Map();
    this.circuitStates = new Map();
    this.proxy = httpProxy.createProxyServer({});
    this.server = null;
    
    this.setupHealthChecks();
    this.setupProxyHandlers();
  }
  
  // Add backend server
  addBackend(backend) {
    this.backends.push(backend);
    this.backendStatus.set(backend.url, { healthy: true, lastCheck: Date.now() });
    this.circuitStates.set(backend.url, {
      state: 'CLOSED',
      failures: 0,
      lastFailure: 0,
      halfOpenAttempts: 0
    });
  }
  
  // Get next backend based on strategy
  getNextBackend() {
    const healthyBackends = this.backends.filter(backend => 
      this.backendStatus.get(backend.url)?.healthy &&
      this.circuitStates.get(backend.url)?.state !== 'OPEN'
    );
    
    if (healthyBackends.length === 0) {
      throw new Error('No healthy backends available');
    }
    
    switch (this.strategy) {
      case 'round-robin':
        const backend = healthyBackends[this.currentIndex % healthyBackends.length];
        this.currentIndex++;
        return backend;
        
      case 'random':
        return healthyBackends[Math.floor(Math.random() * healthyBackends.length)];
        
      case 'least-connections':
        // Implement connection counting
        return healthyBackends.reduce((prev, curr) => 
          (prev.connections || 0) < (curr.connections || 0) ? prev : curr
        );
        
      default:
        return healthyBackends[0];
    }
  }
  
  // Setup health checks
  setupHealthChecks() {
    setInterval(() => {
      this.backends.forEach(async (backend) => {
        try {
          const healthy = await this.checkHealth(backend);
          const previousStatus = this.backendStatus.get(backend.url);
          
          this.backendStatus.set(backend.url, {
            healthy,
            lastCheck: Date.now()
          });
          
          if (previousStatus.healthy !== healthy) {
            this.emit('backendHealthChange', {
              backend: backend.url,
              healthy,
              timestamp: Date.now()
            });
          }
        } catch (error) {
          console.error(`Health check failed for ${backend.url}:`, error);
        }
      });
    }, this.healthCheckInterval);
  }
  
  // Check backend health
  async checkHealth(backend) {
    return new Promise((resolve) => {
      const url = new URL(backend.healthCheck || backend.url);
      const module = url.protocol === 'https:' ? https : http;
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'GET',
        timeout: 5000
      };
      
      const req = module.request(options, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          resolve(res.statusCode === 200);
        });
      });
      
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      
      req.end();
    });
  }
  
  // Setup proxy handlers
  setupProxyHandlers() {
    this.proxy.on('error', (err, req, res) => {
      console.error('Proxy error:', err);
      
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Gateway' }));
      }
    });
    
    this.proxy.on('proxyReq', (proxyReq, req, res, options) => {
      // Add custom headers
      proxyReq.setHeader('X-Forwarded-For', req.connection.remoteAddress);
      proxyReq.setHeader('X-Forwarded-Host', req.headers.host);
    });
    
    this.proxy.on('proxyRes', (proxyRes, req, res) => {
      const backend = req._backend;
      const circuitState = this.circuitStates.get(backend.url);
      
      // Reset circuit breaker on success
      if (circuitState.state === 'HALF_OPEN') {
        circuitState.halfOpenAttempts++;
        
        if (circuitState.halfOpenAttempts >= this.circuitBreaker.halfOpenMaxAttempts) {
          circuitState.state = 'CLOSED';
          circuitState.failures = 0;
          circuitState.halfOpenAttempts = 0;
        }
      }
      
      // Track backend metrics
      backend.lastResponseTime = Date.now() - req._startTime;
      backend.totalRequests = (backend.totalRequests || 0) + 1;
    });
  }
  
  // Request handler
  async handleRequest(req, res) {
    req._startTime = Date.now();
    
    try {
      const backend = this.getNextBackend();
      req._backend = backend;
      
      const circuitState = this.circuitStates.get(backend.url);
      
      // Check circuit breaker
      if (circuitState.state === 'OPEN') {
        if (Date.now() - circuitState.lastFailure > this.circuitBreaker.resetTimeout) {
          circuitState.state = 'HALF_OPEN';
          circuitState.halfOpenAttempts = 0;
        } else {
          throw new Error('Circuit breaker open');
        }
      }
      
      // Proxy the request
      this.proxy.web(req, res, {
        target: backend.url,
        changeOrigin: true,
        timeout: 10000,
        proxyTimeout: 10000
      });
      
    } catch (error) {
      this.handleProxyError(error, req, res);
    }
  }
  
  // Handle proxy errors
  handleProxyError(error, req, res) {
    const backend = req._backend;
    
    if (backend) {
      // Update circuit breaker
      const circuitState = this.circuitStates.get(backend.url);
      circuitState.failures++;
      circuitState.lastFailure = Date.now();
      
      if (circuitState.failures >= this.circuitBreaker.failureThreshold) {
        circuitState.state = 'OPEN';
      }
    }
    
    if (!res.headersSent) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service unavailable' }));
    }
  }
  
  // WebSocket support
  handleUpgrade(req, socket, head) {
    try {
      const backend = this.getNextBackend();
      
      this.proxy.ws(req, socket, head, {
        target: backend.url,
        changeOrigin: true
      });
    } catch (error) {
      socket.destroy();
    }
  }
  
  // Start load balancer
  start(port = 8080) {
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
    
    this.server.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket, head);
    });
    
    this.server.listen(port, () => {
      console.log(`Load balancer listening on port ${port}`);
    });
  }
  
  // Graceful shutdown
  async stop() {
    if (this.server) {
      await new Promise(resolve => this.server.close(resolve));
    }
    this.proxy.close();
  }
}
```

**Scenario 2: API Gateway with Rate Limiting & Caching**
> Build an API gateway that:
> 1. Routes requests to microservices
> 2. Implements rate limiting per client
> 3. Caches responses
> 4. Performs request/response transformation

**Solution:**
```javascript
const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');

class APIGateway {
  constructor(options = {}) {
    this.routes = new Map();
    this.middleware = [];
    this.rateLimiters = new Map();
    this.cache = new Map();
    this.metrics = {
      requests: 0,
      cacheHits: 0,
      rateLimited: 0
    };
    
    this.defaultOptions = {
      rateLimit: options.rateLimit || {
        windowMs: 60000,
        max: 100,
        message: 'Too many requests'
      },
      cache: options.cache || {
        ttl: 300000, // 5 minutes
        maxSize: 1000
      },
      timeout: options.timeout || 10000
    };
  }
  
  // Add route
  route(method, path, service) {
    const key = `${method}:${path}`;
    this.routes.set(key, service);
  }
  
  // Add middleware
  use(middleware) {
    this.middleware.push(middleware);
  }
  
  // Rate limiting middleware
  rateLimitMiddleware(req, res) {
    const clientId = this.getClientId(req);
    const limiter = this.getRateLimiter(clientId);
    
    if (!limiter.check()) {
      this.metrics.rateLimited++;
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
      return false;
    }
    
    return true;
  }
  
  // Caching middleware
  cachingMiddleware(req, res, next) {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next();
    }
    
    const cacheKey = this.getCacheKey(req);
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() < cached.expires) {
      this.metrics.cacheHits++;
      
      // Copy cached headers
      Object.entries(cached.headers).forEach(([key, value]) => {
        res.setHeader(key, value);
      });
      
      res.writeHead(cached.statusCode);
      res.end(cached.body);
      return false; // Stop middleware chain
    }
    
    // Override res.end to cache response
    const originalEnd = res.end.bind(res);
    res.end = (body) => {
      // Cache the response
      this.cacheResponse(cacheKey, {
        statusCode: res.statusCode,
        headers: this.getResponseHeaders(res),
        body: body,
        expires: Date.now() + this.defaultOptions.cache.ttl
      });
      
      originalEnd(body);
    };
    
    return next();
  }
  
  // Request handler
  async handleRequest(req, res) {
    this.metrics.requests++;
    
    // Apply middleware
    const middlewareChain = [...this.middleware];
    
    for (let i = 0; i < middlewareChain.length; i++) {
      const shouldContinue = await middlewareChain[i](req, res, () => {
        return i < middlewareChain.length - 1 ? middlewareChain[i + 1] : () => true;
      });
      
      if (shouldContinue === false) {
        return; // Middleware handled the request
      }
    }
    
    // Find route
    const routeKey = `${req.method}:${req.url}`;
    const service = this.findMatchingRoute(routeKey);
    
    if (!service) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Route not found' }));
      return;
    }
    
    // Proxy to service
    await this.proxyToService(req, res, service);
  }
  
  // Proxy request to service
  async proxyToService(req, res, service) {
    const url = new URL(service.url);
    const isHttps = url.protocol === 'https:';
    const module = isHttps ? https : http;
    
    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + this.getRequestPath(req, service),
      method: req.method,
      headers: this.transformRequestHeaders(req.headers, service),
      timeout: this.defaultOptions.timeout
    };
    
    // Handle request body
    let requestBody = '';
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      requestBody = await this.readRequestBody(req);
    }
    
    const proxyReq = module.request(options, (proxyRes) => {
      // Transform response if needed
      const transformedHeaders = this.transformResponseHeaders(proxyRes.headers, service);
      
      res.writeHead(proxyRes.statusCode || 200, transformedHeaders);
      
      // Pipe response
      proxyRes.on('data', (chunk) => {
        res.write(chunk);
      });
      
      proxyRes.on('end', () => {
        res.end();
      });
    });
    
    proxyReq.on('error', (error) => {
      console.error('Proxy error:', error);
      
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Gateway' }));
      }
    });
    
    if (requestBody) {
      proxyReq.write(requestBody);
    }
    
    proxyReq.end();
  }
  
  // Helper methods
  getClientId(req) {
    // Use IP address or API key
    return req.headers['x-api-key'] || 
           req.connection.remoteAddress || 
           'anonymous';
  }
  
  getRateLimiter(clientId) {
    if (!this.rateLimiters.has(clientId)) {
      this.rateLimiters.set(clientId, new RateLimiter(this.defaultOptions.rateLimit));
    }
    return this.rateLimiters.get(clientId);
  }
  
  getCacheKey(req) {
    return crypto.createHash('md5')
      .update(`${req.method}:${req.url}:${JSON.stringify(req.headers)}`)
      .digest('hex');
  }
  
  cacheResponse(key, response) {
    // Simple LRU cache implementation
    if (this.cache.size >= this.defaultOptions.cache.maxSize) {
      // Remove oldest entry
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    
    this.cache.set(key, response);
  }
  
  getResponseHeaders(res) {
    const headers = {};
    res.getHeaderNames().forEach(name => {
      headers[name] = res.getHeader(name);
    });
    return headers;
  }
  
  findMatchingRoute(routeKey) {
    // Simple exact match - could be enhanced with path patterns
    return this.routes.get(routeKey);
  }
  
  getRequestPath(req, service) {
    // Extract path after service prefix
    const servicePath = service.path || '';
    return req.url.slice(servicePath.length) || '/';
  }
  
  transformRequestHeaders(headers, service) {
    // Remove hop-by-hop headers
    const hopByHop = [
      'connection', 'keep-alive', 'proxy-authenticate',
      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
    ];
    
    const transformed = { ...headers };
    hopByHop.forEach(header => delete transformed[header]);
    
    // Add service-specific headers
    if (service.headers) {
      Object.assign(transformed, service.headers);
    }
    
    return transformed;
  }
  
  transformResponseHeaders(headers, service) {
    // Similar transformation for response
    const transformed = { ...headers };
    
    // Add CORS headers if needed
    if (service.cors) {
      Object.assign(transformed, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      });
    }
    
    return transformed;
  }
  
  async readRequestBody(req) {
    return new Promise((resolve) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => resolve(body));
    });
  }
  
  // Start server
  start(port = 3000) {
    const server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
    
    server.listen(port, () => {
      console.log(`API Gateway listening on port ${port}`);
    });
    
    return server;
  }
  
  // Get metrics
  getMetrics() {
    return {
      ...this.metrics,
      cacheSize: this.cache.size,
      cacheHitRate: this.metrics.requests > 0 ? 
        (this.metrics.cacheHits / this.metrics.requests * 100).toFixed(2) : 0
    };
  }
}

// Rate limiter class
class RateLimiter {
  constructor(options) {
    this.windowMs = options.windowMs;
    this.max = options.max;
    this.requests = [];
  }
  
  check() {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    // Remove old requests
    this.requests = this.requests.filter(time => time > windowStart);
    
    if (this.requests.length >= this.max) {
      return false;
    }
    
    this.requests.push(now);
    return true;
  }
}
```

---

## 5. os

### In-depth Explanation

The `os` module provides operating system-related utility methods and properties. It's useful for system information, resource monitoring, and platform-specific behavior.

**Key Methods and Properties:**
```javascript
const os = require('os');

// Platform information
console.log('Platform:', os.platform()); // 'linux', 'darwin', 'win32'
console.log('Architecture:', os.arch()); // 'x64', 'arm', 'ia32'
console.log('Release:', os.release()); // Kernel version
console.log('Type:', os.type()); // 'Linux', 'Darwin', 'Windows_NT'

// CPU information
console.log('CPUs:', os.cpus().length);
console.log('CPU Model:', os.cpus()[0].model);
console.log('CPU Speed:', os.cpus()[0].speed, 'MHz');

// Memory information
console.log('Total Memory:', os.totalmem() / 1024 / 1024 / 1024, 'GB');
console.log('Free Memory:', os.freemem() / 1024 / 1024 / 1024, 'GB');
console.log('Memory Usage:', 
  ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2), '%');

// Network interfaces
console.log('Network Interfaces:', Object.keys(os.networkInterfaces()));

// System uptime
console.log('Uptime:', os.uptime(), 'seconds');
console.log('Load Average:', os.loadavg()); // 1, 5, 15 minute averages

// User information
console.log('User Info:', os.userInfo());
console.log('Home Directory:', os.homedir());
console.log('Temp Directory:', os.tmpdir());

// Line endings (platform-specific)
console.log('EOL:', JSON.stringify(os.EOL)); // '\n' on Unix, '\r\n' on Windows

// Hostname
console.log('Hostname:', os.hostname());

// Constants
console.log('Constants:', {
  signals: os.constants.signals,
  errno: os.constants.errno,
  priority: os.constants.priority
});
```

**Advanced OS Monitoring:**
```javascript
const os = require('os');
const EventEmitter = require('events');

class SystemMonitor extends EventEmitter {
  constructor(interval = 5000) {
    super();
    this.interval = interval;
    this.monitorInterval = null;
    this.metrics = {
      cpu: [],
      memory: [],
      load: [],
      network: []
    };
    this.maxHistory = 60; // Keep 5 minutes of history (at 5s intervals)
  }
  
  start() {
    if (this.monitorInterval) {
      return;
    }
    
    // Initial metrics
    this.collectMetrics();
    
    // Start monitoring interval
    this.monitorInterval = setInterval(() => {
      this.collectMetrics();
    }, this.interval);
  }
  
  stop() {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }
  }
  
  collectMetrics() {
    const timestamp = Date.now();
    
    // CPU usage
    const cpuUsage = this.getCPUUsage();
    this.metrics.cpu.push({ timestamp, ...cpuUsage });
    this.trimHistory(this.metrics.cpu);
    
    // Memory usage
    const memoryUsage = this.getMemoryUsage();
    this.metrics.memory.push({ timestamp, ...memoryUsage });
    this.trimHistory(this.metrics.memory);
    
    // Load average
    const load = os.loadavg();
    this.metrics.load.push({ 
      timestamp, 
      '1min': load[0], 
      '5min': load[1], 
      '15min': load[2] 
    });
    this.trimHistory(this.metrics.load);
    
    // Network I/O
    const network = this.getNetworkIO();
    this.metrics.network.push({ timestamp, ...network });
    this.trimHistory(this.metrics.network);
    
    // Emit metrics
    this.emit('metrics', {
      cpu: cpuUsage,
      memory: memoryUsage,
      load,
      network
    });
    
    // Check thresholds
    this.checkThresholds(cpuUsage, memoryUsage, load);
  }
  
  getCPUUsage() {
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;
    
    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });
    
    // Calculate percentage
    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const usage = 100 - (100 * idle / total);
    
    return {
      usage: parseFloat(usage.toFixed(2)),
      cores: cpus.length,
      model: cpus[0].model,
      speed: cpus[0].speed
    };
  }
  
  getMemoryUsage() {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    
    return {
      total: this.formatBytes(total),
      free: this.formatBytes(free),
      used: this.formatBytes(used),
      percentage: parseFloat(((used / total) * 100).toFixed(2))
    };
  }
  
  getNetworkIO() {
    const interfaces = os.networkInterfaces();
    const stats = {};
    
    Object.entries(interfaces).forEach(([name, addrs]) => {
      stats[name] = {
        addresses: addrs.map(addr => ({
          address: addr.address,
          family: addr.family,
          internal: addr.internal
        })),
        total: addrs.length
      };
    });
    
    return stats;
  }
  
  checkThresholds(cpu, memory, load) {
    // CPU threshold (80%)
    if (cpu.usage > 80) {
      this.emit('warning', {
        type: 'high_cpu',
        value: cpu.usage,
        threshold: 80,
        timestamp: Date.now()
      });
    }
    
    // Memory threshold (90%)
    if (memory.percentage > 90) {
      this.emit('warning', {
        type: 'high_memory',
        value: memory.percentage,
        threshold: 90,
        timestamp: Date.now()
      });
    }
    
    // Load average threshold (cores * 2)
    const cores = os.cpus().length;
    if (load[0] > cores * 2) {
      this.emit('warning', {
        type: 'high_load',
        value: load[0],
        threshold: cores * 2,
        timestamp: Date.now()
      });
    }
  }
  
  formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unitIndex = 0;
    
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    
    return {
      value: parseFloat(value.toFixed(2)),
      unit: units[unitIndex],
      raw: bytes
    };
  }
  
  trimHistory(array) {
    while (array.length > this.maxHistory) {
      array.shift();
    }
  }
  
  getSummary() {
    const now = Date.now();
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    
    // Filter recent metrics
    const recentCPU = this.metrics.cpu.filter(m => m.timestamp > fiveMinutesAgo);
    const recentMemory = this.metrics.memory.filter(m => m.timestamp > fiveMinutesAgo);
    
    // Calculate averages
    const avgCPU = recentCPU.length > 0 ?
      recentCPU.reduce((sum, m) => sum + m.usage, 0) / recentCPU.length : 0;
    
    const avgMemory = recentMemory.length > 0 ?
      recentMemory.reduce((sum, m) => sum + m.percentage, 0) / recentMemory.length : 0;
    
    return {
      cpu: {
        current: this.metrics.cpu[this.metrics.cpu.length - 1]?.usage || 0,
        average: parseFloat(avgCPU.toFixed(2)),
        cores: os.cpus().length
      },
      memory: {
        current: this.metrics.memory[this.metrics.memory.length - 1]?.percentage || 0,
        average: parseFloat(avgMemory.toFixed(2)),
        total: this.formatBytes(os.totalmem()),
        free: this.formatBytes(os.freemem())
      },
      load: os.loadavg(),
      uptime: os.uptime(),
      platform: os.platform(),
      hostname: os.hostname()
    };
  }
}

// Process priority management
class ProcessManager {
  static setPriority(pid, priority = 'normal') {
    const priorities = {
      lowest: os.constants.priority.PRIORITY_LOWEST,
      low: os.constants.priority.PRIORITY_BELOW_NORMAL,
      normal: os.constants.priority.PRIORITY_NORMAL,
      high: os.constants.priority.PRIORITY_ABOVE_NORMAL,
      highest: os.constants.priority.PRIORITY_HIGHEST
    };
    
    try {
      if (priorities[priority] !== undefined) {
        os.setPriority(pid, priorities[priority]);
        return true;
      }
    } catch (error) {
      console.error('Failed to set priority:', error);
    }
    
    return false;
  }
  
  static getPriority(pid) {
    try {
      const priority = os.getPriority(pid);
      
      // Map numeric priority to string
      const priorityMap = {
        [os.constants.priority.PRIORITY_LOWEST]: 'lowest',
        [os.constants.priority.PRIORITY_BELOW_NORMAL]: 'low',
        [os.constants.priority.PRIORITY_NORMAL]: 'normal',
        [os.constants.priority.PRIORITY_ABOVE_NORMAL]: 'high',
        [os.constants.priority.PRIORITY_HIGHEST]: 'highest'
      };
      
      return priorityMap[priority] || 'unknown';
    } catch (error) {
      console.error('Failed to get priority:', error);
      return 'unknown';
    }
  }
}

// Platform-specific utilities
class PlatformUtils {
  static isWindows() {
    return os.platform() === 'win32';
  }
  
  static isLinux() {
    return os.platform() === 'linux';
  }
  
  static isMac() {
    return os.platform() === 'darwin';
  }
  
  static getLineEnding() {
    return os.EOL;
  }
  
  static getTempDir() {
    return os.tmpdir();
  }
  
  static getHomeDir() {
    return os.homedir();
  }
  
  static createTempFile(prefix = 'tmp') {
    const tempDir = this.getTempDir();
    const random = Math.random().toString(36).substring(2);
    return path.join(tempDir, `${prefix}-${random}`);
  }
  
  static getNetworkInfo() {
    const interfaces = os.networkInterfaces();
    const result = {
      public: [],
      private: [],
      loopback: []
    };
    
    Object.values(interfaces).flat().forEach(iface => {
      if (iface.internal) {
        result.loopback.push(iface.address);
      } else if (iface.family === 'IPv4') {
        // Check if private IP
        const ip = iface.address;
        if (ip.startsWith('10.') || 
            ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31 ||
            ip.startsWith('192.168.')) {
          result.private.push(ip);
        } else {
          result.public.push(ip);
        }
      }
    });
    
    return result;
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. How do you get CPU and memory usage information in Node.js?
2. What's the difference between `os.freemem()` and `os.totalmem()`?
3. How can you detect the operating system platform?
4. What are load averages and how do you interpret them?

**Senior Level:**
5. How would you implement a system resource monitor that alerts on thresholds?
6. Explain how to handle platform-specific file paths and line endings.
7. How would you implement CPU affinity in Node.js?
8. What are the security considerations when accessing system information?

### 🌍 Real-World Scenarios

**Scenario 1: Auto-scaling Decision Engine**
> Build a system that monitors resource usage and makes scaling decisions for a cloud deployment.

**Solution:**
```javascript
const os = require('os');
const EventEmitter = require('events');

class AutoScaler extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      checkInterval: options.checkInterval || 10000,
      scaleUpThreshold: options.scaleUpThreshold || 80,
      scaleDownThreshold: options.scaleDownThreshold || 30,
      cooldownPeriod: options.cooldownPeriod || 60000,
      maxInstances: options.maxInstances || 10,
      minInstances: options.minInstances || 1,
      ...options
    };
    
    this.currentInstances = this.options.minInstances;
    this.metricsHistory = [];
    this.lastScaleTime = 0;
    this.scalingInProgress = false;
    this.monitorInterval = null;
  }
  
  start() {
    this.monitorInterval = setInterval(() => {
      this.checkAndScale();
    }, this.options.checkInterval);
    
    console.log('Auto-scaler started');
  }
  
  stop() {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }
  }
  
  async checkAndScale() {
    // Check cooldown period
    if (Date.now() - this.lastScaleTime < this.options.cooldownPeriod) {
      return;
    }
    
    // Check if scaling is already in progress
    if (this.scalingInProgress) {
      return;
    }
    
    // Collect current metrics
    const metrics = await this.collectMetrics();
    this.metricsHistory.push({
      timestamp: Date.now(),
      ...metrics
    });
    
    // Keep only recent history (last 5 minutes)
    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
    this.metricsHistory = this.metricsHistory.filter(
      m => m.timestamp > fiveMinutesAgo
    );
    
    // Calculate trends
    const trend = this.calculateTrend();
    
    // Make scaling decision
    const decision = this.makeScalingDecision(metrics, trend);
    
    if (decision !== 'noop') {
      await this.executeScaling(decision);
    }
  }
  
  async collectMetrics() {
    // Collect system metrics
    const cpus = os.cpus();
    const load = os.loadavg();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    
    // Calculate CPU usage per core
    let totalIdle = 0;
    let totalTick = 0;
    
    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });
    
    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const cpuUsage = 100 - (100 * idle / total);
    
    // Collect application-specific metrics
    const appMetrics = await this.collectApplicationMetrics();
    
    return {
      cpu: {
        usage: cpuUsage,
        cores: cpus.length,
        load1: load[0],
        load5: load[1],
        load15: load[2]
      },
      memory: {
        total: totalMem,
        used: usedMem,
        free: freeMem,
        percentage: (usedMem / totalMem) * 100
      },
      application: appMetrics
    };
  }
  
  async collectApplicationMetrics() {
    // This would collect application-specific metrics
    // For example: request rate, queue length, error rate, etc.
    
    // Mock implementation
    return {
      requestRate: Math.random() * 1000,
      errorRate: Math.random() * 5,
      queueLength: Math.floor(Math.random() * 100),
      responseTime: Math.random() * 500
    };
  }
  
  calculateTrend() {
    if (this.metricsHistory.length < 2) {
      return { direction: 'stable', strength: 0 };
    }
    
    const recent = this.metricsHistory.slice(-5); // Last 5 data points
    const cpuTrend = this.calculateLinearTrend(
      recent.map(m => m.timestamp),
      recent.map(m => m.cpu.usage)
    );
    
    const memoryTrend = this.calculateLinearTrend(
      recent.map(m => m.timestamp),
      recent.map(m => m.memory.percentage)
    );
    
    return {
      cpu: cpuTrend,
      memory: memoryTrend,
      overall: (cpuTrend.slope + memoryTrend.slope) / 2
    };
  }
  
  calculateLinearTrend(x, y) {
    const n = x.length;
    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumX2 = 0;
    
    for (let i = 0; i < n; i++) {
      sumX += x[i];
      sumY += y[i];
      sumXY += x[i] * y[i];
      sumX2 += x[i] * x[i];
    }
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;
    
    return {
      slope,
      intercept,
      direction: slope > 0.1 ? 'up' : slope < -0.1 ? 'down' : 'stable'
    };
  }
  
  makeScalingDecision(metrics, trend) {
    const cpuUsage = metrics.cpu.usage;
    const memoryUsage = metrics.memory.percentage;
    const appMetrics = metrics.application;
    
    // Weighted score
    const cpuWeight = 0.4;
    const memoryWeight = 0.3;
    const appWeight = 0.3;
    
    let score = 0;
    let reasons = [];
    
    // CPU contribution
    if (cpuUsage > this.options.scaleUpThreshold) {
      score += cpuWeight;
      reasons.push(`CPU usage high: ${cpuUsage.toFixed(2)}%`);
    } else if (cpuUsage < this.options.scaleDownThreshold) {
      score -= cpuWeight;
      reasons.push(`CPU usage low: ${cpuUsage.toFixed(2)}%`);
    }
    
    // Memory contribution
    if (memoryUsage > this.options.scaleUpThreshold) {
      score += memoryWeight;
      reasons.push(`Memory usage high: ${memoryUsage.toFixed(2)}%`);
    } else if (memoryUsage < this.options.scaleDownThreshold) {
      score -= memoryWeight;
      reasons.push(`Memory usage low: ${memoryUsage.toFixed(2)}%`);
    }
    
    // Application metrics contribution
    if (appMetrics.queueLength > 50) {
      score += appWeight;
      reasons.push(`Queue length high: ${appMetrics.queueLength}`);
    }
    
    if (appMetrics.responseTime > 200) {
      score += appWeight * 0.5;
      reasons.push(`Response time high: ${appMetrics.responseTime.toFixed(2)}ms`);
    }
    
    // Consider trend
    if (trend.overall > 0.2) {
      score += 0.2;
      reasons.push(`Upward trend detected`);
    } else if (trend.overall < -0.2) {
      score -= 0.2;
      reasons.push(`Downward trend detected`);
    }
    
    // Make decision
    if (score > 0.7 && this.currentInstances < this.options.maxInstances) {
      return {
        action: 'scale_up',
        amount: this.calculateScaleAmount(score),
        reasons,
        score
      };
    } else if (score < -0.5 && this.currentInstances > this.options.minInstances) {
      return {
        action: 'scale_down',
        amount: 1,
        reasons,
        score
      };
    }
    
    return {
      action: 'noop',
      reasons: ['No significant pressure detected'],
      score
    };
  }
  
  calculateScaleAmount(score) {
    // Scale more aggressively for higher scores
    if (score > 1.5) return 3;
    if (score > 1.0) return 2;
    return 1;
  }
  
  async executeScaling(decision) {
    this.scalingInProgress = true;
    
    try {
      this.emit('scaling_started', {
        decision,
        currentInstances: this.currentInstances,
        timestamp: Date.now()
      });
      
      // Execute scaling action
      if (decision.action === 'scale_up') {
        await this.scaleUp(decision.amount);
      } else if (decision.action === 'scale_down') {
        await this.scaleDown(decision.amount);
      }
      
      this.lastScaleTime = Date.now();
      
      this.emit('scaling_completed', {
        decision,
        newInstances: this.currentInstances,
        timestamp: Date.now()
      });
      
    } catch (error) {
      this.emit('scaling_failed', {
        decision,
        error: error.message,
        timestamp: Date.now()
      });
      
    } finally {
      this.scalingInProgress = false;
    }
  }
  
  async scaleUp(amount) {
    // Implementation depends on cloud provider
    // This is a mock implementation
    
    console.log(`Scaling up by ${amount} instances`);
    
    // Simulate scaling delay
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    this.currentInstances += amount;
    
    console.log(`Scaled to ${this.currentInstances} instances`);
  }
  
  async scaleDown(amount) {
    console.log(`Scaling down by ${amount} instances`);
    
    // Simulate scaling delay
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    this.currentInstances -= amount;
    
    console.log(`Scaled to ${this.currentInstances} instances`);
  }
  
  getStatus() {
    return {
      currentInstances: this.currentInstances,
      lastScaleTime: this.lastScaleTime,
      scalingInProgress: this.scalingInProgress,
      options: this.options,
      metricsHistoryLength: this.metricsHistory.length
    };
  }
}
```

**Scenario 2: Cross-platform CLI Tool**
> Build a CLI tool that works consistently across Windows, macOS, and Linux, handling platform differences.

**Solution:**
```javascript
const os = require('os');
const path = require('path');
const fs = require('fs').promises;
const { exec, spawn } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class CrossPlatformCLI {
  constructor() {
    this.platform = os.platform();
    this.arch = os.arch();
    this.tempDir = os.tmpdir();
    this.homeDir = os.homedir();
    this.configDirs = this.getConfigDirs();
  }
  
  getConfigDirs() {
    const configDirs = {};
    
    switch (this.platform) {
      case 'win32':
        configDirs.config = path.join(this.homeDir, 'AppData', 'Roaming');
        configDirs.data = path.join(this.homeDir, 'AppData', 'Local');
        configDirs.cache = path.join(this.homeDir, 'AppData', 'Local', 'Temp');
        break;
        
      case 'darwin':
        configDirs.config = path.join(this.homeDir, 'Library', 'Application Support');
        configDirs.data = path.join(this.homeDir, 'Library', 'Application Support');
        configDirs.cache = path.join(this.homeDir, 'Library', 'Caches');
        break;
        
      default: // Linux and other Unix-like
        const xdgConfig = process.env.XDG_CONFIG_HOME || 
                         path.join(this.homeDir, '.config');
        const xdgData = process.env.XDG_DATA_HOME || 
                       path.join(this.homeDir, '.local', 'share');
        const xdgCache = process.env.XDG_CACHE_HOME || 
                        path.join(this.homeDir, '.cache');
        
        configDirs.config = xdgConfig;
        configDirs.data = xdgData;
        configDirs.cache = xdgCache;
    }
    
    return configDirs;
  }
  
  async ensureDir(dirPath) {
    try {
      await fs.mkdir(dirPath, { recursive: true });
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }
  }
  
  async writeConfig(appName, config) {
    const configDir = path.join(this.configDirs.config, appName);
    await this.ensureDir(configDir);
    
    const configPath = path.join(configDir, 'config.json');
    await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf8');
    
    return configPath;
  }
  
  async readConfig(appName) {
    const configPath = path.join(this.configDirs.config, appName, 'config.json');
    
    try {
      const content = await fs.readFile(configPath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      if (error.code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }
  
  async getCachePath(appName, key) {
    const cacheDir = path.join(this.configDirs.cache, appName);
    await this.ensureDir(cacheDir);
    
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(key).digest('hex');
    
    return path.join(cacheDir, hash);
  }
  
  async cacheData(appName, key, data, ttl = 3600000) {
    const cachePath = await this.getCachePath(appName, key);
    const cacheEntry = {
      data,
      expires: Date.now() + ttl,
      created: Date.now()
    };
    
    await fs.writeFile(cachePath, JSON.stringify(cacheEntry), 'utf8');
  }
  
  async getCachedData(appName, key) {
    const cachePath = await this.getCachePath(appName, key);
    
    try {
      const content = await fs.readFile(cachePath, 'utf8');
      const cacheEntry = JSON.parse(content);
      
      if (cacheEntry.expires > Date.now()) {
        return cacheEntry.data;
      } else {
        // Expired, delete cache file
        await fs.unlink(cachePath);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    
    return null;
  }
  
  async executeCommand(command, args = [], options = {}) {
    const shellCommand = this.platform === 'win32' ? 
      `cmd /c ${command} ${args.join(' ')}` :
      `${command} ${args.join(' ')}`;
    
    try {
      const { stdout, stderr } = await execAsync(shellCommand, {
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, ...options.env },
        timeout: options.timeout || 30000,
        maxBuffer: options.maxBuffer || 10 * 1024 * 1024 // 10MB
      });
      
      return {
        success: true,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        code: 0
      };
    } catch (error) {
      return {
        success: false,
        stdout: error.stdout?.toString().trim() || '',
        stderr: error.stderr?.toString().trim() || error.message,
        code: error.code || 1
      };
    }
  }
  
  spawnProcess(command, args = [], options = {}) {
    const spawnOptions = {
      cwd: options.cwd || process.cwd(),
      env: { ...process.env, ...options.env },
      stdio: options.stdio || 'pipe',
      detached: options.detached || false
    };
    
    // Handle Windows-specific spawning
    if (this.platform === 'win32') {
      spawnOptions.shell = true;
      if (options.detached) {
        spawnOptions.stdio = 'ignore';
      }
    }
    
    const child = spawn(command, args, spawnOptions);
    
    // Handle signals
    const signalHandler = (signal) => {
      if (child.killed) return;
      
      if (this.platform === 'win32') {
        // Windows doesn't support signals well
        child.kill('SIGTERM');
      } else {
        child.kill(signal);
      }
    };
    
    process.on('SIGTERM', signalHandler);
    process.on('SIGINT', signalHandler);
    
    // Cleanup signal handlers when child exits
    child.on('exit', () => {
      process.off('SIGTERM', signalHandler);
      process.off('SIGINT', signalHandler);
    });
    
    return child;
  }
  
  async getSystemInfo() {
    const info = {
      platform: this.platform,
      arch: this.arch,
      release: os.release(),
      hostname: os.hostname(),
      cpus: os.cpus().length,
      memory: {
        total: this.formatBytes(os.totalmem()),
        free: this.formatBytes(os.freemem())
      },
      load: os.loadavg(),
      uptime: os.uptime(),
      network: this.getNetworkInfo(),
      user: os.userInfo().username
    };
    
    // Platform-specific info
    switch (this.platform) {
      case 'win32':
        info.windows = await this.getWindowsInfo();
        break;
      case 'darwin':
        info.mac = await this.getMacInfo();
        break;
      case 'linux':
        info.linux = await this.getLinuxInfo();
        break;
    }
    
    return info;
  }
  
  async getWindowsInfo() {
    try {
      const { stdout } = await execAsync('systeminfo');
      const lines = stdout.split('\n');
      
      const info = {};
      lines.forEach(line => {
        const parts = line.split(':');
        if (parts.length >= 2) {
          const key = parts[0].trim();
          const value = parts.slice(1).join(':').trim();
          if (key && value) {
            info[key] = value;
          }
        }
      });
      
      return info;
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async getMacInfo() {
    try {
      const commands = {
        model: 'sysctl -n hw.model',
        serial: 'system_profiler SPHardwareDataType | grep "Serial Number"',
        osVersion: 'sw_vers -productVersion'
      };
      
      const results = {};
      
      for (const [key, command] of Object.entries(commands)) {
        try {
          const { stdout } = await execAsync(command);
          results[key] = stdout.trim();
        } catch (error) {
          results[key] = null;
        }
      }
      
      return results;
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async getLinuxInfo() {
    try {
      const commands = {
        distro: 'cat /etc/os-release | grep PRETTY_NAME',
        kernel: 'uname -r',
        packageManager: 'which apt && echo "apt" || which yum && echo "yum" || which pacman && echo "pacman" || echo "unknown"'
      };
      
      const results = {};
      
      for (const [key, command] of Object.entries(commands)) {
        try {
          const { stdout } = await execAsync(command);
          let value = stdout.trim();
          
          if (key === 'distro') {
            value = value.replace('PRETTY_NAME=', '').replace(/"/g, '');
          }
          
          results[key] = value;
        } catch (error) {
          results[key] = null;
        }
      }
      
      return results;
    } catch (error) {
      return { error: error.message };
    }
  }
  
  getNetworkInfo() {
    const interfaces = os.networkInterfaces();
    const result = {};
    
    Object.entries(interfaces).forEach(([name, addrs]) => {
      result[name] = addrs.map(addr => ({
        address: addr.address,
        netmask: addr.netmask,
        family: addr.family,
        mac: addr.mac,
        internal: addr.internal,
        cidr: addr.cidr
      }));
    });
    
    return result;
  }
  
  formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unitIndex = 0;
    
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    
    return {
      value: parseFloat(value.toFixed(2)),
      unit: units[unitIndex]
    };
  }
  
  async cleanupTempFiles(appName, maxAge = 24 * 60 * 60 * 1000) {
    const tempDir = path.join(this.tempDir, appName);
    
    try {
      const files = await fs.readdir(tempDir);
      const now = Date.now();
      
      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);
        
        if (now - stats.mtimeMs > maxAge) {
          await fs.unlink(filePath);
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
}
```

---

## 6. process

### In-depth Explanation

The `process` object provides information and control over the current Node.js process. It's a global object, so it's available without requiring.

**Key Properties and Methods:**
```javascript
// Process information
console.log('Process ID:', process.pid);
console.log('Parent PID:', process.ppid);
console.log('Platform:', process.platform);
console.log('Architecture:', process.arch);
console.log('Node version:', process.version);
console.log('V8 version:', process.versions.v8);
console.log('Versions:', process.versions);

// Memory usage
console.log('Memory usage:', process.memoryUsage());
console.log('Memory usage (RSS):', process.memoryUsage().rss / 1024 / 1024, 'MB');
console.log('Heap total:', process.memoryUsage().heapTotal / 1024 / 1024, 'MB');
console.log('Heap used:', process.memoryUsage().heapUsed / 1024 / 1024, 'MB');

// CPU usage
console.log('CPU usage:', process.cpuUsage());
console.log('CPU usage (user):', process.cpuUsage().user / 1000, 'ms');
console.log('CPU usage (system):', process.cpuUsage().system / 1000, 'ms');

// Command line arguments
console.log('argv:', process.argv);
console.log('execPath:', process.execPath);
console.log('execArgv:', process.execArgv);

// Environment variables
console.log('env NODE_ENV:', process.env.NODE_ENV);
console.log('env PATH:', process.env.PATH);

// Working directory
console.log('cwd:', process.cwd());
process.chdir('/tmp'); // Change working directory
console.log('New cwd:', process.cwd());

// Process title
console.log('Title:', process.title);
process.title = 'My Node App';

// Process events
process.on('exit', (code) => {
  console.log(`Process exiting with code: ${code}`);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection:', reason);
});

process.on('warning', (warning) => {
  console.warn('Warning:', warning);
});

// Process signals
process.on('SIGINT', () => {
  console.log('Received SIGINT (Ctrl+C)');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM');
  process.exit(0);
});

process.on('SIGUSR1', () => {
  console.log('Received SIGUSR1');
  // Can be used for debugging
});

process.on('SIGUSR2', () => {
  console.log('Received SIGUSR2');
  // Used by nodemon for restart
});

// Process control
setTimeout(() => {
  process.exit(0); // Exit with code 0
}, 5000);

// Or force exit
// process.exit(1); // Exit with code 1 (error)
// process.abort(); // Immediate abort
// process.kill(process.pid, 'SIGTERM'); // Send signal

// Process communication (if forked)
if (process.send) {
  process.send({ message: 'Hello parent' });
  process.on('message', (msg) => {
    console.log('Message from parent:', msg);
  });
}

// Resource limits (POSIX only)
try {
  console.log('Resource limits:', process.getResourceLimits());
} catch (err) {
  // Not available on Windows
}

// System uptime vs process uptime
console.log('System uptime:', process.uptime(), 'seconds');
console.log('Process uptime:', process.uptime(), 'seconds');
```

**Advanced Process Management:**
```javascript
const cluster = require('cluster');
const os = require('os');

class ProcessManager {
  constructor() {
    this.workers = new Map();
    this.isShuttingDown = false;
  }
  
  // Fork workers based on CPU cores
  forkWorkers(workerCount = os.cpus().length) {
    if (cluster.isMaster) {
      console.log(`Master ${process.pid} is running`);
      
      // Fork workers
      for (let i = 0; i < workerCount; i++) {
        this.forkWorker();
      }
      
      // Handle worker events
      cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
        if (!this.isShuttingDown) {
          this.forkWorker(); // Restart worker
        }
      });
      
    } else {
      // Worker process
      require('./worker'); // Your worker code
    }
  }
  
  forkWorker() {
    const worker = cluster.fork();
    this.workers.set(worker.process.pid, worker);
    
    worker.on('message', (msg) => {
      console.log(`Message from worker ${worker.process.pid}:`, msg);
    });
  }
  
  // Graceful shutdown
  async gracefulShutdown(signal) {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;
    
    console.log(`Received ${signal}, starting graceful shutdown...`);
    
    // Close workers
    const promises = [];
    for (const worker of this.workers.values()) {
      promises.push(new Promise((resolve) => {
        worker.on('disconnect', resolve);
        worker.send({ type: 'shutdown' });
        
        // Force kill after timeout
        setTimeout(() => {
          if (worker.isConnected()) {
            worker.kill('SIGKILL');
          }
          resolve();
        }, 10000);
      }));
    }
    
    await Promise.all(promises);
    console.log('All workers stopped');
    process.exit(0);
  }
  
  // Monitor process health
  setupHealthMonitoring() {
    setInterval(() => {
      const metrics = {
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        uptime: process.uptime(),
        workers: this.workers.size
      };
      
      // Check memory usage
      if (metrics.memory.heapUsed / metrics.memory.heapTotal > 0.9) {
        console.warn('High memory usage, consider restarting workers');
      }
      
      // Send metrics to monitoring system
      if (process.send) {
        process.send({ type: 'metrics', data: metrics });
      }
    }, 10000);
  }
}

// Process isolation with domains (deprecated but useful concept)
class ProcessIsolation {
  constructor() {
    this.domains = new Map();
  }
  
  executeInIsolation(code, context = {}) {
    return new Promise((resolve, reject) => {
      const domain = require('domain').create();
      
      domain.on('error', (err) => {
        console.error('Domain error:', err);
        reject(err);
      });
      
      domain.run(() => {
        try {
          // Isolate execution
          const result = this.safeEval(code, context);
          resolve(result);
        } catch (err) {
          reject(err);
        }
      });
    });
  }
  
  safeEval(code, context) {
    // Create isolated context
    const sandbox = {
      console,
      setTimeout,
      setInterval,
      clearTimeout,
      clearInterval,
      Buffer,
      ...context
    };
    
    // Restrict access
    const proxy = new Proxy(sandbox, {
      has(target, key) {
        if (key in target) {
          return true;
        }
        throw new Error(`Access to ${key} is not allowed`);
      },
      get(target, key) {
        if (key === 'require') {
          throw new Error('Require is not allowed in sandbox');
        }
        if (key === 'process') {
          // Return limited process object
          return {
            pid: process.pid,
            platform: process.platform,
            arch: process.arch,
            memoryUsage: process.memoryUsage,
            cpuUsage: process.cpuUsage,
            uptime: process.uptime
          };
        }
        return target[key];
      }
    });
    
    // Use vm module for true isolation
    const vm = require('vm');
    const script = new vm.Script(code);
    const result = script.runInNewContext(proxy, {
      timeout: 5000,
      displayErrors: true
    });
    
    return result;
  }
}

// Process resource management
class ResourceManager {
  constructor() {
    this.resources = new Map();
    this.cleanupHandlers = new Map();
  }
  
  // Track resource usage
  trackResource(name, resource) {
    this.resources.set(name, {
      resource,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      usageCount: 0
    });
  }
  
  useResource(name) {
    const entry = this.resources.get(name);
    if (entry) {
      entry.lastUsed = Date.now();
      entry.usageCount++;
      return entry.resource;
    }
    return null;
  }
  
  // Cleanup unused resources
  cleanupUnusedResources(maxAge = 60000) {
    const now = Date.now();
    
    for (const [name, entry] of this.resources) {
      if (now - entry.lastUsed > maxAge) {
        this.cleanupResource(name, entry.resource);
        this.resources.delete(name);
      }
    }
  }
  
  cleanupResource(name, resource) {
    const handler = this.cleanupHandlers.get(name);
    if (handler) {
      handler(resource);
    } else if (typeof resource.destroy === 'function') {
      resource.destroy();
    } else if (typeof resource.close === 'function') {
      resource.close();
    }
  }
  
  registerCleanupHandler(name, handler) {
    this.cleanupHandlers.set(name, handler);
  }
  
  // Setup global cleanup on exit
  setupExitCleanup() {
    const cleanup = () => {
      console.log('Cleaning up resources...');
      
      for (const [name, entry] of this.resources) {
        this.cleanupResource(name, entry.resource);
      }
      
      this.resources.clear();
      this.cleanupHandlers.clear();
    };
    
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(0);
    });
    process.on('SIGTERM', () => {
      cleanup();
      process.exit(0);
    });
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `process.exit()` and throwing an uncaught exception?
2. How do you handle graceful shutdown in Node.js?
3. What are the different signals a Node.js process can receive?
4. How can you monitor memory usage in a Node.js process?

**Senior Level:**
5. How would you implement zero-downtime deployments with Node.js?
6. What are the implications of the `--max-old-space-size` flag?
7. How does Node.js handle orphaned processes and zombie processes?
8. Explain how to use process clustering for multi-core utilization.

### 🌍 Real-World Scenarios

**Scenario 1: Application Lifecycle Manager**
> Build a system that manages application startup, shutdown, and health checks with dependency resolution.

**Solution:**
```javascript
const EventEmitter = require('events');

class ApplicationLifecycle extends EventEmitter {
  constructor() {
    super();
    this.services = new Map();
    this.dependencies = new Map();
    this.startupOrder = [];
    this.shutdownOrder = [];
    this.state = 'stopped';
    this.startupTimeout = 30000;
    this.shutdownTimeout = 30000;
  }
  
  // Register a service
  registerService(name, service, dependencies = []) {
    this.services.set(name, {
      instance: service,
      dependencies,
      state: 'stopped',
      startupPromise: null,
      shutdownPromise: null
    });
    
    this.dependencies.set(name, dependencies);
    
    // Update dependency graph
    this.updateDependencyGraph();
  }
  
  // Update dependency graph and topological order
  updateDependencyGraph() {
    const graph = new Map();
    const inDegree = new Map();
    
    // Initialize graph
    for (const [name, service] of this.services) {
      graph.set(name, new Set());
      inDegree.set(name, 0);
    }
    
    // Build graph
    for (const [name, service] of this.services) {
      for (const dep of service.dependencies) {
        if (graph.has(dep)) {
          graph.get(dep).add(name);
          inDegree.set(name, inDegree.get(name) + 1);
        }
      }
    }
    
    // Topological sort (Kahn's algorithm)
    const queue = [];
    const order = [];
    
    // Find nodes with no dependencies
    for (const [name, degree] of inDegree) {
      if (degree === 0) {
        queue.push(name);
      }
    }
    
    while (queue.length > 0) {
      const name = queue.shift();
      order.push(name);
      
      for (const dependent of graph.get(name)) {
        inDegree.set(dependent, inDegree.get(dependent) - 1);
        if (inDegree.get(dependent) === 0) {
          queue.push(dependent);
        }
      }
    }
    
    // Check for cycles
    if (order.length !== this.services.size) {
      throw new Error('Circular dependency detected');
    }
    
    this.startupOrder = order;
    this.shutdownOrder = [...order].reverse();
  }
  
  // Start all services
  async start() {
    if (this.state !== 'stopped') {
      throw new Error(`Cannot start from state: ${this.state}`);
    }
    
    this.state = 'starting';
    this.emit('starting');
    
    const errors = [];
    
    try {
      // Start services in topological order
      for (const name of this.startupOrder) {
        try {
          await this.startService(name);
        } catch (error) {
          errors.push({ service: name, error });
          
          // If critical service fails, stop startup
          if (this.services.get(name).instance.critical) {
            throw new Error(`Critical service ${name} failed to start: ${error.message}`);
          }
        }
      }
      
      if (errors.length > 0) {
        console.warn('Some services failed to start:', errors);
      }
      
      this.state = 'started';
      this.emit('started');
      
      return { success: true, errors };
      
    } catch (error) {
      // Startup failed, shutdown what was started
      await this.emergencyShutdown();
      
      this.state = 'stopped';
      this.emit('startupFailed', error);
      
      throw error;
    }
  }
  
  // Start a single service
  async startService(name) {
    const service = this.services.get(name);
    if (!service) {
      throw new Error(`Service ${name} not found`);
    }
    
    if (service.state !== 'stopped') {
      throw new Error(`Service ${name} is already ${service.state}`);
    }
    
    service.state = 'starting';
    this.emit('serviceStarting', name);
    
    try {
      // Check dependencies
      for (const dep of service.dependencies) {
        const depService = this.services.get(dep);
        if (!depService || depService.state !== 'started') {
          throw new Error(`Dependency ${dep} is not started`);
        }
      }
      
      // Start service with timeout
      const startupPromise = Promise.race([
        service.instance.start(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error(`Startup timeout for ${name}`)), this.startupTimeout)
        )
      ]);
      
      service.startupPromise = startupPromise;
      await startupPromise;
      
      service.state = 'started';
      service.startupPromise = null;
      
      this.emit('serviceStarted', name);
      
    } catch (error) {
      service.state = 'failed';
      service.startupPromise = null;
      
      this.emit('serviceStartFailed', { name, error });
      throw error;
    }
  }
  
  // Stop all services
  async stop() {
    if (this.state !== 'started') {
      throw new Error(`Cannot stop from state: ${this.state}`);
    }
    
    this.state = 'stopping';
    this.emit('stopping');
    
    const errors = [];
    
    try {
      // Stop services in reverse topological order
      for (const name of this.shutdownOrder) {
        try {
          await this.stopService(name);
        } catch (error) {
          errors.push({ service: name, error });
          console.error(`Failed to stop service ${name}:`, error);
        }
      }
      
      this.state = 'stopped';
      this.emit('stopped');
      
      return { success: true, errors };
      
    } catch (error) {
      this.state = 'unknown';
      this.emit('shutdownFailed', error);
      throw error;
    }
  }
  
  // Stop a single service
  async stopService(name) {
    const service = this.services.get(name);
    if (!service) {
      throw new Error(`Service ${name} not found`);
    }
    
    if (service.state !== 'started') {
      return; // Already stopped or not started
    }
    
    service.state = 'stopping';
    this.emit('serviceStopping', name);
    
    try {
      // Stop service with timeout
      const shutdownPromise = Promise.race([
        service.instance.stop(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error(`Shutdown timeout for ${name}`)), this.shutdownTimeout)
        )
      ]);
      
      service.shutdownPromise = shutdownPromise;
      await shutdownPromise;
      
      service.state = 'stopped';
      service.shutdownPromise = null;
      
      this.emit('serviceStopped', name);
      
    } catch (error) {
      service.state = 'unknown';
      service.shutdownPromise = null;
      
      this.emit('serviceStopFailed', { name, error });
      throw error;
    }
  }
  
  // Emergency shutdown
  async emergencyShutdown() {
    console.error('Performing emergency shutdown');
    
    // Stop all started services (no order, just stop)
    const promises = [];
    
    for (const [name, service] of this.services) {
      if (service.state === 'started' || service.state === 'starting') {
        promises.push(
          this.stopService(name).catch(error => {
            console.error(`Emergency stop failed for ${name}:`, error);
          })
        );
      }
    }
    
    await Promise.all(promises);
  }
  
  // Get service status
  getStatus() {
    const status = {};
    
    for (const [name, service] of this.services) {
      status[name] = {
        state: service.state,
        dependencies: service.dependencies,
        uptime: service.instance.uptime ? service.instance.uptime() : 0
      };
    }
    
    return {
      state: this.state,
      services: status,
      startupOrder: this.startupOrder,
      shutdownOrder: this.shutdownOrder
    };
  }
  
  // Health check
  async healthCheck() {
    const checks = [];
    
    for (const [name, service] of this.services) {
      if (service.state === 'started' && service.instance.healthCheck) {
        try {
          const health = await service.instance.healthCheck();
          checks.push({ service: name, healthy: true, details: health });
        } catch (error) {
          checks.push({ service: name, healthy: false, error: error.message });
        }
      }
    }
    
    const healthy = checks.every(check => check.healthy);
    
    return {
      healthy,
      checks,
      timestamp: Date.now()
    };
  }
  
  // Setup signal handlers
  setupSignalHandlers() {
    process.on('SIGTERM', async () => {
      console.log('Received SIGTERM, shutting down...');
      await this.stop();
      process.exit(0);
    });
    
    process.on('SIGINT', async () => {
      console.log('Received SIGINT, shutting down...');
      await this.stop();
      process.exit(0);
    });
    
    // Graceful shutdown on uncaught exceptions
    process.on('uncaughtException', async (error) => {
      console.error('Uncaught exception:', error);
      await this.emergencyShutdown();
      process.exit(1);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled rejection:', reason);
    });
  }
}
```

**Scenario 2: Feature Flag System with Dynamic Configuration**
> Build a system that allows runtime configuration changes without restarting the application.

**Solution:**
```javascript
const EventEmitter = require('events');
const crypto = require('crypto');

class FeatureManager extends EventEmitter {
  constructor() {
    super();
    this.features = new Map();
    this.configs = new Map();
    this.listeners = new Map();
    this.configSources = [];
    this.pollingInterval = 30000; // 30 seconds
    this.pollingTimer = null;
    this.initialized = false;
  }
  
  // Initialize with config sources
  async initialize(sources = []) {
    if (this.initialized) {
      throw new Error('FeatureManager already initialized');
    }
    
    this.configSources = sources;
    
    // Load initial configuration
    await this.loadAllConfigs();
    
    // Start polling for changes
    this.startPolling();
    
    this.initialized = true;
    this.emit('initialized');
  }
  
  // Add config source
  addConfigSource(source) {
    if (this.initialized) {
      throw new Error('Cannot add config source after initialization');
    }
    
    this.configSources.push(source);
  }
  
  // Load configuration from all sources
  async loadAllConfigs() {
    const promises = this.configSources.map(source => this.loadConfig(source));
    const results = await Promise.allSettled(promises);
    
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Failed to load config from source ${index}:`, result.reason);
      }
    });
    
    this.emit('configsLoaded');
  }
  
  // Load configuration from a source
  async loadConfig(source) {
    let config;
    
    if (typeof source === 'function') {
      // Function source
      config = await source();
    } else if (source.type === 'file') {
      // File source
      const fs = require('fs').promises;
      const content = await fs.readFile(source.path, 'utf8');
      config = JSON.parse(content);
    } else if (source.type === 'http') {
      // HTTP source
      const http = source.url.startsWith('https') ? require('https') : require('http');
      config = await new Promise((resolve, reject) => {
        http.get(source.url, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (error) {
              reject(error);
            }
          });
        }).on('error', reject);
      });
    } else if (source.type === 'env') {
      // Environment variables
      config = {};
      for (const key in process.env) {
        if (key.startsWith(source.prefix || 'FEATURE_')) {
          const featureName = key.replace(source.prefix || 'FEATURE_', '').toLowerCase();
          config[featureName] = this.parseEnvValue(process.env[key]);
        }
      }
    }
    
    // Merge config
    this.mergeConfig(config, source.priority || 0);
  }
  
  // Parse environment variable value
  parseEnvValue(value) {
    if (value === 'true' || value === 'false') {
      return value === 'true';
    } else if (!isNaN(value) && value.trim() !== '') {
      return Number(value);
    } else if (value.startsWith('{') || value.startsWith('[')) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }
    }
    return value;
  }
  
  // Merge configuration with priority
  mergeConfig(config, priority) {
    for (const [key, value] of Object.entries(config)) {
      const existing = this.configs.get(key);
      
      if (!existing || existing.priority < priority) {
        this.configs.set(key, { value, priority, timestamp: Date.now() });
        
        // Check if value changed
        if (existing && this.valueChanged(existing.value, value)) {
          this.notifyChange(key, value, existing.value);
        }
      }
    }
  }
  
  // Check if value changed
  valueChanged(oldValue, newValue) {
    const oldHash = crypto.createHash('md5')
      .update(JSON.stringify(oldValue))
      .digest('hex');
    const newHash = crypto.createHash('md5')
      .update(JSON.stringify(newValue))
      .digest('hex');
    
    return oldHash !== newHash;
  }
  
  // Notify listeners of change
  notifyChange(key, newValue, oldValue) {
    const listeners = this.listeners.get(key) || [];
    
    listeners.forEach(listener => {
      try {
        listener(newValue, oldValue);
      } catch (error) {
        console.error(`Error in feature change listener for ${key}:`, error);
      }
    });
    
    this.emit('featureChanged', { key, newValue, oldValue });
  }
  
  // Start polling for config changes
  startPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
    }
    
    this.pollingTimer = setInterval(() => {
      this.loadAllConfigs().catch(error => {
        console.error('Failed to poll configs:', error);
      });
    }, this.pollingInterval);
  }
  
  // Stop polling
  stopPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }
  
  // Check if feature is enabled
  isEnabled(featureName, context = {}) {
    const config = this.configs.get(featureName);
    
    if (!config) {
      return false; // Feature not configured
    }
    
    const value = config.value;
    
    // Handle different types of feature flags
    if (typeof value === 'boolean') {
      return value;
    } else if (typeof value === 'number') {
      // Percentage rollout
      const hash = crypto.createHash('md5')
        .update(`${featureName}:${context.userId || 'anonymous'}`)
        .digest('hex');
      const percentage = parseInt(hash.slice(0, 8), 16) % 100;
      return percentage < value;
    } else if (typeof value === 'object') {
      // Complex rule-based feature
      return this.evaluateRule(value, context);
    }
    
    return false;
  }
  
  // Evaluate complex rule
  evaluateRule(rule, context) {
    if (rule.enabled !== undefined) {
      return rule.enabled;
    }
    
    if (rule.percentage !== undefined) {
      const hash = crypto.createHash('md5')
        .update(`${rule.seed || 'default'}:${context.userId || 'anonymous'}`)
        .digest('hex');
      const percentage = parseInt(hash.slice(0, 8), 16) % 100;
      return percentage < rule.percentage;
    }
    
    if (rule.users && context.userId) {
      return rule.users.includes(context.userId);
    }
    
    if (rule.groups && context.groups) {
      return context.groups.some(group => rule.groups.includes(group));
    }
    
    if (rule.timeRange) {
      const now = Date.now();
      const start = new Date(rule.timeRange.start).getTime();
      const end = new Date(rule.timeRange.end).getTime();
      return now >= start && now <= end;
    }
    
    return false;
  }
  
  // Get feature configuration
  getConfig(featureName, defaultValue = null) {
    const config = this.configs.get(featureName);
    return config ? config.value : defaultValue;
  }
  
  // Set feature configuration (runtime override)
  setConfig(featureName, value, priority = 1000) {
    const existing = this.configs.get(featureName);
    const oldValue = existing ? existing.value : null;
    
    this.configs.set(featureName, { 
      value, 
      priority, 
      timestamp: Date.now(),
      source: 'runtime'
    });
    
    if (this.valueChanged(oldValue, value)) {
      this.notifyChange(featureName, value, oldValue);
    }
  }
  
  // Listen for feature changes
  onChange(featureName, listener) {
    if (!this.listeners.has(featureName)) {
      this.listeners.set(featureName, []);
    }
    
    this.listeners.get(featureName).push(listener);
    
    // Return unsubscribe function
    return () => {
      const listeners = this.listeners.get(featureName);
      if (listeners) {
        const index = listeners.indexOf(listener);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }
    };
  }
  
  // Get all features
  getAllFeatures() {
    const features = {};
    
    for (const [key, config] of this.configs) {
      features[key] = {
        value: config.value,
        priority: config.priority,
        timestamp: config.timestamp,
        source: config.source
      };
    }
    
    return features;
  }
  
  // Cleanup
  async cleanup() {
    this.stopPolling();
    this.listeners.clear();
    this.initialized = false;
  }
}

// Dynamic configuration middleware for Express
function featureMiddleware(featureManager) {
  return (req, res, next) => {
    // Add feature checking to request
    req.feature = (featureName, context = {}) => {
      const featureContext = {
        userId: req.user?.id,
        groups: req.user?.groups,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        ...context
      };
      
      return featureManager.isEnabled(featureName, featureContext);
    };
    
    // Add config access to request
    req.config = (featureName, defaultValue = null) => {
      return featureManager.getConfig(featureName, defaultValue);
    };
    
    next();
  };
}

// Example usage with Express
const express = require('express');
const app = express();

const featureManager = new FeatureManager();

// Initialize with multiple sources
featureManager.initialize([
  { type: 'file', path: './config/features.json', priority: 10 },
  { type: 'env', prefix: 'FEATURE_', priority: 100 },
  async () => {
    // Dynamic source - could fetch from database, API, etc.
    return {
      'new_checkout': true,
      'dark_mode': { percentage: 50, seed: 'dark_mode_rollout' }
    };
  }
]);

// Use middleware
app.use(featureMiddleware(featureManager));

// Route with feature flag
app.get('/api/new-feature', (req, res) => {
  if (req.feature('new_checkout')) {
    // New implementation
    res.json({ message: 'New feature enabled' });
  } else {
    // Old implementation
    res.json({ message: 'Old feature' });
  }
});

// Route with dynamic configuration
app.get('/api/config', (req, res) => {
  const config = {
    timeout: req.config('request_timeout', 5000),
    maxRetries: req.config('max_retries', 3),
    featureEnabled: req.feature('experimental_feature')
  };
  
  res.json(config);
});

// Listen for feature changes
featureManager.onChange('maintenance_mode', (newValue, oldValue) => {
  if (newValue) {
    console.log('Entering maintenance mode');
    // Close connections, stop accepting requests, etc.
  } else {
    console.log('Exiting maintenance mode');
    // Resume normal operations
  }
});

// Runtime configuration update endpoint
app.post('/admin/features', express.json(), (req, res) => {
  const { feature, value, priority } = req.body;
  
  if (!feature || value === undefined) {
    return res.status(400).json({ error: 'Missing feature or value' });
  }
  
  featureManager.setConfig(feature, value, priority || 1000);
  
  res.json({ success: true, feature, value });
});
```

---

## 7. url

### In-depth Explanation

The `url` module provides utilities for URL resolution and parsing. It's essential for web applications to handle URLs correctly.

**Key Components:**
```javascript
const url = require('url');
const { URL, URLSearchParams } = require('url');

// Legacy API (url.parse)
const parsedUrl = url.parse('https://example.com:8080/path?query=value#hash');
console.log(parsedUrl);
// {
//   protocol: 'https:',
//   slashes: true,
//   auth: null,
//   host: 'example.com:8080',
//   port: '8080',
//   hostname: 'example.com',
//   hash: '#hash',
//   search: '?query=value',
//   query: 'query=value',
//   pathname: '/path',
//   path: '/path?query=value',
//   href: 'https://example.com:8080/path?query=value#hash'
// }

// Modern API (URL class)
const myURL = new URL('https://example.com:8080/path?query=value#hash');
console.log(myURL);
// URL {
//   href: 'https://example.com:8080/path?query=value#hash',
//   origin: 'https://example.com:8080',
//   protocol: 'https:',
//   username: '',
//   password: '',
//   host: 'example.com:8080',
//   hostname: 'example.com',
//   port: '8080',
//   pathname: '/path',
//   search: '?query=value',
//   searchParams: URLSearchParams { 'query' => 'value' },
//   hash: '#hash'
// }

// URLSearchParams for query string manipulation
const params = new URLSearchParams('key1=value1&key2=value2');
console.log(params.toString()); // key1=value1&key2=value2
console.log(params.get('key1')); // value1
params.append('key3', 'value3');
params.delete('key2');
console.log(params.toString()); // key1=value1&key3=value3

// URL resolution
console.log(url.resolve('https://example.com/foo/bar', '../baz'));
// https://example.com/baz

console.log(url.resolve('https://example.com/foo/bar', '/baz'));
// https://example.com/baz

// Format URL from components
const formatted = url.format({
  protocol: 'https',
  hostname: 'example.com',
  port: 8080,
  pathname: '/path',
  query: { search: 'term' },
  hash: 'section'
});
console.log(formatted); // https://example.com:8080/path?search=term#section
```

**Advanced URL Operations:**
```javascript
const { URL, URLSearchParams } = require('url');

class URLUtils {
  // Parse URL with validation
  static parseSafe(urlString, baseURL) {
    try {
      return new URL(urlString, baseURL);
    } catch (error) {
      if (error.code === 'ERR_INVALID_URL') {
        throw new Error(`Invalid URL: ${urlString}`);
      }
      throw error;
    }
  }
  
  // Normalize URL (remove duplicate slashes, default ports, etc.)
  static normalize(urlString) {
    const url = new URL(urlString);
    
    // Remove default ports
    if ((url.protocol === 'http:' && url.port === '80') ||
        (url.protocol === 'https:' && url.port === '443')) {
      url.port = '';
    }
    
    // Normalize path
    url.pathname = this.normalizePath(url.pathname);
    
    // Sort query parameters
    const params = new URLSearchParams(url.search);
    const sortedParams = new URLSearchParams();
    
    // Get all keys, sort them
    const keys = Array.from(params.keys()).sort();
    
    // Re-add parameters in sorted order
    keys.forEach(key => {
      params.getAll(key).forEach(value => {
        sortedParams.append(key, value);
      });
    });
    
    url.search = sortedParams.toString();
    
    // Decode then encode for consistency
    url.hash = decodeURIComponent(url.hash);
    url.hash = encodeURI(url.hash);
    
    return url.toString();
  }
  
  static normalizePath(path) {
    // Remove duplicate slashes
    let normalized = path.replace(/\/+/g, '/');
    
    // Resolve . and .. segments
    const segments = normalized.split('/');
    const resolved = [];
    
    for (const segment of segments) {
      if (segment === '..') {
        resolved.pop();
      } else if (segment !== '.' && segment !== '') {
        resolved.push(segment);
      }
    }
    
    // Preserve leading slash for absolute paths
    if (path.startsWith('/')) {
      return '/' + resolved.join('/');
    }
    
    return resolved.join('/');
  }
  
  // Check if URL is within allowed domains
  static isAllowed(urlString, allowedDomains) {
    try {
      const url = new URL(urlString);
      
      // Check domain
      if (allowedDomains.includes(url.hostname)) {
        return true;
      }
      
      // Check subdomains with wildcard
      for (const domain of allowedDomains) {
        if (domain.startsWith('*.') && url.hostname.endsWith(domain.slice(1))) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }
  
  // Extract URL components
  static getComponents(urlString) {
    const url = new URL(urlString);
    
    return {
      scheme: url.protocol.replace(':', ''),
      authority: {
        userinfo: url.username || url.password ? 
          `${url.username}:${url.password}` : null,
        host: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80)
      },
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      fragment: url.hash.replace('#', '')
    };
  }
  
  // Build URL from components
  static buildURL(components) {
    const url = new URL(`${components.scheme}://${components.authority.host}`);
    
    if (components.authority.port) {
      url.port = components.authority.port;
    }
    
    if (components.authority.userinfo) {
      const [username, password] = components.authority.userinfo.split(':');
      url.username = username;
      url.password = password || '';
    }
    
    url.pathname = components.path;
    
    if (components.query) {
      const params = new URLSearchParams();
      Object.entries(components.query).forEach(([key, value]) => {
        if (Array.isArray(value)) {
          value.forEach(v => params.append(key, v));
        } else {
          params.append(key, value);
        }
      });
      url.search = params.toString();
    }
    
    if (components.fragment) {
      url.hash = `#${components.fragment}`;
    }
    
    return url.toString();
  }
  
  // Parse query string to object
  static parseQuery(queryString) {
    const params = new URLSearchParams(queryString);
    const result = {};
    
    for (const [key, value] of params) {
      if (result[key]) {
        if (Array.isArray(result[key])) {
          result[key].push(value);
        } else {
          result[key] = [result[key], value];
        }
      } else {
        result[key] = value;
      }
    }
    
    return result;
  }
  
  // Stringify object to query string
  static stringifyQuery(obj) {
    const params = new URLSearchParams();
    
    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        value.forEach(v => params.append(key, v));
      } else {
        params.append(key, value);
      }
    }
    
    return params.toString();
  }
  
  // Validate URL format
  static validate(urlString, options = {}) {
    const defaultOptions = {
      requireProtocol: true,
      allowedProtocols: ['http:', 'https:', 'ftp:', 'mailto:'],
      requireHostname: true,
      allowIP: true,
      allowLocalhost: true,
      allowCredentials: false
    };
    
    const opts = { ...defaultOptions, ...options };
    
    try {
      const url = new URL(urlString);
      
      // Check protocol
      if (opts.requireProtocol && !opts.allowedProtocols.includes(url.protocol)) {
        return { valid: false, error: 'Protocol not allowed' };
      }
      
      // Check hostname
      if (opts.requireHostname && !url.hostname) {
        return { valid: false, error: 'Hostname required' };
      }
      
      // Check IP addresses
      if (!opts.allowIP && this.isIP(url.hostname)) {
        return { valid: false, error: 'IP addresses not allowed' };
      }
      
      // Check localhost
      if (!opts.allowLocalhost && url.hostname === 'localhost') {
        return { valid: false, error: 'Localhost not allowed' };
      }
      
      // Check credentials
      if (!opts.allowCredentials && (url.username || url.password)) {
        return { valid: false, error: 'Credentials not allowed' };
      }
      
      return { valid: true, url };
      
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }
  
  static isIP(hostname) {
    // Simple IP validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
  }
}

// URL router for parsing and matching routes
class URLRouter {
  constructor() {
    this.routes = new Map();
    this.patterns = new Map();
  }
  
  // Add route with pattern
  add(pattern, handler) {
    // Convert pattern to regex
    const regex = this.patternToRegex(pattern);
    this.routes.set(pattern, { regex, handler });
    
    // Store parameter names
    const paramNames = [];
    const regexString = pattern.replace(/:([^/]+)/g, (match, paramName) => {
      paramNames.push(paramName);
      return '([^/]+)';
    });
    
    this.patterns.set(pattern, { regex: new RegExp(`^${regexString}$`), paramNames });
  }
  
  patternToRegex(pattern) {
    // Convert :param to regex group
    const regexString = pattern
      .replace(/\//g, '\\/')
      .replace(/:([^/]+)/g, '([^/]+)');
    
    return new RegExp(`^${regexString}$`);
  }
  
  // Match URL against routes
  match(url) {
    const urlObj = new URL(url);
    const path = urlObj.pathname;
    
    for (const [pattern, { regex, paramNames }] of this.patterns) {
      const match = path.match(regex);
      
      if (match) {
        const params = {};
        
        // Extract parameters
        paramNames.forEach((name, index) => {
          params[name] = match[index + 1];
        });
        
        // Extract query parameters
        const query = {};
        urlObj.searchParams.forEach((value, key) => {
          if (query[key]) {
            if (Array.isArray(query[key])) {
              query[key].push(value);
            } else {
              query[key] = [query[key], value];
            }
          } else {
            query[key] = value;
          }
        });
        
        return {
          pattern,
          params,
          query,
          url: urlObj,
          path
        };
      }
    }
    
    return null;
  }
  
  // Generate URL from pattern and parameters
  generate(pattern, params = {}, query = {}) {
    if (!this.patterns.has(pattern)) {
      throw new Error(`Pattern not found: ${pattern}`);
    }
    
    let url = pattern;
    
    // Replace parameters
    for (const [key, value] of Object.entries(params)) {
      url = url.replace(`:${key}`, encodeURIComponent(value));
    }
    
    // Add query parameters
    if (Object.keys(query).length > 0) {
      const searchParams = new URLSearchParams();
      
      for (const [key, value] of Object.entries(query)) {
        if (Array.isArray(value)) {
          value.forEach(v => searchParams.append(key, v));
        } else {
          searchParams.append(key, value);
        }
      }
      
      url += `?${searchParams.toString()}`;
    }
    
    return url;
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `url.parse()` and the `URL` class?
2. How do you extract query parameters from a URL?
3. What is `URLSearchParams` and when would you use it?
4. How do you safely validate and parse user-provided URLs?

**Senior Level:**
5. How would you implement URL normalization to prevent duplicate content?
6. Explain how to handle internationalized domain names (IDN) in URLs.
7. How would you implement a URL router with pattern matching?
8. What are the security considerations when working with URLs?

### 🌍 Real-World Scenarios

**Scenario 1: URL Shortener Service**
> Build a URL shortener service that:
> 1. Validates and normalizes URLs
> 2. Generates short codes
> 3. Tracks clicks and analytics
> 4. Handles URL expiration

**Solution:**
```javascript
const { URL, URLSearchParams } = require('url');
const crypto = require('crypto');
const EventEmitter = require('events');

class URLShortener extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      domain: options.domain || 'short.example.com',
      protocol: options.protocol || 'https',
      codeLength: options.codeLength || 6,
      alphabet: options.alphabet || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
      maxAttempts: options.maxAttempts || 3,
      ...options
    };
    
    this.urls = new Map(); // code -> URL data
    this.urlToCode = new Map(); // normalized URL -> code
    this.analytics = new Map(); // code -> analytics data
    this.expiryTimers = new Map();
  }
  
  // Shorten a URL
  async shorten(originalUrl, options = {}) {
    // Validate URL
    const validation = this.validateURL(originalUrl);
    if (!validation.valid) {
      throw new Error(`Invalid URL: ${validation.error}`);
    }
    
    // Normalize URL
    const normalizedUrl = this.normalizeURL(originalUrl);
    
    // Check if already shortened
    if (this.urlToCode.has(normalizedUrl)) {
      const existingCode = this.urlToCode.get(normalizedUrl);
      return this.getShortUrl(existingCode);
    }
    
    // Generate unique code
    const code = await this.generateUniqueCode();
    
    // Store URL data
    const urlData = {
      original: originalUrl,
      normalized: normalizedUrl,
      code,
      createdAt: new Date(),
      expiresAt: options.expiresAt ? new Date(options.expiresAt) : null,
      customCode: options.customCode || null,
      metadata: options.metadata || {},
      clickCount: 0,
      uniqueVisitors: new Set()
    };
    
    this.urls.set(code, urlData);
    this.urlToCode.set(normalizedUrl, code);
    
    // Setup expiry timer if needed
    if (urlData.expiresAt) {
      this.setupExpiryTimer(code, urlData.expiresAt);
    }
    
    // Initialize analytics
    this.analytics.set(code, {
      totalClicks: 0,
      uniqueClicks: 0,
      referrers: new Map(),
      userAgents: new Map(),
      countries: new Map(),
      devices: new Map(),
      browsers: new Map(),
      timestamps: []
    });
    
    this.emit('urlShortened', { code, urlData });
    
    return this.getShortUrl(code);
  }
  
  // Validate URL
  validateURL(urlString) {
    try {
      const url = new URL(urlString);
      
      // Check protocol
      if (!['http:', 'https:'].includes(url.protocol)) {
        return { valid: false, error: 'Only http and https protocols allowed' };
      }
      
      // Check hostname
      if (!url.hostname) {
        return { valid: false, error: 'Hostname required' };
      }
      
      // Check for malicious patterns
      if (this.isMaliciousURL(url)) {
        return { valid: false, error: 'URL appears to be malicious' };
      }
      
      return { valid: true, url };
      
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }
  
  // Check for malicious URLs
  isMaliciousURL(url) {
    const maliciousPatterns = [
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /file:/i,
      /^\/\//, // Protocol-relative URLs
      /^\/[^/]/ // Absolute paths without protocol
    ];
    
    return maliciousPatterns.some(pattern => pattern.test(url.href));
  }
  
  // Normalize URL
  normalizeURL(urlString) {
    const url = new URL(urlString);
    
    // Remove default ports
    if ((url.protocol === 'http:' && url.port === '80') ||
        (url.protocol === 'https:' && url.port === '443')) {
      url.port = '';
    }
    
    // Remove tracking parameters
    const trackingParams = [
      'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
      'fbclid', 'gclid', 'msclkid', 'dclid'
    ];
    
    const params = new URLSearchParams(url.search);
    trackingParams.forEach(param => params.delete(param));
    url.search = params.toString();
    
    // Sort query parameters
    if (url.search) {
      const sortedParams = new URLSearchParams();
      Array.from(params.keys())
        .sort()
        .forEach(key => {
          params.getAll(key).forEach(value => {
            sortedParams.append(key, value);
          });
        });
      url.search = sortedParams.toString();
    }
    
    // Remove trailing slash
    if (url.pathname.endsWith('/') && url.pathname !== '/') {
      url.pathname = url.pathname.slice(0, -1);
    }
    
    // Decode then encode for consistency
    url.hash = decodeURIComponent(url.hash);
    url.hash = encodeURI(url.hash);
    
    return url.toString();
  }
  
  // Generate unique code
  async generateUniqueCode(attempt = 1) {
    if (attempt > this.options.maxAttempts) {
      throw new Error('Failed to generate unique code');
    }
    
    // Generate random code
    let code = '';
    for (let i = 0; i < this.options.codeLength; i++) {
      const randomIndex = Math.floor(Math.random() * this.options.alphabet.length);
      code += this.options.alphabet[randomIndex];
    }
    
    // Check if code already exists
    if (this.urls.has(code)) {
      // Try again with different randomness
      await new Promise(resolve => setTimeout(resolve, 10));
      return this.generateUniqueCode(attempt + 1);
    }
    
    return code;
  }
  
  // Get short URL
  getShortUrl(code) {
    return `${this.options.protocol}://${this.options.domain}/${code}`;
  }
  
  // Resolve short URL
  resolve(code, referrer = null, userAgent = null, ip = null) {
    const urlData = this.urls.get(code);
    
    if (!urlData) {
      throw new Error('Short URL not found');
    }
    
    // Check if expired
    if (urlData.expiresAt && new Date() > urlData.expiresAt) {
      this.deleteUrl(code);
      throw new Error('Short URL has expired');
    }
    
    // Update analytics
    this.updateAnalytics(code, referrer, userAgent, ip);
    
    // Update click count
    urlData.clickCount++;
    if (ip) {
      urlData.uniqueVisitors.add(ip);
    }
    
    this.emit('urlResolved', { code, urlData, referrer, userAgent, ip });
    
    return urlData.original;
  }
  
  // Update analytics
  updateAnalytics(code, referrer, userAgent, ip) {
    const analytics = this.analytics.get(code);
    if (!analytics) return;
    
    analytics.totalClicks++;
    
    // Track unique clicks by IP
    if (ip && !analytics.uniqueIPs) {
      analytics.uniqueIPs = new Set();
    }
    if (ip) {
      if (!analytics.uniqueIPs.has(ip)) {
        analytics.uniqueClicks++;
        analytics.uniqueIPs.add(ip);
      }
    }
    
    // Track referrer
    if (referrer) {
      const count = analytics.referrers.get(referrer) || 0;
      analytics.referrers.set(referrer, count + 1);
    }
    
    // Parse user agent
    if (userAgent) {
      const { device, browser, os } = this.parseUserAgent(userAgent);
      
      // Track device
      if (device) {
        const count = analytics.devices.get(device) || 0;
        analytics.devices.set(device, count + 1);
      }
      
      // Track browser
      if (browser) {
        const count = analytics.browsers.get(browser) || 0;
        analytics.browsers.set(browser, count + 1);
      }
    }
    
    // Track timestamp
    analytics.timestamps.push(new Date());
    
    // Keep only last 1000 timestamps
    if (analytics.timestamps.length > 1000) {
      analytics.timestamps = analytics.timestamps.slice(-1000);
    }
  }
  
  // Parse user agent (simplified)
  parseUserAgent(userAgent) {
    const result = {
      device: 'desktop',
      browser: 'unknown',
      os: 'unknown'
    };
    
    if (/mobile/i.test(userAgent)) {
      result.device = 'mobile';
    } else if (/tablet/i.test(userAgent)) {
      result.device = 'tablet';
    }
    
    if (/chrome/i.test(userAgent)) {
      result.browser = 'chrome';
    } else if (/firefox/i.test(userAgent)) {
      result.browser = 'firefox';
    } else if (/safari/i.test(userAgent)) {
      result.browser = 'safari';
    } else if (/edge/i.test(userAgent)) {
      result.browser = 'edge';
    }
    
    if (/windows/i.test(userAgent)) {
      result.os = 'windows';
    } else if (/mac os/i.test(userAgent)) {
      result.os = 'macos';
    } else if (/linux/i.test(userAgent)) {
      result.os = 'linux';
    } else if (/android/i.test(userAgent)) {
      result.os = 'android';
    } else if (/ios/i.test(userAgent)) {
      result.os = 'ios';
    }
    
    return result;
  }
  
  // Setup expiry timer
  setupExpiryTimer(code, expiresAt) {
    const expiresIn = expiresAt.getTime() - Date.now();
    
    if (expiresIn > 0) {
      const timer = setTimeout(() => {
        this.deleteUrl(code);
      }, expiresIn);
      
      this.expiryTimers.set(code, timer);
    }
  }
  
  // Delete URL
  deleteUrl(code) {
    const urlData = this.urls.get(code);
    if (!urlData) return;
    
    // Clear expiry timer
    const timer = this.expiryTimers.get(code);
    if (timer) {
      clearTimeout(timer);
      this.expiryTimers.delete(code);
    }
    
    // Remove from maps
    this.urls.delete(code);
    this.urlToCode.delete(urlData.normalized);
    this.analytics.delete(code);
    
    this.emit('urlDeleted', { code, urlData });
  }
  
  // Get analytics
  getAnalytics(code, timeframe = 'all') {
    const analytics = this.analytics.get(code);
    if (!analytics) return null;
    
    const now = new Date();
    let filteredTimestamps = analytics.timestamps;
    
    // Filter by timeframe
    if (timeframe !== 'all') {
      let startTime;
      switch (timeframe) {
        case 'day':
          startTime = new Date(now - 24 * 60 * 60 * 1000);
          break;
        case 'week':
          startTime = new Date(now - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'month':
          startTime = new Date(now - 30 * 24 * 60 * 60 * 1000);
          break;
      }
      
      filteredTimestamps = analytics.timestamps.filter(
        timestamp => timestamp > startTime
      );
    }
    
    // Calculate clicks per hour
    const clicksByHour = new Array(24).fill(0);
    filteredTimestamps.forEach(timestamp => {
      const hour = timestamp.getHours();
      clicksByHour[hour]++;
    });
    
    return {
      totalClicks: analytics.totalClicks,
      uniqueClicks: analytics.uniqueClicks,
      referrers: Object.fromEntries(analytics.referrers),
      devices: Object.fromEntries(analytics.devices),
      browsers: Object.fromEntries(analytics.browsers),
      clicksByHour,
      timeframe
    };
  }
  
  // Bulk operations
  bulkShorten(urls) {
    const promises = urls.map(url => 
      this.shorten(url.url, url.options).catch(error => ({
        url: url.url,
        error: error.message,
        success: false
      }))
    );
    
    return Promise.all(promises);
  }
  
  // Cleanup expired URLs
  cleanupExpired() {
    const now = new Date();
    
    for (const [code, urlData] of this.urls) {
      if (urlData.expiresAt && now > urlData.expiresAt) {
        this.deleteUrl(code);
      }
    }
  }
  
  // Get statistics
  getStats() {
    return {
      totalUrls: this.urls.size,
      totalClicks: Array.from(this.analytics.values())
        .reduce((sum, analytics) => sum + analytics.totalClicks, 0),
      uniqueClicks: Array.from(this.analytics.values())
        .reduce((sum, analytics) => sum + analytics.uniqueClicks, 0),
      expiredUrls: Array.from(this.urls.values())
        .filter(url => url.expiresAt && new Date() > url.expiresAt).length
    };
  }
}
```

**Scenario 2: Web Crawler URL Manager**
> Build a URL manager for a web crawler that handles URL normalization, deduplication, and domain restrictions.

**Solution:**
```javascript
const { URL, URLSearchParams } = require('url');
const crypto = require('crypto');
const EventEmitter = require('events');

class CrawlManager extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      maxDepth: options.maxDepth || 3,
      maxUrls: options.maxUrls || 10000,
      allowedDomains: options.allowedDomains || [],
      excludedPatterns: options.excludedPatterns || [],
      respectRobotsTxt: options.respectRobotsTxt !== false,
      requestDelay: options.requestDelay || 1000,
      userAgent: options.userAgent || 'MyCrawler/1.0',
      ...options
    };
    
    this.queue = [];
    this.visited = new Set();
    this.robotsCache = new Map();
    this.domainDelays = new Map();
    this.urlData = new Map(); // url -> {depth, parent, discoveredAt}
    this.stats = {
      discovered: 0,
      crawled: 0,
      blocked: 0,
      errors: 0,
      startedAt: null
    };
  }
  
  // Start crawling
  async start(seedUrls) {
    this.stats.startedAt = new Date();
    
    // Add seed URLs to queue
    for (const url of seedUrls) {
      await this.addToQueue(url, 0, null);
    }
    
    // Start processing
    this.processQueue();
  }
  
  // Add URL to queue
  async addToQueue(urlString, depth, parentUrl) {
    if (depth > this.options.maxDepth) {
      return false;
    }
    
    if (this.visited.size >= this.options.maxUrls) {
      return false;
    }
    
    // Normalize and validate URL
    const normalized = this.normalizeURL(urlString, parentUrl);
    if (!normalized) {
      return false;
    }
    
    // Check if already visited or in queue
    if (this.visited.has(normalized) || this.queue.some(item => item.url === normalized)) {
      return false;
    }
    
    // Check domain restrictions
    if (!this.isAllowedDomain(normalized)) {
      return false;
    }
    
    // Check robots.txt
    if (this.options.respectRobotsTxt && !(await this.checkRobotsTxt(normalized))) {
      this.stats.blocked++;
      return false;
    }
    
    // Check excluded patterns
    if (this.isExcluded(normalized)) {
      return false;
    }
    
    // Add to queue
    this.queue.push({
      url: normalized,
      depth,
      parent: parentUrl,
      discoveredAt: new Date()
    });
    
    this.urlData.set(normalized, {
      depth,
      parent: parentUrl,
      discoveredAt: new Date()
    });
    
    this.stats.discovered++;
    this.emit('urlDiscovered', { url: normalized, depth, parent: parentUrl });
    
    return true;
  }
  
  // Process queue
  async processQueue() {
    while (this.queue.length > 0) {
      const item = this.queue.shift();
      
      // Check if we should delay for this domain
      await this.respectDelay(item.url);
      
      try {
        // Mark as visited
        this.visited.add(item.url);
        
        // Crawl the URL
        const result = await this.crawlUrl(item.url);
        
        // Extract links
        if (result.links && item.depth < this.options.maxDepth) {
          for (const link of result.links) {
            await this.addToQueue(link, item.depth + 1, item.url);
          }
        }
        
        this.stats.crawled++;
        this.emit('urlCrawled', {
          url: item.url,
          depth: item.depth,
          result,
          stats: this.getStats()
        });
        
      } catch (error) {
        this.stats.errors++;
        this.emit('crawlError', {
          url: item.url,
          error: error.message,
          stats: this.getStats()
        });
      }
    }
    
    this.emit('crawlComplete', this.getStats());
  }
  
  // Normalize URL
  normalizeURL(urlString, baseURL = null) {
    try {
      const url = new URL(urlString, baseURL);
      
      // Only crawl http and https
      if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
      }
      
      // Remove fragment
      url.hash = '';
      
      // Remove default ports
      if ((url.protocol === 'http:' && url.port === '80') ||
          (url.protocol === 'https:' && url.port === '443')) {
        url.port = '';
      }
      
      // Remove trailing slash (except for root)
      if (url.pathname.endsWith('/') && url.pathname !== '/') {
        url.pathname = url.pathname.slice(0, -1);
      }
      
      // Convert to lowercase for hostname
      url.hostname = url.hostname.toLowerCase();
      
      return url.toString();
      
    } catch (error) {
      return null;
    }
  }
  
  // Check if domain is allowed
  isAllowedDomain(urlString) {
    if (this.options.allowedDomains.length === 0) {
      return true;
    }
    
    try {
      const url = new URL(urlString);
      
      // Check exact match
      if (this.options.allowedDomains.includes(url.hostname)) {
        return true;
      }
      
      // Check subdomains with wildcard
      for (const domain of this.options.allowedDomains) {
        if (domain.startsWith('*.') && url.hostname.endsWith(domain.slice(1))) {
          return true;
        }
      }
      
      return false;
      
    } catch (error) {
      return false;
    }
  }
  
  // Check robots.txt
  async checkRobotsTxt(urlString) {
    try {
      const url = new URL(urlString);
      const domain = url.origin;
      
      // Check cache
      if (this.robotsCache.has(domain)) {
        const rules = this.robotsCache.get(domain);
        return this.checkRobotsRules(rules, url.pathname);
      }
      
      // Fetch robots.txt
      const robotsUrl = `${domain}/robots.txt`;
      const response = await this.fetchUrl(robotsUrl);
      
      if (response.status === 404) {
        // No robots.txt, allow all
        this.robotsCache.set(domain, { allowAll: true });
        return true;
      }
      
      if (response.status !== 200) {
        // Error fetching robots.txt, be conservative
        return false;
      }
      
      // Parse robots.txt
      const rules = this.parseRobotsTxt(response.body, this.options.userAgent);
      this.robotsCache.set(domain, rules);
      
      return this.checkRobotsRules(rules, url.pathname);
      
    } catch (error) {
      // Error fetching robots.txt, be conservative
      return false;
    }
  }
  
  // Parse robots.txt
  parseRobotsTxt(content, userAgent) {
    const lines = content.split('\n');
    const rules = {
      userAgents: {},
      sitemaps: [],
      crawlDelay: null
    };
    
    let currentUserAgent = null;
    let inRelevantSection = false;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }
      
      const [directive, ...valueParts] = trimmed.split(':');
      const value = valueParts.join(':').trim();
      const normalizedDirective = directive.toLowerCase();
      
      if (normalizedDirective === 'user-agent') {
        currentUserAgent = value.toLowerCase();
        inRelevantSection = currentUserAgent === '*' || 
                           currentUserAgent === userAgent.toLowerCase();
        
        if (inRelevantSection && !rules.userAgents[currentUserAgent]) {
          rules.userAgents[currentUserAgent] = {
            allows: [],
            disallows: []
          };
        }
        
      } else if (normalizedDirective === 'disallow' && inRelevantSection && currentUserAgent) {
        if (value) {
          rules.userAgents[currentUserAgent].disallows.push(value);
        }
        
      } else if (normalizedDirective === 'allow' && inRelevantSection && currentUserAgent) {
        if (value) {
          rules.userAgents[currentUserAgent].allows.push(value);
        }
        
      } else if (normalizedDirective === 'crawl-delay' && inRelevantSection) {
        const delay = parseFloat(value);
        if (!isNaN(delay)) {
          rules.crawlDelay = delay * 1000; // Convert to milliseconds
        }
        
      } else if (normalizedDirective === 'sitemap') {
        rules.sitemaps.push(value);
      }
    }
    
    return rules;
  }
  
  // Check robots rules for a path
  checkRobotsRules(rules, path) {
    if (rules.allowAll) {
      return true;
    }
    
    const userAgent = this.options.userAgent.toLowerCase();
    const agentRules = rules.userAgents['*'] || rules.userAgents[userAgent];
    
    if (!agentRules) {
      return true; // No rules for this user agent
    }
    
    // Check if path is disallowed
    for (const disallow of agentRules.disallows) {
      if (disallow === '/') {
        return false; // Disallow everything
      }
      
      if (disallow && path.startsWith(disallow)) {
        // Check if there's a more specific allow rule
        let allowed = false;
        for (const allow of agentRules.allows) {
          if (allow && path.startsWith(allow)) {
            if (allow.length >= disallow.length) {
              // Allow rule is more specific
              allowed = true;
              break;
            }
          }
        }
        
        if (!allowed) {
          return false;
        }
      }
    }
    
    return true;
  }
  
  // Check if URL matches excluded patterns
  isExcluded(urlString) {
    if (this.options.excludedPatterns.length === 0) {
      return false;
    }
    
    for (const pattern of this.options.excludedPatterns) {
      if (pattern instanceof RegExp) {
        if (pattern.test(urlString)) {
          return true;
        }
      } else if (urlString.includes(pattern)) {
        return true;
      }
    }
    
    return false;
  }
  
  // Respect crawl delay for domain
  async respectDelay(urlString) {
    const url = new URL(urlString);
    const domain = url.hostname;
    
    const lastRequest = this.domainDelays.get(domain);
    const now = Date.now();
    
    if (lastRequest) {
      const timeSinceLastRequest = now - lastRequest;
      const delay = this.getCrawlDelay(domain);
      
      if (timeSinceLastRequest < delay) {
        const waitTime = delay - timeSinceLastRequest;
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
    
    this.domainDelays.set(domain, Date.now());
  }
  
  // Get crawl delay for domain
  getCrawlDelay(domain) {
    const rules = this.robotsCache.get(new URL(`https://${domain}`).origin);
    
    if (rules && rules.crawlDelay) {
      return rules.crawlDelay;
    }
    
    return this.options.requestDelay;
  }
  
  // Crawl a URL (mock implementation)
  async crawlUrl(urlString) {
    // In a real implementation, this would make an HTTP request
    // and parse the HTML content
    
    const mockResponse = {
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: `<html>
        <body>
          <a href="/about">About</a>
          <a href="/contact">Contact</a>
          <a href="https://external.com">External</a>
        </body>
      </html>`,
      links: ['/about', '/contact', 'https://external.com']
    };
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return mockResponse;
  }
  
  // Fetch URL (mock implementation)
  async fetchUrl(urlString) {
    // In a real implementation, this would use http/https module
    
    const mockResponse = {
      status: 200,
      body: `User-agent: *
Disallow: /admin
Allow: /public
Crawl-delay: 2
Sitemap: https://example.com/sitemap.xml`
    };
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return mockResponse;
  }
  
  // Get statistics
  getStats() {
    const now = new Date();
    const elapsed = now - this.stats.startedAt;
    
    return {
      ...this.stats,
      queueSize: this.queue.length,
      visitedSize: this.visited.size,
      elapsedMs: elapsed,
      urlsPerSecond: this.stats.crawled / (elapsed / 1000),
      startedAt: this.stats.startedAt
    };
  }
  
  // Get discovered URLs
  getDiscoveredUrls(filter = {}) {
    const urls = [];
    
    for (const [url, data] of this.urlData) {
      let include = true;
      
      if (filter.domain) {
        const urlObj = new URL(url);
        if (urlObj.hostname !== filter.domain) {
          include = false;
        }
      }
      
      if (filter.minDepth !== undefined && data.depth < filter.minDepth) {
        include = false;
      }
      
      if (filter.maxDepth !== undefined && data.depth > filter.maxDepth) {
        include = false;
      }
      
      if (include) {
        urls.push({
          url,
          ...data
        });
      }
    }
    
    return urls;
  }
  
  // Export/import crawl state
  exportState() {
    return {
      queue: this.queue,
      visited: Array.from(this.visited),
      urlData: Array.from(this.urlData.entries()),
      stats: this.stats,
      options: this.options
    };
  }
  
  importState(state) {
    this.queue = state.queue || [];
    this.visited = new Set(state.visited || []);
    this.urlData = new Map(state.urlData || []);
    this.stats = state.stats || this.stats;
    this.options = { ...this.options, ...state.options };
  }
}
```

---

## 8. crypto

### In-depth Explanation

The `crypto` module provides cryptographic functionality including hashing, encryption, decryption, signing, and verification.

**Key Concepts:**
```javascript
const crypto = require('crypto');

// 1. Hash functions
const hash = crypto.createHash('sha256');
hash.update('some data to hash');
console.log('SHA256:', hash.digest('hex'));

// 2. HMAC (Hash-based Message Authentication Code)
const secret = 'my-secret-key';
const hmac = crypto.createHmac('sha256', secret);
hmac.update('some data to authenticate');
console.log('HMAC:', hmac.digest('hex'));

// 3. Random bytes
const randomBytes = crypto.randomBytes(32);
console.log('Random bytes:', randomBytes.toString('hex'));

// 4. Symmetric encryption
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

const cipher = crypto.createCipheriv(algorithm, key, iv);
let encrypted = cipher.update('secret message', 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log('Encrypted:', encrypted);

const decipher = crypto.createDecipheriv(algorithm, key, iv);
let decrypted = decipher.update(encrypted, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log('Decrypted:', decrypted);

// 5. Asymmetric encryption (RSA)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const data = 'secret data';
const encryptedRSA = crypto.publicEncrypt(publicKey, Buffer.from(data));
const decryptedRSA = crypto.privateDecrypt(privateKey, encryptedRSA);
console.log('RSA Decrypted:', decryptedRSA.toString());

// 6. Signing and verification
const sign = crypto.createSign('SHA256');
sign.update(data);
sign.end();
const signature = sign.sign(privateKey, 'hex');

const verify = crypto.createVerify('SHA256');
verify.update(data);
verify.end();
const isValid = verify.verify(publicKey, signature, 'hex');
console.log('Signature valid:', isValid);

// 7. Password hashing (PBKDF2)
const password = 'my-password';
const salt = crypto.randomBytes(16);
crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedKey) => {
  if (err) throw err;
  console.log('PBKDF2 hash:', derivedKey.toString('hex'));
});

// 8. Timing safe comparison
const a = 'value1';
const b = 'value2';
console.log('Timing safe equal:', crypto.timingSafeEqual(
  Buffer.from(a),
  Buffer.from(b)
));
```

**Advanced Crypto Operations:**
```javascript
const crypto = require('crypto');

class CryptoService {
  constructor() {
    this.keyCache = new Map();
    this.nonceCache = new Map();
  }
  
  // Generate secure random string
  generateRandomString(length, charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') {
    const randomBytes = crypto.randomBytes(length);
    let result = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = randomBytes[i] % charset.length;
      result += charset[randomIndex];
    }
    
    return result;
  }
  
  // Generate secure token
  generateToken(byteLength = 32, encoding = 'base64url') {
    return crypto.randomBytes(byteLength).toString(encoding);
  }
  
  // Hash with salt
  async hashWithSalt(data, saltLength = 16, iterations = 100000, keyLength = 64, algorithm = 'sha512') {
    const salt = crypto.randomBytes(saltLength);
    
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(data, salt, iterations, keyLength, algorithm, (err, derivedKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({
            hash: derivedKey.toString('hex'),
            salt: salt.toString('hex'),
            iterations,
            keyLength,
            algorithm
          });
        }
      });
    });
  }
  
  // Verify hash with salt
  async verifyHash(data, hash, salt, iterations = 100000, keyLength = 64, algorithm = 'sha512') {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(data, Buffer.from(salt, 'hex'), iterations, keyLength, algorithm, (err, derivedKey) => {
        if (err) {
          reject(err);
        } else {
          resolve(crypto.timingSafeEqual(derivedKey, Buffer.from(hash, 'hex')));
        }
      });
    });
  }
  
  // Symmetric encryption with authenticated encryption
  async encryptSymmetric(plaintext, key, additionalData = null) {
    // Generate random IV
    const iv = crypto.randomBytes(12); // 96 bits for GCM
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Add additional authenticated data if provided
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData));
    }
    
    // Encrypt
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Get authentication tag
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted.toString('hex'),
      authTag: authTag.toString('hex'),
      additionalData: additionalData
    };
  }
  
  // Symmetric decryption with authentication
  async decryptSymmetric(encryptedData, key) {
    const { iv, encrypted, authTag, additionalData } = encryptedData;
    
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(iv, 'hex')
    );
    
    // Set authentication tag
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    // Add additional authenticated data if provided
    if (additionalData) {
      decipher.setAAD(Buffer.from(additionalData));
    }
    
    let decrypted = decipher.update(Buffer.from(encrypted, 'hex'), 'utf8');
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted.toString('utf8');
  }
  
  // Generate key pair with metadata
  generateKeyPair(type = 'rsa', options = {}) {
    const defaultOptions = {
      rsa: {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: '' }
      },
      ec: {
        namedCurve: 'secp256k1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'sec1', format: 'pem' }
      },
      ed25519: {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }
    };
    
    const keyOptions = defaultOptions[type] || defaultOptions.rsa;
    const mergedOptions = { ...keyOptions, ...options };
    
    const { publicKey, privateKey } = crypto.generateKeyPairSync(type, mergedOptions);
    
    // Generate key ID (fingerprint)
    const publicKeyHash = crypto.createHash('sha256').update(publicKey).digest('hex');
    const keyId = publicKeyHash.slice(0, 16);
    
    return {
      publicKey,
      privateKey,
      keyId,
      type,
      generatedAt: new Date(),
      metadata: {
        modulusLength: type === 'rsa' ? mergedOptions.modulusLength : undefined,
        namedCurve: type === 'ec' ? mergedOptions.namedCurve : undefined
      }
    };
  }
  
  // Sign data with metadata
  signData(data, privateKey, algorithm = 'SHA256') {
    const sign = crypto.createSign(algorithm);
    sign.update(data);
    sign.end();
    
    const signature = sign.sign(privateKey, 'base64');
    const timestamp = Date.now();
    const nonce = this.generateRandomString(16);
    
    // Create signature metadata
    const signatureData = {
      data: typeof data === 'string' ? data : data.toString('base64'),
      signature,
      algorithm,
      timestamp,
      nonce,
      keyId: this.getKeyIdFromPrivateKey(privateKey)
    };
    
    // Create signature envelope
    const envelope = {
      ...signatureData,
      signature: this.createSignatureEnvelope(signatureData)
    };
    
    return envelope;
  }
  
  // Verify signature with metadata
  verifySignature(envelope, publicKey) {
    try {
      // Extract signature data
      const signatureData = this.parseSignatureEnvelope(envelope.signature);
      
      // Check nonce to prevent replay attacks
      if (this.nonceCache.has(signatureData.nonce)) {
        throw new Error('Nonce reused');
      }
      
      // Check timestamp (prevent old signatures)
      const maxAge = 5 * 60 * 1000; // 5 minutes
      if (Date.now() - signatureData.timestamp > maxAge) {
        throw new Error('Signature too old');
      }
      
      // Verify signature
      const verify = crypto.createVerify(signatureData.algorithm);
      verify.update(Buffer.from(signatureData.data, 'base64'));
      verify.end();
      
      const isValid = verify.verify(publicKey, signatureData.signature, 'base64');
      
      if (isValid) {
        // Cache nonce
        this.nonceCache.set(signatureData.nonce, signatureData.timestamp);
        return { valid: true, data: Buffer.from(signatureData.data, 'base64') };
      }
      
      return { valid: false, reason: 'Invalid signature' };
      
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }
  
  // Create signature envelope
  createSignatureEnvelope(signatureData) {
    const encoded = Buffer.from(JSON.stringify(signatureData)).toString('base64');
    return encoded;
  }
  
  // Parse signature envelope
  parseSignatureEnvelope(envelope) {
    return JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'));
  }
  
  // Get key ID from private key
  getKeyIdFromPrivateKey(privateKey) {
    // Extract public key from private key
    const keyObject = crypto.createPrivateKey(privateKey);
    const publicKey = crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'pem' });
    
    // Generate fingerprint
    return crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
  }
  
  // Generate JWT (JSON Web Token)
  generateJWT(payload, privateKey, options = {}) {
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: options.keyId
    };
    
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      ...payload,
      iat: now,
      exp: now + (options.expiresIn || 3600), // Default 1 hour
      nbf: now - (options.notBefore || 0),
      jti: this.generateRandomString(16)
    };
    
    // Encode header and claims
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedClaims = Buffer.from(JSON.stringify(claims)).toString('base64url');
    
    // Create signature
    const data = `${encodedHeader}.${encodedClaims}`;
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    const signature = sign.sign(privateKey, 'base64url');
    
    return `${data}.${signature}`;
  }
  
  // Verify JWT
  verifyJWT(token, publicKey) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      const [encodedHeader, encodedClaims, signature] = parts;
      
      // Verify signature
      const data = `${encodedHeader}.${encodedClaims}`;
      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(data);
      const isValid = verify.verify(publicKey, signature, 'base64url');
      
      if (!isValid) {
        throw new Error('Invalid signature');
      }
      
      // Decode claims
      const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url').toString());
      
      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (claims.exp && now > claims.exp) {
        throw new Error('Token expired');
      }
      
      // Check not before
      if (claims.nbf && now < claims.nbf) {
        throw new Error('Token not yet valid');
      }
      
      return { valid: true, claims };
      
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }
  
  // Generate secure password
  generatePassword(length = 16, options = {}) {
    const {
      uppercase = true,
      lowercase = true,
      numbers = true,
      symbols = true,
      excludeSimilar = true,
      excludeAmbiguous = false
    } = options;
    
    let charset = '';
    const uppercaseChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // Exclude I, O
    const lowercaseChars = 'abcdefghijkmnpqrstuvwxyz'; // Exclude l, o
    const numberChars = '23456789'; // Exclude 0, 1
    const symbolChars = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    
    if (uppercase) charset += uppercaseChars;
    if (lowercase) charset += lowercaseChars;
    if (numbers) charset += numberChars;
    if (symbols) charset += symbolChars;
    
    if (charset.length === 0) {
      throw new Error('At least one character set must be enabled');
    }
    
    // Generate password
    let password = '';
    const randomBytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      const randomIndex = randomBytes[i] % charset.length;
      password += charset[randomIndex];
    }
    
    // Ensure password meets requirements
    const requirements = [];
    if (uppercase) requirements.push(/[A-Z]/);
    if (lowercase) requirements.push(/[a-z]/);
    if (numbers) requirements.push(/[0-9]/);
    if (symbols) requirements.push(/[^A-Za-z0-9]/);
    
    let attempts = 0;
    const maxAttempts = 100;
    
    while (attempts < maxAttempts) {
      let meetsAllRequirements = true;
      
      for (const regex of requirements) {
        if (!regex.test(password)) {
          meetsAllRequirements = false;
          break;
        }
      }
      
      if (meetsAllRequirements) {
        break;
      }
      
      // Regenerate one character
      const replaceIndex = Math.floor(Math.random() * length);
      const randomByte = crypto.randomBytes(1)[0];
      const charIndex = randomByte % charset.length;
      
      password = password.substring(0, replaceIndex) + 
                charset[charIndex] + 
                password.substring(replaceIndex + 1);
      
      attempts++;
    }
    
    return password;
  }
  
  // Cleanup expired nonces
  cleanupNonces(maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    
    for (const [nonce, timestamp] of this.nonceCache) {
      if (now - timestamp > maxAge) {
        this.nonceCache.delete(nonce);
      }
    }
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between hashing and encryption?
2. How does HMAC differ from regular hashing?
3. When would you use symmetric vs asymmetric encryption?
4. What is PBKDF2 and why is it used for password hashing?

**Senior Level:**
5. How would you implement a secure authentication system with refresh tokens?
6. Explain the differences between AES-CBC and AES-GCM modes.
7. How would you implement forward secrecy in a messaging application?
8. What are the security considerations when storing cryptographic keys?

### 🌍 Real-World Scenarios

**Scenario 1: Secure File Storage System**
> Build a system that encrypts files before storage and provides secure access controls.

**Solution:**
```javascript
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class SecureFileStorage {
  constructor(storagePath, masterKey) {
    this.storagePath = path.resolve(storagePath);
    this.masterKey = Buffer.from(masterKey, 'hex');
    this.keyCache = new Map();
    this.metadataCache = new Map();
    
    // Ensure storage directory exists
    this.ensureStorageDir();
  }
  
  async ensureStorageDir() {
    try {
      await fs.mkdir(this.storagePath, { recursive: true });
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }
  }
  
  // Store file with encryption
  async storeFile(fileId, fileData, options = {}) {
    const {
      encryptionKey = null,
      metadata = {},
      chunkSize = 64 * 1024, // 64KB chunks
      compress = false
    } = options;
    
    // Generate file-specific encryption key
    const fileKey = encryptionKey || this.generateFileKey(fileId);
    
    // Prepare metadata
    const fileMetadata = {
      fileId,
      size: fileData.length,
      chunkSize,
      compressed: compress,
      algorithm: 'aes-256-gcm',
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      ...metadata
    };
    
    // Encrypt metadata
    const encryptedMetadata = await this.encryptMetadata(fileMetadata, fileKey);
    
    // Store metadata
    await this.storeMetadata(fileId, encryptedMetadata);
    
    // Encrypt and store file in chunks
    const totalChunks = Math.ceil(fileData.length / chunkSize);
    const chunkPromises = [];
    
    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      const start = chunkIndex * chunkSize;
      const end = Math.min(start + chunkSize, fileData.length);
      const chunk = fileData.slice(start, end);
      
      chunkPromises.push(
        this.storeChunk(fileId, chunkIndex, chunk, fileKey, options)
      );
    }
    
    await Promise.all(chunkPromises);
    
    // Cache metadata
    this.metadataCache.set(fileId, fileMetadata);
    
    return {
      fileId,
      size: fileData.length,
      chunks: totalChunks,
      key: fileKey.toString('hex')
    };
  }
  
  // Retrieve file
  async retrieveFile(fileId, decryptionKey = null) {
    // Retrieve metadata
    const encryptedMetadata = await this.retrieveMetadata(fileId);
    const metadata = await this.decryptMetadata(encryptedMetadata, decryptionKey);
    
    // Get file key
    const fileKey = decryptionKey || this.getFileKey(fileId);
    
    // Retrieve and decrypt chunks
    const chunks = [];
    
    for (let chunkIndex = 0; chunkIndex < metadata.chunks; chunkIndex++) {
      const chunk = await this.retrieveChunk(fileId, chunkIndex, fileKey, metadata);
      chunks.push(chunk);
    }
    
    // Combine chunks
    const fileData = Buffer.concat(chunks);
    
    return {
      data: fileData,
      metadata
    };
  }
  
  // Store file chunk
  async storeChunk(fileId, chunkIndex, chunkData, fileKey, options) {
    const chunkPath = this.getChunkPath(fileId, chunkIndex);
    
    // Compress if requested
    let dataToEncrypt = chunkData;
    if (options.compress) {
      const zlib = require('zlib');
      dataToEncrypt = await new Promise((resolve, reject) => {
        zlib.deflate(chunkData, (err, compressed) => {
          if (err) reject(err);
          else resolve(compressed);
        });
      });
    }
    
    // Encrypt chunk
    const encrypted = await this.encryptData(dataToEncrypt, fileKey);
    
    // Add chunk metadata
    const chunkMetadata = {
      index: chunkIndex,
      originalSize: chunkData.length,
      encryptedSize: encrypted.encrypted.length,
      compressed: options.compress,
      iv: encrypted.iv,
      authTag: encrypted.authTag
    };
    
    // Combine metadata and encrypted data
    const chunkFileData = Buffer.concat([
      Buffer.from(JSON.stringify(chunkMetadata)),
      Buffer.from('\n\n'), // Separator
      Buffer.from(encrypted.encrypted, 'hex')
    ]);
    
    // Write to file
    await fs.writeFile(chunkPath, chunkFileData);
  }
  
  // Retrieve file chunk
  async retrieveChunk(fileId, chunkIndex, fileKey, metadata) {
    const chunkPath = this.getChunkPath(fileId, chunkIndex);
    
    try {
      const chunkFileData = await fs.readFile(chunkPath);
      
      // Split metadata and encrypted data
      const separator = Buffer.from('\n\n');
      const separatorIndex = chunkFileData.indexOf(separator);
      
      if (separatorIndex === -1) {
        throw new Error('Invalid chunk format');
      }
      
      const metadataPart = chunkFileData.slice(0, separatorIndex);
      const encryptedPart = chunkFileData.slice(separatorIndex + separator.length);
      
      const chunkMetadata = JSON.parse(metadataPart.toString());
      
      // Decrypt chunk
      const decrypted = await this.decryptData({
        encrypted: encryptedPart.toString('hex'),
        iv: chunkMetadata.iv,
        authTag: chunkMetadata.authTag
      }, fileKey);
      
      // Decompress if needed
      if (chunkMetadata.compressed) {
        const zlib = require('zlib');
        return new Promise((resolve, reject) => {
          zlib.inflate(decrypted, (err, decompressed) => {
            if (err) reject(err);
            else resolve(decompressed);
          });
        });
      }
      
      return decrypted;
      
    } catch (error) {
      throw new Error(`Failed to retrieve chunk ${chunkIndex}: ${error.message}`);
    }
  }
  
  // Encrypt data
  async encryptData(plaintext, key) {
    const iv = crypto.randomBytes(12); // 96 bits for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(plaintext);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }
  
  // Decrypt data
  async decryptData(encryptedData, key) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
  }
  
  // Encrypt metadata
  async encryptMetadata(metadata, fileKey) {
    const metadataString = JSON.stringify(metadata);
    const encrypted = await this.encryptData(Buffer.from(metadataString), fileKey);
    
    return {
      ...encrypted,
      algorithm: 'aes-256-gcm'
    };
  }
  
  // Decrypt metadata
  async decryptMetadata(encryptedMetadata, decryptionKey) {
    const decrypted = await this.decryptData(encryptedMetadata, decryptionKey);
    return JSON.parse(decrypted.toString());
  }
  
  // Store metadata
  async storeMetadata(fileId, encryptedMetadata) {
    const metadataPath = this.getMetadataPath(fileId);
    await fs.writeFile(metadataPath, JSON.stringify(encryptedMetadata, null, 2));
  }
  
  // Retrieve metadata
  async retrieveMetadata(fileId) {
    const metadataPath = this.getMetadataPath(fileId);
    
    try {
      const data = await fs.readFile(metadataPath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`File ${fileId} not found`);
      }
      throw error;
    }
  }
  
  // Generate file-specific key
  generateFileKey(fileId) {
    // Derive key from master key and file ID
    const hmac = crypto.createHmac('sha256', this.masterKey);
    hmac.update(fileId);
    return hmac.digest();
  }
  
  // Get file key from cache or generate
  getFileKey(fileId) {
    if (this.keyCache.has(fileId)) {
      return this.keyCache.get(fileId);
    }
    
    const key = this.generateFileKey(fileId);
    this.keyCache.set(fileId, key);
    return key;
  }
  
  // Path helpers
  getMetadataPath(fileId) {
    return path.join(this.storagePath, `${fileId}.meta`);
  }
  
  getChunkPath(fileId, chunkIndex) {
    const chunkDir = path.join(this.storagePath, fileId);
    return path.join(chunkDir, `chunk_${chunkIndex.toString().padStart(6, '0')}`);
  }
  
  // List files
  async listFiles(filter = {}) {
    try {
      const files = await fs.readdir(this.storagePath);
      const result = [];
      
      for (const file of files) {
        if (file.endsWith('.meta')) {
          const fileId = file.slice(0, -5); // Remove .meta extension
          
          try {
            const encryptedMetadata = await this.retrieveMetadata(fileId);
            const metadata = await this.decryptMetadata(encryptedMetadata, this.getFileKey(fileId));
            
            // Apply filters
            let include = true;
            
            if (filter.minSize && metadata.size < filter.minSize) {
              include = false;
            }
            
            if (filter.maxSize && metadata.size > filter.maxSize) {
              include = false;
            }
            
            if (filter.createdAfter && new Date(metadata.createdAt) < new Date(filter.createdAfter)) {
              include = false;
            }
            
            if (filter.tags && filter.tags.length > 0) {
              const fileTags = metadata.tags || [];
              const hasAllTags = filter.tags.every(tag => fileTags.includes(tag));
              if (!hasAllTags) {
                include = false;
              }
            }
            
            if (include) {
              result.push({
                fileId,
                ...metadata
              });
            }
            
          } catch (error) {
            console.error(`Failed to read metadata for ${fileId}:`, error);
          }
        }
      }
      
      return result;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }
  
  // Delete file
  async deleteFile(fileId) {
    // Delete metadata
    const metadataPath = this.getMetadataPath(fileId);
    await fs.unlink(metadataPath).catch(() => {}); // Ignore if not exists
    
    // Delete chunks directory
    const chunkDir = path.join(this.storagePath, fileId);
    try {
      const chunks = await fs.readdir(chunkDir);
      const deletePromises = chunks.map(chunk => 
        fs.unlink(path.join(chunkDir, chunk))
      );
      await Promise.all(deletePromises);
      await fs.rmdir(chunkDir);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    
    // Clear caches
    this.keyCache.delete(fileId);
    this.metadataCache.delete(fileId);
  }
  
  // Update metadata
  async updateMetadata(fileId, updates) {
    const encryptedMetadata = await this.retrieveMetadata(fileId);
    const metadata = await this.decryptMetadata(encryptedMetadata, this.getFileKey(fileId));
    
    // Update metadata
    const updatedMetadata = {
      ...metadata,
      ...updates,
      modifiedAt: new Date().toISOString()
    };
    
    // Re-encrypt and store
    const updatedEncrypted = await this.encryptMetadata(updatedMetadata, this.getFileKey(fileId));
    await this.storeMetadata(fileId, updatedEncrypted);
    
    // Update cache
    this.metadataCache.set(fileId, updatedMetadata);
    
    return updatedMetadata;
  }
  
  // File operations with access control
  async shareFile(fileId, recipientPublicKey, permissions = ['read']) {
    const fileKey = this.getFileKey(fileId);
    
    // Encrypt file key with recipient's public key
    const encryptedKey = crypto.publicEncrypt(
      recipientPublicKey,
      fileKey
    );
    
    // Create access token
    const accessToken = {
      fileId,
      encryptedKey: encryptedKey.toString('base64'),
      permissions,
      grantedAt: new Date().toISOString(),
      expiresAt: null // No expiration by default
    };
    
    // Sign access token
    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(accessToken));
    const signature = sign.sign(this.masterKey, 'base64');
    
    return {
      ...accessToken,
      signature
    };
  }
  
  // Verify access token
  async verifyAccessToken(accessToken) {
    try {
      // Extract signature
      const { signature, ...tokenData } = accessToken;
      
      // Verify signature
      const verify = crypto.createVerify('SHA256');
      verify.update(JSON.stringify(tokenData));
      const isValid = verify.verify(this.masterKey, signature, 'base64');
      
      if (!isValid) {
        throw new Error('Invalid signature');
      }
      
      // Check expiration
      if (tokenData.expiresAt && new Date(tokenData.expiresAt) < new Date()) {
        throw new Error('Access token expired');
      }
      
      return { valid: true, tokenData };
      
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }
}
```

**Scenario 2: Blockchain-like Merkle Tree Implementation**
> Implement a Merkle tree for verifying data integrity in a distributed system.

**Solution:**
```javascript
const crypto = require('crypto');
const EventEmitter = require('events');

class MerkleTree extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      hashAlgorithm: options.hashAlgorithm || 'sha256',
      doubleHash: options.doubleHash || false,
      leavesPerNode: options.leavesPerNode || 2, // Binary tree by default
      ...options
    };
    
    this.leaves = [];
    this.nodes = [];
    this.root = null;
    this.leafHashes = new Map(); // data -> leaf hash
    this.proofs = new Map(); // leaf index -> proof
  }
  
  // Add data to the tree
  add(data, metadata = {}) {
    const leaf = {
      data,
      hash: this.hashData(data),
      metadata,
      index: this.leaves.length,
      timestamp: Date.now()
    };
    
    this.leaves.push(leaf);
    this.leafHashes.set(data, leaf.hash);
    
    // Invalidate cached proofs
    this.proofs.clear();
    
    this.emit('leafAdded', { leaf, totalLeaves: this.leaves.length });
    
    return leaf;
  }
  
  // Add multiple leaves
  addBatch(dataArray, metadataArray = []) {
    const leaves = [];
    
    dataArray.forEach((data, index) => {
      const metadata = metadataArray[index] || {};
      const leaf = this.add(data, metadata);
      leaves.push(leaf);
    });
    
    return leaves;
  }
  
  // Build the tree
  build() {
    if (this.leaves.length === 0) {
      throw new Error('No leaves to build tree');
    }
    
    // Reset nodes
    this.nodes = [];
    
    // Start with leaf hashes
    let currentLevel = this.leaves.map(leaf => leaf.hash);
    this.nodes.push([...currentLevel]);
    
    // Build tree levels
    while (currentLevel.length > 1) {
      const nextLevel = [];
      
      // Group leaves into nodes
      for (let i = 0; i < currentLevel.length; i += this.options.leavesPerNode) {
        const group = currentLevel.slice(i, i + this.options.leavesPerNode);
        
        // If group is incomplete, pad with last element
        while (group.length < this.options.leavesPerNode) {
          group.push(group[group.length - 1]);
        }
        
        const nodeHash = this.hashNode(group);
        nextLevel.push(nodeHash);
      }
      
      this.nodes.push([...nextLevel]);
      currentLevel = nextLevel;
    }
    
    // Root is the only element in the last level
    this.root = currentLevel[0];
    
    this.emit('treeBuilt', { 
      root: this.root, 
      depth: this.nodes.length,
      leafCount: this.leaves.length 
    });
    
    return this.root;
  }
  
  // Get proof for a leaf
  getProof(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error('Invalid leaf index');
    }
    
    // Check cache
    if (this.proofs.has(leafIndex)) {
      return this.proofs.get(leafIndex);
    }
    
    if (!this.root) {
      throw new Error('Tree not built');
    }
    
    const proof = {
      leafIndex,
      leafHash: this.leaves[leafIndex].hash,
      rootHash: this.root,
      siblings: [],
      positions: [] // 0 = left, 1 = right, etc.
    };
    
    let currentIndex = leafIndex;
    
    // Traverse up the tree
    for (let level = 0; level < this.nodes.length - 1; level++) {
      const levelNodes = this.nodes[level];
      const nodeIndex = Math.floor(currentIndex / this.options.leavesPerNode);
      const groupStart = nodeIndex * this.options.leavesPerNode;
      
      // Get all siblings in the group except the current node
      for (let i = 0; i < this.options.leavesPerNode; i++) {
        const siblingIndex = groupStart + i;
        
        if (siblingIndex !== currentIndex && siblingIndex < levelNodes.length) {
          proof.siblings.push(levelNodes[siblingIndex]);
          proof.positions.push(i);
        }
      }
      
      // Move to parent level
      currentIndex = nodeIndex;
    }
    
    // Cache the proof
    this.proofs.set(leafIndex, proof);
    
    return proof;
  }
  
  // Verify proof
  verifyProof(proof) {
    const { leafHash, siblings, positions, rootHash } = proof;
    
    let currentHash = leafHash;
    
    // Reconstruct the tree from bottom up
    for (let i = 0; i < siblings.length; i += this.options.leavesPerNode - 1) {
      const groupSiblings = siblings.slice(i, i + this.options.leavesPerNode - 1);
      const groupPositions = positions.slice(i, i + this.options.leavesPerNode - 1);
      
      // Reconstruct the group
      const group = new Array(this.options.leavesPerNode);
      
      // Place current hash in its position
      let currentPos = 0;
      if (groupPositions.length > 0) {
        // Find the missing position (where current hash goes)
        const allPositions = [...groupPositions, currentPos].sort((a, b) => a - b);
        for (let j = 0; j < allPositions.length; j++) {
          if (allPositions[j] !== j) {
            currentPos = j;
            break;
          }
        }
      }
      
      group[currentPos] = currentHash;
      
      // Fill in siblings
      for (let j = 0; j < groupSiblings.length; j++) {
        const position = groupPositions[j];
        group[position] = groupSiblings[j];
      }
      
      // Hash the group to get parent node
      currentHash = this.hashNode(group);
    }
    
    // Final hash should match root
    return currentHash === rootHash;
  }
  
  // Batch verification
  verifyBatch(proofs) {
    // Verify all proofs share the same root
    const rootHashes = new Set(proofs.map(p => p.rootHash));
    if (rootHashes.size !== 1) {
      return false;
    }
    
    // Verify each proof
    for (const proof of proofs) {
      if (!this.verifyProof(proof)) {
        return false;
      }
    }
    
    return true;
  }
  
  // Update a leaf
  updateLeaf(leafIndex, newData) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error('Invalid leaf index');
    }
    
    const oldLeaf = this.leaves[leafIndex];
    const newHash = this.hashData(newData);
    
    // Update leaf
    this.leaves[leafIndex] = {
      ...oldLeaf,
      data: newData,
      hash: newHash,
      updatedAt: Date.now()
    };
    
    // Update hash map
    this.leafHashes.delete(oldLeaf.data);
    this.leafHashes.set(newData, newHash);
    
    // Invalidate cached proofs
    this.proofs.clear();
    
    // Rebuild tree from the affected node up
    this.rebuildFromLeaf(leafIndex);
    
    this.emit('leafUpdated', { 
      leafIndex, 
      oldHash: oldLeaf.hash, 
      newHash,
      oldData: oldLeaf.data,
      newData 
    });
    
    return this.leaves[leafIndex];
  }
  
  // Rebuild tree from a specific leaf
  rebuildFromLeaf(leafIndex) {
    if (!this.root) {
      return; // Tree wasn't built yet
    }
    
    let currentIndex = leafIndex;
    
    // Update affected nodes bottom-up
    for (let level = 0; level < this.nodes.length; level++) {
      const nodeIndex = Math.floor(currentIndex / this.options.leavesPerNode);
      const groupStart = nodeIndex * this.options.leavesPerNode;
      
      // Get all hashes in the group
      const group = [];
      for (let i = 0; i < this.options.leavesPerNode; i++) {
        const elementIndex = groupStart + i;
        
        if (level === 0) {
          // Leaf level
          if (elementIndex < this.leaves.length) {
            group.push(this.leaves[elementIndex].hash);
          } else if (this.leaves.length > 0) {
            // Pad with last leaf hash
            group.push(this.leaves[this.leaves.length - 1].hash);
          }
        } else {
          // Node level
          if (elementIndex < this.nodes[level - 1].length) {
            group.push(this.nodes[level - 1][elementIndex]);
          } else if (this.nodes[level - 1].length > 0) {
            // Pad with last node hash
            group.push(this.nodes[level - 1][this.nodes[level - 1].length - 1]);
          }
        }
      }
      
      // Calculate new hash for this node
      const newNodeHash = this.hashNode(group);
      this.nodes[level][nodeIndex] = newNodeHash;
      
      // Move to parent level
      currentIndex = nodeIndex;
    }
    
    // Update root
    this.root = this.nodes[this.nodes.length - 1][0];
    
    this.emit('treeUpdated', { root: this.root });
  }
  
  // Delete a leaf
  deleteLeaf(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error('Invalid leaf index');
    }
    
    const deletedLeaf = this.leaves[leafIndex];
    
    // Remove leaf
    this.leaves.splice(leafIndex, 1);
    this.leafHashes.delete(deletedLeaf.data);
    
    // Update indices
    for (let i = leafIndex; i < this.leaves.length; i++) {
      this.leaves[i].index = i;
    }
    
    // Invalidate all cached proofs
    this.proofs.clear();
    
    // Rebuild tree
    if (this.leaves.length > 0) {
      this.build();
    } else {
      this.root = null;
      this.nodes = [];
    }
    
    this.emit('leafDeleted', { 
      leafIndex, 
      deletedLeaf,
      remainingLeaves: this.leaves.length 
    });
    
    return deletedLeaf;
  }
  
  // Hash data
  hashData(data) {
    const hash = crypto.createHash(this.options.hashAlgorithm);
    
    if (typeof data === 'string') {
      hash.update(data);
    } else if (Buffer.isBuffer(data)) {
      hash.update(data);
    } else {
      hash.update(JSON.stringify(data));
    }
    
    let result = hash.digest('hex');
    
    if (this.options.doubleHash) {
      const secondHash = crypto.createHash(this.options.hashAlgorithm);
      secondHash.update(result);
      result = secondHash.digest('hex');
    }
    
    return result;
  }
  
  // Hash a node (group of hashes)
  hashNode(hashes) {
    const hash = crypto.createHash(this.options.hashAlgorithm);
    
    // Sort hashes for deterministic output
    const sortedHashes = [...hashes].sort();
    sortedHashes.forEach(h => hash.update(h));
    
    let result = hash.digest('hex');
    
    if (this.options.doubleHash) {
      const secondHash = crypto.createHash(this.options.hashAlgorithm);
      secondHash.update(result);
      result = secondHash.digest('hex');
    }
    
    return result;
  }
  
  // Get tree statistics
  getStats() {
    return {
      leafCount: this.leaves.length,
      depth: this.nodes.length,
      root: this.root,
      hashAlgorithm: this.options.hashAlgorithm,
      leavesPerNode: this.options.leavesPerNode,
      doubleHash: this.options.doubleHash,
      size: this.calculateSize()
    };
  }
  
  // Calculate approximate memory size
  calculateSize() {
    let size = 0;
    
    // Leaves
    this.leaves.forEach(leaf => {
      size += JSON.stringify(leaf).length;
    });
    
    // Nodes
    this.nodes.forEach(level => {
      size += level.length * 64; // Approximate hash size
    });
    
    // Proofs cache
    for (const proof of this.proofs.values()) {
      size += JSON.stringify(proof).length;
    }
    
    return size;
  }
  
  // Export tree state
  export() {
    return {
      options: this.options,
      leaves: this.leaves.map(leaf => ({
        data: leaf.data,
        hash: leaf.hash,
        metadata: leaf.metadata,
        timestamp: leaf.timestamp
      })),
      nodes: this.nodes,
      root: this.root
    };
  }
  
  // Import tree state
  import(state) {
    this.options = state.options;
    this.leaves = state.leaves.map((leaf, index) => ({
      ...leaf,
      index
    }));
    this.nodes = state.nodes;
    this.root = state.root;
    
    // Rebuild hash map
    this.leafHashes.clear();
    this.leaves.forEach(leaf => {
      this.leafHashes.set(leaf.data, leaf.hash);
    });
    
    // Clear proofs cache
    this.proofs.clear();
  }
  
  // Find leaf by data
  findLeafByData(data) {
    const hash = this.hashData(data);
    return this.leaves.find(leaf => leaf.hash === hash);
  }
  
  // Find leaf by hash
  findLeafByHash(hash) {
    return this.leaves.find(leaf => leaf.hash === hash);
  }
  
  // Check if data exists in tree
  contains(data) {
    const hash = this.hashData(data);
    return this.leafHashes.has(data) || this.leaves.some(leaf => leaf.hash === hash);
  }
  
  // Generate inclusion proof for data
  getInclusionProof(data) {
    const leaf = this.findLeafByData(data);
    if (!leaf) {
      throw new Error('Data not found in tree');
    }
    
    return this.getProof(leaf.index);
  }
  
  // Generate exclusion proof (proof that data is NOT in tree)
  getExclusionProof(data) {
    // For exclusion proof, we need to show that the data's hash
    // would be in a position that doesn't exist or doesn't match
    
    const dataHash = this.hashData(data);
    const leafCount = this.leaves.length;
    
    // Simple exclusion proof for now
    return {
      dataHash,
      leafCount,
      rootHash: this.root,
      message: `Data would be at position ${leafCount} in a tree with ${leafCount} leaves`
    };
  }
}

// Distributed Merkle Tree for synchronization
class DistributedMerkleTree extends MerkleTree {
  constructor(options = {}) {
    super(options);
    this.peers = new Map(); // peerId -> {rootHash, timestamp}
    this.syncQueue = [];
    this.syncing = false;
  }
  
  // Add peer
  addPeer(peerId, initialRootHash = null) {
    this.peers.set(peerId, {
      rootHash: initialRootHash,
      timestamp: Date.now(),
      lastSynced: null,
      status: 'connected'
    });
    
    this.emit('peerAdded', { peerId, rootHash: initialRootHash });
  }
  
  // Remove peer
  removePeer(peerId) {
    const existed = this.peers.delete(peerId);
    if (existed) {
      this.emit('peerRemoved', { peerId });
    }
  }
  
  // Update peer root hash
  updatePeerRoot(peerId, rootHash) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.rootHash = rootHash;
      peer.timestamp = Date.now();
      this.emit('peerUpdated', { peerId, rootHash });
    }
  }
  
  // Sync with peer
  async syncWithPeer(peerId, syncMethod = 'full') {
    if (this.syncing) {
      this.syncQueue.push({ peerId, syncMethod });
      return { queued: true, position: this.syncQueue.length };
    }
    
    this.syncing = true;
    
    try {
      const peer = this.peers.get(peerId);
      if (!peer) {
        throw new Error(`Peer ${peerId} not found`);
      }
      
      this.emit('syncStarted', { peerId, method: syncMethod });
      
      let result;
      
      switch (syncMethod) {
        case 'full':
          result = await this.fullSync(peerId);
          break;
        case 'incremental':
          result = await this.incrementalSync(peerId);
          break;
        case 'optimistic':
          result = await this.optimisticSync(peerId);
          break;
        default:
          throw new Error(`Unknown sync method: ${syncMethod}`);
      }
      
      peer.lastSynced = new Date();
      peer.status = 'synced';
      
      this.emit('syncCompleted', { peerId, result });
      
      return result;
      
    } catch (error) {
      this.emit('syncFailed', { peerId, error: error.message });
      throw error;
      
    } finally {
      this.syncing = false;
      
      // Process next in queue
      if (this.syncQueue.length > 0) {
        const next = this.syncQueue.shift();
        setTimeout(() => this.syncWithPeer(next.peerId, next.syncMethod), 100);
      }
    }
  }
  
  // Full sync - exchange entire tree
  async fullSync(peerId) {
    // In a real implementation, this would communicate with the peer
    // For now, simulate network communication
    
    const peer = this.peers.get(peerId);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Compare root hashes
    if (this.root === peer.rootHash) {
      return { synchronized: true, method: 'full', changes: 0 };
    }
    
    // If our tree is empty, adopt peer's tree
    if (this.leaves.length === 0) {
      // In real implementation, would fetch peer's tree
      return { synchronized: false, method: 'full', action: 'need_to_fetch' };
    }
    
    // If peer's tree is empty, send our tree
    if (!peer.rootHash) {
      // In real implementation, would send our tree
      return { synchronized: false, method: 'full', action: 'need_to_send' };
    }
    
    // Both trees have data, need to reconcile
    return { synchronized: false, method: 'full', action: 'need_reconciliation' };
  }
  
  // Incremental sync - exchange only differences
  async incrementalSync(peerId) {
    const peer = this.peers.get(peerId);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Check if we're already synchronized
    if (this.root === peer.rootHash) {
      return { synchronized: true, method: 'incremental', changes: 0 };
    }
    
    // Generate difference
    const difference = await this.calculateDifference(peerId);
    
    if (difference.additions.length === 0 && difference.removals.length === 0) {
      // Trees are structurally different but contain same data
      this.root = peer.rootHash; // Update root to match
      return { synchronized: true, method: 'incremental', structuralChange: true };
    }
    
    // Apply differences
    const applied = await this.applyDifference(difference);
    
    return {
      synchronized: applied,
      method: 'incremental',
      additions: difference.additions.length,
      removals: difference.removals.length,
      applied
    };
  }
  
  // Optimistic sync - assume peer's tree is more up-to-date
  async optimisticSync(peerId) {
    const peer = this.peers.get(peerId);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Simply adopt peer's root hash
    // In real implementation, would verify with some leaves first
    const oldRoot = this.root;
    this.root = peer.rootHash;
    
    this.emit('rootChanged', { oldRoot, newRoot: this.root, peerId });
    
    return {
      synchronized: true,
      method: 'optimistic',
      oldRoot,
      newRoot: this.root
    };
  }
  
  // Calculate difference between trees
  async calculateDifference(peerId) {
    // In a real implementation, this would compare tree structures
    // For now, return mock differences
    
    return {
      additions: [
        { data: 'new_data_1', hash: this.hashData('new_data_1') },
        { data: 'new_data_2', hash: this.hashData('new_data_2') }
      ],
      removals: [
        { data: 'old_data_1', hash: this.hashData('old_data_1') },
        { data: 'old_data_2', hash: this.hashData('old_data_2') }
      ],
      modifications: [] // Could track modified leaves
    };
  }
  
  // Apply difference to tree
  async applyDifference(difference) {
    try {
      // Remove leaves
      for (const removal of difference.removals) {
        const leaf = this.findLeafByHash(removal.hash);
        if (leaf) {
          this.deleteLeaf(leaf.index);
        }
      }
      
      // Add leaves
      for (const addition of difference.additions) {
        this.add(addition.data);
      }
      
      // Rebuild tree
      if (difference.additions.length > 0 || difference.removals.length > 0) {
        this.build();
      }
      
      return true;
      
    } catch (error) {
      console.error('Failed to apply difference:', error);
      return false;
    }
  }
  
  // Get synchronization status
  getSyncStatus() {
    const status = {
      syncing: this.syncing,
      queueLength: this.syncQueue.length,
      peers: {}
    };
    
    for (const [peerId, peer] of this.peers) {
      status.peers[peerId] = {
        rootHash: peer.rootHash,
        lastSynced: peer.lastSynced,
        status: peer.status,
        inSync: peer.rootHash === this.root
      };
    }
    
    return status;
  }
  
  // Resolve conflicts (when multiple peers have different roots)
  resolveConflicts(strategy = 'majority') {
    const rootCounts = new Map();
    
    // Count occurrences of each root hash
    for (const peer of this.peers.values()) {
      if (peer.rootHash) {
        const count = rootCounts.get(peer.rootHash) || 0;
        rootCounts.set(peer.rootHash, count + 1);
      }
    }
    
    // Add our own root
    if (this.root) {
      const count = rootCounts.get(this.root) || 0;
      rootCounts.set(this.root, count + 1);
    }
    
    let chosenRoot;
    
    switch (strategy) {
      case 'majority':
        // Choose root with most occurrences
        let maxCount = 0;
        for (const [rootHash, count] of rootCounts) {
          if (count > maxCount) {
            maxCount = count;
            chosenRoot = rootHash;
          }
        }
        break;
        
      case 'newest':
        // Choose most recent root (would need timestamps)
        // For now, choose our root
        chosenRoot = this.root;
        break;
        
      case 'oldest':
        // Choose oldest root (most stable)
        // For now, choose first peer's root
        const firstPeer = Array.from(this.peers.values())[0];
        chosenRoot = firstPeer?.rootHash || this.root;
        break;
        
      default:
        chosenRoot = this.root;
    }
    
    // Update all peers to chosen root
    for (const [peerId, peer] of this.peers) {
      peer.rootHash = chosenRoot;
    }
    
    // Update our root if different
    if (this.root !== chosenRoot) {
      const oldRoot = this.root;
      this.root = chosenRoot;
      this.emit('conflictResolved', { oldRoot, newRoot: chosenRoot, strategy });
    }
    
    return chosenRoot;
  }
}
```

---

## 9. stream

### In-depth Explanation

Streams are collections of data — just like arrays or strings — but they don't have to be available all at once. They're especially useful for reading from or writing to sources like files, network connections, or any source of data that comes in chunks.

**Types of Streams:**
1. **Readable**: Data can be read (fs.createReadStream)
2. **Writable**: Data can be written (fs.createWriteStream)
3. **Duplex**: Both readable and writable (net.Socket)
4. **Transform**: Duplex that can modify data (zlib.createGzip)

**Basic Stream Operations:**
```javascript
const fs = require('fs');
const { pipeline, Transform } = require('stream');

// 1. Simple file copy with streams
const readStream = fs.createReadStream('source.txt');
const writeStream = fs.createWriteStream('destination.txt');

readStream.pipe(writeStream);

readStream.on('error', (err) => {
  console.error('Read error:', err);
});

writeStream.on('error', (err) => {
  console.error('Write error:', err);
});

writeStream.on('finish', () => {
  console.log('File copied successfully');
});

// 2. Using pipeline (handles cleanup automatically)
pipeline(
  fs.createReadStream('source.txt'),
  fs.createWriteStream('destination.txt'),
  (err) => {
    if (err) {
      console.error('Pipeline failed:', err);
    } else {
      console.log('Pipeline succeeded');
    }
  }
);

// 3. Transform stream
const uppercaseTransform = new Transform({
  transform(chunk, encoding, callback) {
    this.push(chunk.toString().toUpperCase());
    callback();
  }
});

// 4. Custom readable stream
const { Readable } = require('stream');

class CounterStream extends Readable {
  constructor(max, options) {
    super(options);
    this.max = max;
    this.index = 0;
  }
  
  _read() {
    this.index += 1;
    if (this.index > this.max) {
      this.push(null); // End stream
    } else {
      const buf = Buffer.from(`${this.index}\n`, 'utf8');
      this.push(buf);
    }
  }
}

const counter = new CounterStream(10);
counter.pipe(process.stdout);

// 5. Custom writable stream
const { Writable } = require('stream');

class LoggerStream extends Writable {
  constructor(options) {
    super(options);
    this.logs = [];
  }
  
  _write(chunk, encoding, callback) {
    const message = chunk.toString();
    this.logs.push({
      timestamp: new Date(),
      message: message.trim()
    });
    console.log('Logged:', message.trim());
    callback();
  }
  
  _final(callback) {
    console.log('Total logs:', this.logs.length);
    callback();
  }
}
```

**Advanced Stream Patterns:**
```javascript
const { Readable, Writable, Transform, Duplex, pipeline } = require('stream');
const EventEmitter = require('events');

// 1. Stream multiplexing (multiple streams over one)
class Multiplexer extends Duplex {
  constructor(options) {
    super(options);
    this.streams = new Map(); // id -> {stream, buffer}
    this.nextId = 0;
    this.bufferSize = options.bufferSize || 16384;
  }
  
  addStream(stream) {
    const id = this.nextId++;
    this.streams.set(id, { stream, buffer: Buffer.alloc(0) });
    
    // Forward data from stream to multiplexer
    stream.on('data', (chunk) => {
      this.writeToMultiplex(id, chunk);
    });
    
    stream.on('end', () => {
      this.writeToMultiplex(id, null); // End marker
    });
    
    stream.on('error', (err) => {
      this.destroy(err);
    });
    
    return id;
  }
  
  writeToMultiplex(id, chunk) {
    if (chunk === null) {
      // End of stream
      const header = Buffer.alloc(5);
      header.writeUInt32BE(id, 0);
      header.writeUInt8(1, 4); // 1 = end marker
      this.push(header);
    } else {
      // Data chunk
      const header = Buffer.alloc(9);
      header.writeUInt32BE(id, 0);
      header.writeUInt32BE(chunk.length, 4);
      header.writeUInt8(0, 8); // 0 = data
      
      this.push(Buffer.concat([header, chunk]));
    }
  }
  
  _write(chunk, encoding, callback) {
    // Demultiplex incoming data
    this.demultiplex(chunk);
    callback();
  }
  
  _read(size) {
    // Generate data when requested
    // Data is generated by writeToMultiplex
  }
  
  demultiplex(chunk) {
    let offset = 0;
    
    while (offset < chunk.length) {
      const id = chunk.readUInt32BE(offset);
      offset += 4;
      
      if (offset + 5 > chunk.length) {
        // Incomplete header
        break;
      }
      
      const type = chunk.readUInt8(offset);
      offset += 1;
      
      if (type === 0) {
        // Data chunk
        const length = chunk.readUInt32BE(offset);
        offset += 4;
        
        if (offset + length > chunk.length) {
          // Incomplete data
          break;
        }
        
        const data = chunk.slice(offset, offset + length);
        offset += length;
        
        const streamInfo = this.streams.get(id);
        if (streamInfo) {
          streamInfo.stream.push(data);
        }
      } else if (type === 1) {
        // End marker
        const streamInfo = this.streams.get(id);
        if (streamInfo) {
          streamInfo.stream.push(null);
          this.streams.delete(id);
        }
      }
    }
  }
}

// 2. Stream with backpressure handling
class BackpressureAwareStream extends Transform {
  constructor(options) {
    super({
      highWaterMark: options.highWaterMark || 16384,
      ...options
    });
    
    this.processQueue = [];
    this.processing = false;
    this.paused = false;
    this.stats = {
      processed: 0,
      buffered: 0,
      maxBuffer: 0
    };
  }
  
  _transform(chunk, encoding, callback) {
    this.stats.buffered += chunk.length;
    this.stats.maxBuffer = Math.max(this.stats.maxBuffer, this.stats.buffered);
    
    // Check if we should apply backpressure
    if (this.stats.buffered > this.writableHighWaterMark * 0.8) {
      this.pauseSource();
    }
    
    this.processQueue.push({ chunk, callback });
    
    if (!this.processing) {
      this.processNext();
    }
  }
  
  async processNext() {
    if (this.processQueue.length === 0) {
      this.processing = false;
      return;
    }
    
    this.processing = true;
    const { chunk, callback } = this.processQueue.shift();
    
    try {
      // Simulate async processing
      await this.processChunk(chunk);
      
      this.stats.processed++;
      this.stats.buffered -= chunk.length;
      
      // Resume source if buffer is low
      if (this.paused && this.stats.buffered < this.writableHighWaterMark * 0.3) {
        this.resumeSource();
      }
      
      callback();
      this.processNext();
      
    } catch (error) {
      callback(error);
    }
  }
  
  async processChunk(chunk) {
    // Override this method in subclasses
    this.push(chunk);
  }
  
  pauseSource() {
    if (!this.paused) {
      this.paused = true;
      this.emit('backpressure', { buffered: this.stats.buffered });
    }
  }
  
  resumeSource() {
    if (this.paused) {
      this.paused = false;
      this.emit('resume', { buffered: this.stats.buffered });
    }
  }
  
  getStats() {
    return { ...this.stats, queueLength: this.processQueue.length };
  }
}

// 3. Stream error recovery
class ResilientStream extends Transform {
  constructor(options) {
    super(options);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.errorCount = 0;
    this.buffer = [];
    this.maxBufferSize = options.maxBufferSize || 100;
  }
  
  _transform(chunk, encoding, callback) {
    // Buffer chunk for potential retry
    this.buffer.push({ chunk, encoding });
    
    if (this.buffer.length > this.maxBufferSize) {
      // Drop oldest chunk if buffer is full
      this.buffer.shift();
    }
    
    this.processWithRetry(callback);
  }
  
  async processWithRetry(callback, retryCount = 0) {
    try {
      const { chunk, encoding } = this.buffer[this.buffer.length - 1];
      await this.processChunk(chunk, encoding);
      
      // Success - clear buffer
      this.buffer = [];
      this.errorCount = 0;
      callback();
      
    } catch (error) {
      if (retryCount < this.maxRetries) {
        // Retry after delay
        setTimeout(() => {
          this.processWithRetry(callback, retryCount + 1);
        }, this.retryDelay);
        
        this.emit('retry', { 
          error: error.message, 
          retryCount: retryCount + 1,
          maxRetries: this.maxRetries 
        });
        
      } else {
        // Max retries exceeded
        this.errorCount++;
        this.emit('errorExceeded', { 
          error: error.message, 
          errorCount: this.errorCount 
        });
        
        // Skip this chunk and continue
        this.buffer.pop();
        callback();
      }
    }
  }
  
  async processChunk(chunk, encoding) {
    // Override this method
    // Simulate potential failure
    if (Math.random() < 0.1) {
      throw new Error('Random processing error');
    }
    this.push(chunk);
  }
}

// 4. Stream batching
class BatchStream extends Transform {
  constructor(options) {
    super({
      objectMode: true,
      ...options
    });
    
    this.batchSize = options.batchSize || 100;
    this.batchTimeout = options.batchTimeout || 1000;
    this.currentBatch = [];
    this.timeout = null;
  }
  
  _transform(chunk, encoding, callback) {
    this.currentBatch.push(chunk);
    
    // Clear existing timeout
    if (this.timeout) {
      clearTimeout(this.timeout);
    }
    
    // Check if batch is full
    if (this.currentBatch.length >= this.batchSize) {
      this.flushBatch();
    } else {
      // Set timeout for partial batch
      this.timeout = setTimeout(() => {
        this.flushBatch();
      }, this.batchTimeout);
    }
    
    callback();
  }
  
  _flush(callback) {
    // Flush any remaining items
    if (this.currentBatch.length > 0) {
      this.flushBatch();
    }
    callback();
  }
  
  flushBatch() {
    if (this.currentBatch.length > 0) {
      this.push([...this.currentBatch]);
      this.currentBatch = [];
    }
    
    if (this.timeout) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }
}

// 5. Stream with rate limiting
class RateLimitedStream extends Transform {
  constructor(options) {
    super(options);
    this.rateLimit = options.rateLimit || 1000; // items per second
    this.tokenBucket = options.burstSize || this.rateLimit;
    this.maxTokens = options.burstSize || this.rateLimit;
    this.tokensPerMs = this.rateLimit / 1000;
    this.lastUpdate = Date.now();
    this.queue = [];
    this.processing = false;
  }
  
  _transform(chunk, encoding, callback) {
    this.queue.push({ chunk, encoding, callback });
    
    if (!this.processing) {
      this.processQueue();
    }
  }
  
  updateTokens() {
    const now = Date.now();
    const elapsed = now - this.lastUpdate;
    this.lastUpdate = now;
    
    // Add tokens based on elapsed time
    this.tokenBucket = Math.min(
      this.maxTokens,
      this.tokenBucket + (elapsed * this.tokensPerMs)
    );
  }
  
  async processQueue() {
    if (this.queue.length === 0) {
      this.processing = false;
      return;
    }
    
    this.processing = true;
    this.updateTokens();
    
    if (this.tokenBucket >= 1) {
      // We have tokens, process immediately
      this.tokenBucket -= 1;
      const { chunk, encoding, callback } = this.queue.shift();
      
      try {
        await this.processChunk(chunk, encoding);
        callback();
      } catch (error) {
        callback(error);
      }
      
      // Process next item
      setImmediate(() => this.processQueue());
      
    } else {
      // Wait for tokens
      const waitTime = (1 - this.tokenBucket) / this.tokensPerMs;
      setTimeout(() => {
        this.processQueue();
      }, Math.max(0, waitTime));
    }
  }
  
  async processChunk(chunk, encoding) {
    // Override this method
    this.push(chunk);
  }
  
  getStats() {
    return {
      queueLength: this.queue.length,
      tokenBucket: this.tokenBucket,
      rateLimit: this.rateLimit,
      processing: this.processing
    };
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between `pipe()` and `pipeline()`?
2. How does backpressure work in Node.js streams?
3. When would you use object mode vs buffer mode in streams?
4. What are the different types of streams and their use cases?

**Senior Level:**
5. How would you implement a stream that handles data from multiple sources?
6. Explain how to implement custom backpressure management in a Transform stream.
7. How would you build a streaming API that supports resume on disconnect?
8. What are the memory implications of large buffers in streams?

### 🌍 Real-World Scenarios

**Scenario 1: Real-time Video Processing Pipeline**
> Build a video processing pipeline that handles encoding, watermarking, and streaming.

**Solution:**
```javascript
const { Readable, Writable, Transform, pipeline } = require('stream');
const EventEmitter = require('events');
const crypto = require('crypto');

class VideoProcessingPipeline extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      segmentDuration: options.segmentDuration || 10, // seconds
      maxConcurrent: options.maxConcurrent || 2,
      bufferSize: options.bufferSize || 10,
      ...options
    };
    
    this.segments = new Map();
    this.processingQueue = [];
    this.activeProcesses = 0;
    this.stats = {
      processed: 0,
      failed: 0,
      skipped: 0,
      totalSize: 0
    };
  }
  
  // Process video file
  async processVideo(inputPath, outputDir) {
    const videoId = crypto.randomBytes(8).toString('hex');
    const segments = await this.segmentVideo(inputPath, videoId);
    
    this.emit('segmentationComplete', { videoId, segments: segments.length });
    
    // Process segments in parallel with concurrency control
    const segmentPromises = segments.map((segment, index) => 
      this.processSegmentWithConcurrency(segment, index, videoId, outputDir)
    );
    
    const results = await Promise.allSettled(segmentPromises);
    
    // Collect statistics
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        this.stats.processed++;
        this.stats.totalSize += result.value.size || 0;
      } else {
        this.stats.failed++;
        console.error(`Segment ${index} failed:`, result.reason);
      }
    });
    
    // Generate playlist
    const playlist = await this.generatePlaylist(videoId, outputDir);
    
    this.emit('processingComplete', { 
      videoId, 
      playlist,
      stats: this.stats 
    });
    
    return { videoId, playlist, stats: this.stats };
  }
  
  // Segment video into chunks
  async segmentVideo(inputPath, videoId) {
    // In real implementation, use ffmpeg or similar
    // This is a mock implementation
    
    const fs = require('fs').promises;
    const stats = await fs.stat(inputPath);
    const fileSize = stats.size;
    const segmentCount = Math.ceil(this.options.segmentDuration); // Mock
    
    const segments = [];
    
    for (let i = 0; i < segmentCount; i++) {
      segments.push({
        index: i,
        videoId,
        inputPath,
        startTime: i * this.options.segmentDuration,
        duration: this.options.segmentDuration,
        estimatedSize: Math.floor(fileSize / segmentCount)
      });
    }
    
    return segments;
  }
  
  // Process segment with concurrency control
  async processSegmentWithConcurrency(segment, index, videoId, outputDir) {
    return new Promise((resolve, reject) => {
      this.processingQueue.push({ segment, index, resolve, reject });
      this.processQueue();
    });
  }
  
  // Process queued segments
  async processQueue() {
    if (this.activeProcesses >= this.options.maxConcurrent || 
        this.processingQueue.length === 0) {
      return;
    }
    
    this.activeProcesses++;
    const { segment, index, resolve, reject } = this.processingQueue.shift();
    
    try {
      const result = await this.processSegment(segment, index);
      resolve(result);
    } catch (error) {
      reject(error);
    } finally {
      this.activeProcesses--;
      this.processQueue();
    }
  }
  
  // Process a single segment
  async processSegment(segment, index) {
    this.emit('segmentStart', { segment, index });
    
    // Create processing pipeline
    const startTime = Date.now();
    
    // Mock processing steps
    const processedSegment = await this.applyProcessingSteps(segment);
    
    const processingTime = Date.now() - startTime;
    
    this.emit('segmentComplete', { 
      segment, 
      index, 
      processingTime,
      size: processedSegment.size 
    });
    
    return processedSegment;
  }
  
  // Apply processing steps to segment
  async applyProcessingSteps(segment) {
    // Create processing pipeline
    return new Promise((resolve, reject) => {
      // Mock file streams
      const mockReadStream = this.createMockVideoStream(segment);
      const processingStream = this.createProcessingStream();
      
      let processedData = Buffer.alloc(0);
      
      processingStream.on('data', (chunk) => {
        processedData = Buffer.concat([processedData, chunk]);
      });
      
      processingStream.on('end', () => {
        resolve({
          ...segment,
          data: processedData,
          size: processedData.length,
          processedAt: new Date()
        });
      });
      
      processingStream.on('error', reject);
      
      // Start processing
      mockReadStream.pipe(processingStream);
    });
  }
  
  // Create mock video stream
  createMockVideoStream(segment) {
    const { Readable } = require('stream');
    
    return new Readable({
      read(size) {
        // Generate mock video data
        const chunkSize = Math.min(size, 1024 * 1024); // 1MB chunks
        const totalSize = segment.estimatedSize;
        let bytesSent = 0;
        
        const interval = setInterval(() => {
          if (bytesSent >= totalSize) {
            clearInterval(interval);
            this.push(null); // End stream
            return;
          }
          
          const chunk = crypto.randomBytes(Math.min(chunkSize, totalSize - bytesSent));
          bytesSent += chunk.length;
          
          if (!this.push(chunk)) {
            // Backpressure - stop sending
            clearInterval(interval);
          }
        }, 10); // 10ms delay to simulate reading
        
        this.on('pause', () => clearInterval(interval));
        this.on('resume', () => {
          // Restart reading
          this.createMockVideoStream(segment);
        });
      }
    });
  }
  
  // Create processing stream pipeline
  createProcessingStream() {
    const { Transform, pipeline } = require('stream');
    
    // Create transform streams for each processing step
    const decodeStream = new Transform({
      transform(chunk, encoding, callback) {
        // Mock decoding
        setTimeout(() => {
          callback(null, chunk);
        }, 10);
      }
    });
    
    const watermarkStream = new Transform({
      transform(chunk, encoding, callback) {
        // Mock watermarking
        const watermarked = Buffer.concat([
          Buffer.from('[WATERMARK]'),
          chunk
        ]);
        callback(null, watermarked);
      }
    });
    
    const encodeStream = new Transform({
      transform(chunk, encoding, callback) {
        // Mock encoding
        setTimeout(() => {
          callback(null, chunk);
        }, 15);
      }
    });
    
    // Create a custom transform to combine all steps
    const processingStream = new Transform({
      transform(chunk, encoding, callback) {
        // Process through all steps
        decodeStream.write(chunk);
        
        decodeStream.on('data', (decoded) => {
          watermarkStream.write(decoded);
        });
        
        watermarkStream.on('data', (watermarked) => {
          encodeStream.write(watermarked);
        });
        
        encodeStream.on('data', (encoded) => {
          this.push(encoded);
        });
        
        // Handle completion
        decodeStream.on('end', () => {
          watermarkStream.end();
        });
        
        watermarkStream.on('end', () => {
          encodeStream.end();
        });
        
        encodeStream.on('end', () => {
          callback();
        });
        
        decodeStream.end();
      }
    });
    
    return processingStream;
  }
  
  // Generate playlist file (HLS)
  async generatePlaylist(videoId, outputDir) {
    const playlist = {
      version: 3,
      targetDuration: this.options.segmentDuration,
      mediaSequence: 0,
      segments: []
    };
    
    for (let i = 0; i < this.stats.processed; i++) {
      playlist.segments.push({
        duration: this.options.segmentDuration,
        title: `Segment ${i}`,
        uri: `${videoId}_segment_${i}.ts`
      });
    }
    
    // Generate playlist content
    const playlistContent = this.formatPlaylist(playlist);
    const playlistPath = `${outputDir}/${videoId}.m3u8`;
    
    const fs = require('fs').promises;
    await fs.writeFile(playlistPath, playlistContent, 'utf8');
    
    return playlistPath;
  }
  
  formatPlaylist(playlist) {
    let content = '#EXTM3U\n';
    content += '#EXT-X-VERSION:3\n';
    content += `#EXT-X-TARGETDURATION:${playlist.targetDuration}\n`;
    content += `#EXT-X-MEDIA-SEQUENCE:${playlist.mediaSequence}\n\n`;
    
    playlist.segments.forEach(segment => {
      content += `#EXTINF:${segment.duration.toFixed(3)},\n`;
      content += `${segment.uri}\n`;
    });
    
    content += '\n#EXT-X-ENDLIST\n';
    
    return content;
  }
  
  // Live streaming support
  createLiveStream(videoId) {
    const { Readable, Transform } = require('stream');
    
    let currentSegment = 0;
    const buffer = [];
    const subscribers = new Set();
    
    // Source stream (simulated)
    const sourceStream = new Readable({
      read(size) {
        // Generate live data
        const chunk = crypto.randomBytes(size);
        this.push(chunk);
      }
    });
    
    // Segment stream
    const segmentStream = new Transform({
      transform(chunk, encoding, callback) {
        buffer.push(chunk);
        
        // Check if we have enough data for a segment
        const bufferSize = buffer.reduce((sum, c) => sum + c.length, 0);
        const targetSize = 1024 * 1024 * this.options.segmentDuration; // 1MB per second
        
        if (bufferSize >= targetSize) {
          const segmentData = Buffer.concat(buffer);
          buffer.length = 0; // Clear buffer
          
          // Create segment
          const segment = {
            index: currentSegment++,
            data: segmentData,
            timestamp: Date.now(),
            duration: this.options.segmentDuration
          };
          
          // Notify subscribers
          this.emit('segment', segment);
          
          // Also push through the stream
          this.push(segmentData);
        }
        
        callback();
      },
      flush(callback) {
        // Flush remaining data
        if (buffer.length > 0) {
          const segmentData = Buffer.concat(buffer);
          this.push(segmentData);
        }
        callback();
      }
    });
    
    // Subscribe to segments
    segmentStream.on('segment', (segment) => {
      subscribers.forEach(subscriber => {
        subscriber(segment);
      });
    });
    
    // Pipe source to segmenter
    sourceStream.pipe(segmentStream);
    
    return {
      stream: segmentStream,
      subscribe: (callback) => {
        subscribers.add(callback);
        return () => subscribers.delete(callback);
      },
      videoId,
      startTime: Date.now()
    };
  }
  
  // Get pipeline statistics
  getStatistics() {
    return {
      ...this.stats,
      activeProcesses: this.activeProcesses,
      queueLength: this.processingQueue.length,
      segmentsInProgress: this.segments.size
    };
  }
  
  // Cleanup resources
  async cleanup() {
    this.processingQueue = [];
    this.activeProcesses = 0;
    this.segments.clear();
  }
}
```

**Scenario 2: Distributed Log Aggregator**
> Build a system that collects logs from multiple sources, processes them in real-time, and distributes to multiple outputs.

**Solution:**
```javascript
const { Readable, Writable, Transform, pipeline, PassThrough } = require('stream');
const EventEmitter = require('events');
const crypto = require('crypto');

class LogAggregator extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      batchSize: options.batchSize || 100,
      flushInterval: options.flushInterval || 1000,
      maxBufferSize: options.maxBufferSize || 10000,
      retryAttempts: options.retryAttempts || 3,
      ...options
    };
    
    this.sources = new Map(); // sourceId -> {stream, metadata}
    this.processors = new Map(); // processorId -> {transform, metadata}
    this.outputs = new Map(); // outputId -> {stream, metadata}
    this.buffer = [];
    this.isFlushing = false;
    this.metrics = {
      received: 0,
      processed: 0,
      failed: 0,
      buffered: 0,
      throughput: 0
    };
    
    this.startMetricsCollection();
    this.startBufferFlush();
  }
  
  // Add log source
  addSource(sourceId, sourceStream, metadata = {}) {
    if (this.sources.has(sourceId)) {
      throw new Error(`Source ${sourceId} already exists`);
    }
    
    const sourceInfo = {
      stream: sourceStream,
      metadata: {
        id: sourceId,
        type: metadata.type || 'unknown',
        tags: metadata.tags || [],
        ...metadata
      },
      metrics: {
        received: 0,
        lastReceived: null
      }
    };
    
    // Set up source stream handling
    sourceStream.on('data', (chunk) => {
      this.handleLogEntry(sourceId, chunk, sourceInfo.metadata);
    });
    
    sourceStream.on('error', (error) => {
      this.emit('sourceError', { sourceId, error });
    });
    
    sourceStream.on('end', () => {
      this.emit('sourceEnd', { sourceId });
    });
    
    this.sources.set(sourceId, sourceInfo);
    this.emit('sourceAdded', { sourceId, metadata: sourceInfo.metadata });
    
    return sourceId;
  }
  
  // Add log processor
  addProcessor(processorId, transformStream, metadata = {}) {
    if (this.processors.has(processorId)) {
      throw new Error(`Processor ${processorId} already exists`);
    }
    
    const processorInfo = {
      transform: transformStream,
      metadata: {
        id: processorId,
        type: metadata.type || 'transform',
        ...metadata
      },
      metrics: {
        processed: 0,
        errors: 0
      }
    };
    
    // Set up processor error handling
    transformStream.on('error', (error) => {
      processorInfo.metrics.errors++;
      this.emit('processorError', { processorId, error });
    });
    
    this.processors.set(processorId, processorInfo);
    this.emit('processorAdded', { processorId, metadata: processorInfo.metadata });
    
    return processorId;
  }
  
  // Add output destination
  addOutput(outputId, outputStream, metadata = {}) {
    if (this.outputs.has(outputId)) {
      throw new Error(`Output ${outputId} already exists`);
    }
    
    const outputInfo = {
      stream: outputStream,
      metadata: {
        id: outputId,
        type: metadata.type || 'unknown',
        ...metadata
      },
      metrics: {
        sent: 0,
        errors: 0
      }
    };
    
    // Set up output error handling
    outputStream.on('error', (error) => {
      outputInfo.metrics.errors++;
      this.emit('outputError', { outputId, error });
    });
    
    this.outputs.set(outputId, outputInfo);
    this.emit('outputAdded', { outputId, metadata: outputInfo.metadata });
    
    return outputId;
  }
  
  // Handle incoming log entry
  handleLogEntry(sourceId, chunk, sourceMetadata) {
    try {
      const sourceInfo = this.sources.get(sourceId);
      if (!sourceInfo) return;
      
      sourceInfo.metrics.received++;
      sourceInfo.metrics.lastReceived = new Date();
      this.metrics.received++;
      
      // Parse log entry
      const logEntry = this.parseLogEntry(chunk, sourceMetadata);
      
      // Add to buffer
      this.buffer.push(logEntry);
      this.metrics.buffered++;
      
      // Check if buffer needs flushing
      if (this.buffer.length >= this.options.batchSize) {
        this.flushBuffer();
      }
      
      this.emit('logReceived', { sourceId, logEntry });
      
    } catch (error) {
      this.metrics.failed++;
      this.emit('logParseError', { sourceId, chunk, error });
    }
  }
  
  // Parse log entry
  parseLogEntry(chunk, sourceMetadata) {
    let entry;
    
    if (Buffer.isBuffer(chunk)) {
      entry = JSON.parse(chunk.toString('utf8'));
    } else if (typeof chunk === 'string') {
      entry = JSON.parse(chunk);
    } else if (typeof chunk === 'object') {
      entry = chunk;
    } else {
      throw new Error('Unsupported log format');
    }
    
    return {
      id: crypto.randomBytes(8).toString('hex'),
      timestamp: new Date().toISOString(),
      source: sourceMetadata.id,
      sourceType: sourceMetadata.type,
      tags: sourceMetadata.tags,
      data: entry,
      receivedAt: Date.now(),
      metadata: {
        size: Buffer.byteLength(JSON.stringify(entry)),
        format: 'json'
      }
    };
  }
  
  // Start buffer flush interval
  startBufferFlush() {
    setInterval(() => {
      if (this.buffer.length > 0 && !this.isFlushing) {
        this.flushBuffer();
      }
    }, this.options.flushInterval);
  }
  
  // Flush buffer to processors
  async flushBuffer() {
    if (this.isFlushing || this.buffer.length === 0) {
      return;
    }
    
    this.isFlushing = true;
    
    try {
      // Take current buffer
      const batch = this.buffer.splice(0, this.options.batchSize);
      this.metrics.buffered -= batch.length;
      
      // Process batch through processors
      const processedBatch = await this.processBatch(batch);
      
      // Send to outputs
      await this.sendToOutputs(processedBatch);
      
      this.metrics.processed += batch.length;
      
      this.emit('batchProcessed', { 
        batchSize: batch.length,
        processedCount: processedBatch.length
      });
      
    } catch (error) {
      this.emit('batchError', { error: error.message });
      
      // Re-add batch to buffer for retry
      // In production, you might want a dead letter queue
    } finally {
      this.isFlushing = false;
    }
  }
  
  // Process batch through processors
  async processBatch(batch) {
    if (this.processors.size === 0) {
      return batch; // No processors, return as-is
    }
    
    let processedBatch = batch;
    
    // Apply processors in sequence
    for (const [processorId, processorInfo] of this.processors) {
      const processorStream = processorInfo.transform;
      
      processedBatch = await this.applyProcessor(
        processedBatch, 
        processorStream, 
        processorId
      );
      
      processorInfo.metrics.processed += processedBatch.length;
    }
    
    return processedBatch;
  }
  
  // Apply single processor to batch
  applyProcessor(batch, processorStream, processorId) {
    return new Promise((resolve, reject) => {
      const results = [];
      let processedCount = 0;
      
      // Create a readable stream from batch
      const readable = new Readable({
        objectMode: true,
        read() {
          batch.forEach(item => this.push(item));
          this.push(null); // End stream
        }
      });
      
      // Create a writable stream to collect results
      const writable = new Writable({
        objectMode: true,
        write(chunk, encoding, callback) {
          results.push(chunk);
          processedCount++;
          
          if (processedCount === batch.length) {
            callback();
          } else {
            callback();
          }
        }
      });
      
      // Set up pipeline
      pipeline(
        readable,
        processorStream,
        writable,
        (error) => {
          if (error) {
            reject(new Error(`Processor ${processorId} failed: ${error.message}`));
          } else {
            resolve(results);
          }
        }
      );
    });
  }
  
  // Send processed batch to outputs
  async sendToOutputs(batch) {
    if (this.outputs.size === 0) {
      throw new Error('No outputs configured');
    }
    
    const outputPromises = [];
    
    for (const [outputId, outputInfo] of this.outputs) {
      outputPromises.push(
        this.sendToOutput(batch, outputId, outputInfo)
      );
    }
    
    const results = await Promise.allSettled(outputPromises);
    
    // Handle results
    results.forEach((result, index) => {
      const outputId = Array.from(this.outputs.keys())[index];
      const outputInfo = this.outputs.get(outputId);
      
      if (result.status === 'fulfilled') {
        outputInfo.metrics.sent += batch.length;
      } else {
        outputInfo.metrics.errors++;
        this.emit('outputSendError', { 
          outputId, 
          error: result.reason.message 
        });
      }
    });
  }
  
  // Send batch to specific output
  async sendToOutput(batch, outputId, outputInfo) {
    return new Promise((resolve, reject) => {
      const outputStream = outputInfo.stream;
      
      // Check if output stream is writable
      if (!outputStream.writable) {
        reject(new Error(`Output ${outputId} is not writable`));
        return;
      }
      
      let sentCount = 0;
      
      // Write each item
      batch.forEach((item, index) => {
        const data = JSON.stringify(item) + '\n';
        
        const canWrite = outputStream.write(data, (error) => {
          if (error) {
            reject(error);
          } else {
            sentCount++;
            
            if (sentCount === batch.length) {
              resolve({ outputId, sent: sentCount });
            }
          }
        });
        
        if (!canWrite) {
          // Handle backpressure
          outputStream.once('drain', () => {
            // Resume writing
            // In a real implementation, you might want to retry
          });
        }
      });
      
      // If batch is empty
      if (batch.length === 0) {
        resolve({ outputId, sent: 0 });
      }
    });
  }
  
  // Create custom processors
  static createFilterProcessor(filterFn) {
    return new Transform({
      objectMode: true,
      transform(chunk, encoding, callback) {
        try {
          if (filterFn(chunk)) {
            callback(null, chunk);
          } else {
            callback(); // Skip this entry
          }
        } catch (error) {
          callback(error);
        }
      }
    });
  }
  
  static createTransformProcessor(transformFn) {
    return new Transform({
      objectMode: true,
      transform(chunk, encoding, callback) {
        try {
          const transformed = transformFn(chunk);
          callback(null, transformed);
        } catch (error) {
          callback(error);
        }
      }
    });
  }
  
  static createAggregateProcessor(aggregateFn, windowSize = 100) {
    let buffer = [];
    
    return new Transform({
      objectMode: true,
      transform(chunk, encoding, callback) {
        buffer.push(chunk);
        
        if (buffer.length >= windowSize) {
          try {
            const aggregated = aggregateFn(buffer);
            buffer = []; // Clear buffer
            callback(null, aggregated);
          } catch (error) {
            callback(error);
          }
        } else {
          callback(); // Wait for more data
        }
      },
      flush(callback) {
        // Flush remaining data
        if (buffer.length > 0) {
          try {
            const aggregated = aggregateFn(buffer);
            callback(null, aggregated);
          } catch (error) {
            callback(error);
          }
        } else {
          callback();
        }
      }
    });
  }
  
  // Start metrics collection
  startMetricsCollection() {
    setInterval(() => {
      // Calculate throughput
      const now = Date.now();
      const timeWindow = 60000; // 1 minute
      
      // This would track throughput over time in a real implementation
      this.metrics.throughput = this.metrics.processed / (timeWindow / 1000);
      
      this.emit('metrics', { ...this.metrics });
    }, 5000);
  }
  
  // Get aggregator status
  getStatus() {
    return {
      sources: this.sources.size,
      processors: this.processors.size,
      outputs: this.outputs.size,
      bufferSize: this.buffer.length,
      isFlushing: this.isFlushing,
      metrics: { ...this.metrics }
    };
  }
  
  // Get detailed metrics
  getDetailedMetrics() {
    const sourceMetrics = {};
    for (const [sourceId, sourceInfo] of this.sources) {
      sourceMetrics[sourceId] = { ...sourceInfo.metrics };
    }
    
    const processorMetrics = {};
    for (const [processorId, processorInfo] of this.processors) {
      processorMetrics[processorId] = { ...processorInfo.metrics };
    }
    
    const outputMetrics = {};
    for (const [outputId, outputInfo] of this.outputs) {
      outputMetrics[outputId] = { ...outputInfo.metrics };
    }
    
    return {
      sources: sourceMetrics,
      processors: processorMetrics,
      outputs: outputMetrics,
      aggregator: this.metrics
    };
  }
  
  // Cleanup resources
  async cleanup() {
    // Close all sources
    for (const [sourceId, sourceInfo] of this.sources) {
      if (typeof sourceInfo.stream.destroy === 'function') {
        sourceInfo.stream.destroy();
      }
    }
    
    // End all processors
    for (const [processorId, processorInfo] of this.processors) {
      if (typeof processorInfo.transform.end === 'function') {
        processorInfo.transform.end();
      }
    }
    
    // End all outputs
    for (const [outputId, outputInfo] of this.outputs) {
      if (typeof outputInfo.stream.end === 'function') {
        outputInfo.stream.end();
      }
    }
    
    this.sources.clear();
    this.processors.clear();
    this.outputs.clear();
    this.buffer = [];
    
    this.emit('cleanup');
  }
}
```

---

## 10. zlib

### In-depth Explanation

The `zlib` module provides compression and decompression functionality using Gzip, Deflate/Inflate, and Brotli algorithms.

**Basic Compression Operations:**
```javascript
const zlib = require('zlib');
const fs = require('fs');

// 1. Gzip compression
const input = 'Hello, World! This is some text to compress.';
zlib.gzip(input, (err, compressed) => {
  if (err) throw err;
  console.log('Compressed size:', compressed.length);
  
  // Decompress
  zlib.gunzip(compressed, (err, decompressed) => {
    if (err) throw err;
    console.log('Decompressed:', decompressed.toString());
  });
});

// 2. Deflate compression
zlib.deflate(input, (err, compressed) => {
  if (err) throw err;
  zlib.inflate(compressed, (err, decompressed) => {
    if (err) throw err;
    console.log('Deflate/Inflate:', decompressed.toString());
  });
});

// 3. Brotli compression (Node.js 10+)
if (zlib.brotliCompress) {
  zlib.brotliCompress(input, (err, compressed) => {
    if (err) throw err;
    zlib.brotliDecompress(compressed, (err, decompressed) => {
      if (err) throw err;
      console.log('Brotli:', decompressed.toString());
    });
  });
}

// 4. Stream-based compression
const readStream = fs.createReadStream('largefile.txt');
const writeStream = fs.createWriteStream('largefile.txt.gz');
const gzipStream = zlib.createGzip();

readStream.pipe(gzipStream).pipe(writeStream);

// 5. Compression levels and strategies
const deflate = zlib.createDeflate({
  level: zlib.constants.Z_BEST_COMPRESSION, // 9
  memLevel: 9, // Memory usage (1-9)
  strategy: zlib.constants.Z_DEFAULT_STRATEGY
});

// 6. Creating streams with options
const gzip = zlib.createGzip({
  level: 6, // Compression level (0-9)
  chunkSize: 32 * 1024, // 32KB chunks
  windowBits: 15, // Gzip window size
  memLevel: 8, // Memory usage
  strategy: zlib.constants.Z_DEFAULT_STRATEGY
});

// 7. Sync operations (blocking, use carefully)
try {
  const compressed = zlib.gzipSync(input);
  const decompressed = zlib.gunzipSync(compressed);
  console.log('Sync decompressed:', decompressed.toString());
} catch (err) {
  console.error('Sync error:', err);
}
```

**Advanced Compression Patterns:**
```javascript
const zlib = require('zlib');
const { Transform, pipeline } = require('stream');
const crypto = require('crypto');

class AdvancedCompression {
  // Adaptive compression based on content type
  static createAdaptiveCompressor(options = {}) {
    const defaultOptions = {
      textThreshold: 1024, // Compress text larger than this
      binaryThreshold: 4096, // Compress binary larger than this
      minCompressionRatio: 0.9, // Only compress if ratio is better than this
      algorithms: {
        text: 'gzip',
        json: 'gzip',
        binary: 'deflate'
      }
    };
    
    const opts = { ...defaultOptions, ...options };
    
    return new Transform({
      transform(chunk, encoding, callback) {
        // Analyze content
        const isText = this.isTextContent(chunk);
        const size = chunk.length;
        
        let shouldCompress = false;
        let algorithm = 'none';
        
        if (isText) {
          if (size > opts.textThreshold) {
            shouldCompress = true;
            algorithm = opts.algorithms.text;
          }
        } else {
          if (size > opts.binaryThreshold) {
            shouldCompress = true;
            algorithm = opts.algorithms.binary;
          }
        }
        
        if (shouldCompress) {
          this.compressChunk(chunk, algorithm, opts.minCompressionRatio)
            .then(compressed => {
              // Add compression header
              const header = Buffer.from([
                algorithm === 'gzip' ? 0x1F : 
                algorithm === 'deflate' ? 0x78 : 0x00
              ]);
              
              const result = Buffer.concat([header, compressed]);
              callback(null, result);
            })
            .catch(error => {
              // Compression failed, send original
              const header = Buffer.from([0x00]);
              const result = Buffer.concat([header, chunk]);
              callback(null, result);
            });
        } else {
          // No compression
          const header = Buffer.from([0x00]);
          const result = Buffer.concat([header, chunk]);
          callback(null, result);
        }
      }
    });
  }
  
  static isTextContent(buffer) {
    // Simple text detection
    const text = buffer.toString('utf8', 0, Math.min(buffer.length, 1024));
    
    // Check for non-printable characters
    for (let i = 0; i < text.length; i++) {
      const charCode = text.charCodeAt(i);
      if (charCode < 32 && charCode !== 9 && charCode !== 10 && charCode !== 13) {
        return false;
      }
    }
    
    return true;
  }
  
  static async compressChunk(chunk, algorithm, minRatio) {
    return new Promise((resolve, reject) => {
      const compressFn = algorithm === 'gzip' ? zlib.gzip : zlib.deflate;
      
      compressFn(chunk, (error, compressed) => {
        if (error) {
          reject(error);
        } else {
          // Check compression ratio
          const ratio = compressed.length / chunk.length;
          
          if (ratio < minRatio) {
            resolve(compressed);
          } else {
            // Compression didn't help enough
            reject(new Error('Compression ratio too low'));
          }
        }
      });
    });
  }
  
  // Progressive compression (compress in chunks)
  static createProgressiveCompressor(options = {}) {
    const defaultOptions = {
      chunkSize: 64 * 1024, // 64KB chunks
      compressionLevel: 6,
      flushFrequency: 10 // Flush every 10 chunks
    };
    
    const opts = { ...defaultOptions, ...options };
    
    return new Transform({
      transform(chunk, encoding, callback) {
        this.buffer = this.buffer || Buffer.alloc(0);
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.chunkCount = (this.chunkCount || 0) + 1;
        
        // Process if buffer is full or flush frequency reached
        if (this.buffer.length >= opts.chunkSize || 
            this.chunkCount % opts.flushFrequency === 0) {
          
          this.compressBuffer(opts.compressionLevel)
            .then(compressed => {
              this.push(compressed);
              this.buffer = Buffer.alloc(0);
              callback();
            })
            .catch(error => {
              callback(error);
            });
        } else {
          callback();
        }
      },
      
      flush(callback) {
        // Compress any remaining data
        if (this.buffer && this.buffer.length > 0) {
          this.compressBuffer(opts.compressionLevel)
            .then(compressed => {
              this.push(compressed);
              callback();
            })
            .catch(callback);
        } else {
          callback();
        }
      },
      
      async compressBuffer(level) {
        return new Promise((resolve, reject) => {
          zlib.deflate(this.buffer, { level }, (error, compressed) => {
            if (error) {
              reject(error);
            } else {
              // Add chunk metadata
              const metadata = Buffer.alloc(8);
              metadata.writeUInt32BE(this.buffer.length, 0); // Original size
              metadata.writeUInt32BE(compressed.length, 4); // Compressed size
              
              resolve(Buffer.concat([metadata, compressed]));
            }
          });
        });
      }
    });
  }
  
  // Deduplication with compression
  static createDeduplicatingCompressor(options = {}) {
    const defaultOptions = {
      windowSize: 10, // Look back window for duplicates
      minChunkSize: 1024, // Minimum chunk size to consider for deduplication
      hashAlgorithm: 'md5'
    };
    
    const opts = { ...defaultOptions, ...options };
    const chunkCache = new Map();
    const chunkQueue = [];
    
    return new Transform({
      transform(chunk, encoding, callback) {
        if (chunk.length < opts.minChunkSize) {
          // Too small to deduplicate
          this.push(this.createChunkHeader(chunk, false));
          this.push(chunk);
          callback();
          return;
        }
        
        // Create hash of chunk
        const hash = crypto.createHash(opts.hashAlgorithm)
          .update(chunk)
          .digest('hex');
        
        // Check if we've seen this chunk before
        if (chunkCache.has(hash)) {
          // Reference to existing chunk
          const reference = chunkCache.get(hash);
          const header = this.createReferenceHeader(reference);
          this.push(header);
        } else {
          // New chunk
          chunkCache.set(hash, {
            id: chunkCache.size,
            size: chunk.length,
            timestamp: Date.now()
          });
          
          // Add to queue and maintain window size
          chunkQueue.push(hash);
          if (chunkQueue.length > opts.windowSize) {
            const oldHash = chunkQueue.shift();
            chunkCache.delete(oldHash);
          }
          
          this.push(this.createChunkHeader(chunk, true));
          this.push(chunk);
        }
        
        callback();
      },
      
      createChunkHeader(chunk, isNew) {
        const header = Buffer.alloc(9);
        header.writeUInt8(isNew ? 0x01 : 0x00, 0); // Type
        header.writeUInt32BE(chunk.length, 1); // Size
        header.writeUInt32BE(chunkCache.size - 1, 5); // Chunk ID
        return header;
      },
      
      createReferenceHeader(reference) {
        const header = Buffer.alloc(5);
        header.writeUInt8(0x02, 0); // Reference type
        header.writeUInt32BE(reference.id, 1); // Reference ID
        return header;
      }
    });
  }
  
  // Multi-algorithm compression with fallback
  static createMultiAlgorithmCompressor(options = {}) {
    const algorithms = [
      { name: 'brotli', compress: zlib.brotliCompress, level: 11 },
      { name: 'gzip', compress: zlib.gzip, level: 9 },
      { name: 'deflate', compress: zlib.deflate, level: 9 }
    ];
    
    return new Transform({
      async transform(chunk, encoding, callback) {
        let bestResult = null;
        let bestAlgorithm = null;
        
        // Try each algorithm
        for (const algo of algorithms) {
          try {
            const compressed = await this.compressWithAlgorithm(
              chunk, 
              algo.compress, 
              algo.level
            );
            
            if (!bestResult || compressed.length < bestResult.length) {
              bestResult = compressed;
              bestAlgorithm = algo.name;
            }
          } catch (error) {
            // Algorithm failed, continue to next
            continue;
          }
        }
        
        if (bestResult) {
          // Add algorithm identifier
          const algoByte = this.getAlgorithmByte(bestAlgorithm);
          const result = Buffer.concat([
            Buffer.from([algoByte]),
            bestResult
          ]);
          
          this.push(result);
          callback();
        } else {
          // All algorithms failed, send uncompressed with marker
          const result = Buffer.concat([
            Buffer.from([0x00]),
            chunk
          ]);
          
          this.push(result);
          callback();
        }
      },
      
      compressWithAlgorithm(data, compressFn, level) {
        return new Promise((resolve, reject) => {
          compressFn(data, { level }, (error, compressed) => {
            if (error) {
              reject(error);
            } else {
              resolve(compressed);
            }
          });
        });
      },
      
      getAlgorithmByte(algorithm) {
        switch (algorithm) {
          case 'brotli': return 0x01;
          case 'gzip': return 0x02;
          case 'deflate': return 0x03;
          default: return 0x00;
        }
      }
    });
  }
  
  // Compression with encryption
  static createEncryptedCompressor(key, iv, options = {}) {
    const crypto = require('crypto');
    const algorithm = 'aes-256-gcm';
    
    return new Transform({
      transform(chunk, encoding, callback) {
        // First compress
        zlib.gzip(chunk, (error, compressed) => {
          if (error) {
            callback(error);
            return;
          }
          
          // Then encrypt
          const cipher = crypto.createCipheriv(algorithm, key, iv);
          cipher.setAAD(Buffer.from('compressed'));
          
          let encrypted = cipher.update(compressed);
          encrypted = Buffer.concat([encrypted, cipher.final()]);
          const authTag = cipher.getAuthTag();
          
          // Create result with IV and auth tag
          const result = Buffer.concat([
            iv, // 16 bytes
            authTag, // 16 bytes
            encrypted
          ]);
          
          this.push(result);
          callback();
        });
      }
    });
  }
  
  // Decompress with decryption
  static createDecryptedDecompressor(key, options = {}) {
    const crypto = require('crypto');
    const algorithm = 'aes-256-gcm';
    
    return new Transform({
      transform(chunk, encoding, callback) {
        // Extract IV and auth tag
        const iv = chunk.slice(0, 16);
        const authTag = chunk.slice(16, 32);
        const encrypted = chunk.slice(32);
        
        // Decrypt
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAuthTag(authTag);
        decipher.setAAD(Buffer.from('compressed'));
        
        let decrypted;
        try {
          decrypted = decipher.update(encrypted);
          decrypted = Buffer.concat([decrypted, decipher.final()]);
        } catch (error) {
          callback(error);
          return;
        }
        
        // Then decompress
        zlib.gunzip(decrypted, (error, decompressed) => {
          if (error) {
            callback(error);
          } else {
            this.push(decompressed);
            callback();
          }
        });
      }
    });
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What's the difference between Gzip and Deflate compression?
2. When would you use sync vs async compression methods?
3. How do you handle compression errors in a streaming pipeline?
4. What are the trade-offs between compression level and speed?

**Senior Level:**
5. How would you implement adaptive compression based on content type?
6. Explain how to implement compression with deduplication for log files.
7. How would you build a multi-algorithm compressor that picks the best algorithm per chunk?
8. What are the security considerations when compressing user-supplied data?

### 🌍 Real-World Scenarios

**Scenario 1: CDN-style Compression Proxy**
> Build a compression proxy that sits between clients and origin servers, applying optimal compression.

**Solution:**
```javascript
const zlib = require('zlib');
const http = require('http');
const https = require('https');
const { Transform, pipeline } = require('stream');
const crypto = require('crypto');

class CompressionProxy {
  constructor(options = {}) {
    this.options = {
      port: options.port || 8080,
      compressionLevel: options.compressionLevel || 6,
      minSize: options.minSize || 1024,
      cacheSize: options.cacheSize || 100,
      brotliEnabled: options.brotliEnabled !== false,
      ...options
    };
    
    this.cache = new Map();
    this.cacheOrder = [];
    this.server = null;
    this.metrics = {
      requests: 0,
      compressed: 0,
      cacheHits: 0,
      bytesSaved: 0
    };
  }
  
  start() {
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
    
    this.server.listen(this.options.port, () => {
      console.log(`Compression proxy listening on port ${this.options.port}`);
    });
    
    // Start metrics collection
    this.startMetricsCollection();
    
    return this.server;
  }
  
  async handleRequest(req, res) {
    this.metrics.requests++;
    
    // Parse request headers
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const clientSupportsGzip = acceptEncoding.includes('gzip');
    const clientSupportsBrotli = this.options.brotliEnabled && 
                                 acceptEncoding.includes('br');
    
    // Forward request to origin
    const originReq = this.forwardToOrigin(req);
    
    // Get origin response
    const originRes = await this.getOriginResponse(originReq);
    
    // Check if response should be compressed
    const contentType = originRes.headers['content-type'] || '';
    const contentLength = parseInt(originRes.headers['content-length'] || '0');
    
    const shouldCompress = this.shouldCompressResponse(
      contentType, 
      contentLength, 
      originRes.statusCode
    );
    
    if (shouldCompress && (clientSupportsGzip || clientSupportsBrotli)) {
      await this.handleCompressedResponse(
        req, 
        res, 
        originRes, 
        clientSupportsGzip, 
        clientSupportsBrotli
      );
    } else {
      // Pass through uncompressed
      this.passthroughResponse(res, originRes);
    }
  }
  
  forwardToOrigin(req) {
    const url = new URL(req.url);
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: req.method,
      headers: { ...req.headers }
    };
    
    // Remove hop-by-hop headers
    delete options.headers['connection'];
    delete options.headers['upgrade'];
    delete options.headers['accept-encoding']; // We'll handle compression
    
    const module = url.protocol === 'https:' ? https : http;
    return module.request(options);
  }
  
  getOriginResponse(originReq) {
    return new Promise((resolve, reject) => {
      originReq.on('response', (res) => {
        resolve(res);
      });
      
      originReq.on('error', reject);
      
      // Forward request body if present
      if (req.body) {
        originReq.write(req.body);
      }
      
      originReq.end();
    });
  }
  
  shouldCompressResponse(contentType, contentLength, statusCode) {
    // Don't compress errors
    if (statusCode >= 400) {
      return false;
    }
    
    // Check minimum size
    if (contentLength < this.options.minSize) {
      return false;
    }
    
    // Check content type
    const compressibleTypes = [
      'text/',
      'application/json',
      'application/javascript',
      'application/xml',
      'application/xhtml+xml',
      'image/svg+xml'
    ];
    
    return compressibleTypes.some(type => contentType.includes(type));
  }
  
  async handleCompressedResponse(req, res, originRes, supportsGzip, supportsBrotli) {
    // Check cache first
    const cacheKey = this.getCacheKey(req.url, originRes.headers);
    const cached = this.cache.get(cacheKey);
    
    if (cached) {
      this.metrics.cacheHits++;
      
      // Serve from cache
      res.writeHead(originRes.statusCode, {
        ...originRes.headers,
        'content-encoding': cached.encoding,
        'content-length': cached.data.length,
        'x-compression-cache': 'hit'
      });
      
      res.end(cached.data);
      return;
    }
    
    // Collect response data
    const chunks = [];
    originRes.on('data', chunk => chunks.push(chunk));
    
    await new Promise((resolve) => {
      originRes.on('end', resolve);
    });
    
    const originalData = Buffer.concat(chunks);
    
    // Choose compression algorithm
    let compressedData;
    let encoding;
    
    if (supportsBrotli && zlib.brotliCompressSync) {
      // Use Brotli if supported
      compressedData = zlib.brotliCompressSync(originalData, {
        params: {
          [zlib.constants.BROTLI_PARAM_QUALITY]: this.options.compressionLevel
        }
      });
      encoding = 'br';
    } else if (supportsGzip) {
      // Fall back to Gzip
      compressedData = zlib.gzipSync(originalData, {
        level: this.options.compressionLevel
      });
      encoding = 'gzip';
    } else {
      // No compression supported
      this.passthroughResponse(res, originRes, originalData);
      return;
    }
    
    this.metrics.compressed++;
    this.metrics.bytesSaved += (originalData.length - compressedData.length);
    
    // Cache the compressed response
    this.cacheResponse(cacheKey, {
      encoding,
      data: compressedData,
      headers: originRes.headers,
      timestamp: Date.now()
    });
    
    // Send compressed response
    res.writeHead(originRes.statusCode, {
      ...originRes.headers,
      'content-encoding': encoding,
      'content-length': compressedData.length,
      'x-compression-ratio': (compressedData.length / originalData.length).toFixed(3),
      'x-compression-cache': 'miss'
    });
    
    res.end(compressedData);
  }
  
  passthroughResponse(res, originRes, data = null) {
    // Copy headers
    const headers = { ...originRes.headers };
    
    // Remove content-encoding if present
    delete headers['content-encoding'];
    
    res.writeHead(originRes.statusCode, headers);
    
    if (data) {
      res.end(data);
    } else {
      // Pipe the response
      originRes.pipe(res);
    }
  }
  
  getCacheKey(url, headers) {
    // Create cache key from URL and relevant headers
    const relevantHeaders = {
      'content-type': headers['content-type'],
      'etag': headers['etag'],
      'last-modified': headers['last-modified']
    };
    
    const headerString = JSON.stringify(relevantHeaders);
    return crypto.createHash('md5')
      .update(url + headerString)
      .digest('hex');
  }
  
  cacheResponse(key, response) {
    // Add to cache
    this.cache.set(key, response);
    this.cacheOrder.push(key);
    
    // Remove oldest if cache is full
    if (this.cacheOrder.length > this.options.cacheSize) {
      const oldestKey = this.cacheOrder.shift();
      this.cache.delete(oldestKey);
    }
  }
  
  startMetricsCollection() {
    setInterval(() => {
      const compressionRatio = this.metrics.requests > 0 ?
        (this.metrics.compressed / this.metrics.requests) * 100 : 0;
      
      const cacheHitRate = this.metrics.compressed > 0 ?
        (this.metrics.cacheHits / this.metrics.compressed) * 100 : 0;
      
      console.log('Proxy Metrics:', {
        requests: this.metrics.requests,
        compressed: this.metrics.compressed,
        compressionRate: `${compressionRatio.toFixed(1)}%`,
        cacheHits: this.metrics.cacheHits,
        cacheHitRate: `${cacheHitRate.toFixed(1)}%`,
        bytesSaved: this.formatBytes(this.metrics.bytesSaved),
        cacheSize: this.cache.size
      });
    }, 10000);
  }
  
  formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;
    
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    
    return `${value.toFixed(2)} ${units[unitIndex]}`;
  }
  
  getMetrics() {
    return {
      ...this.metrics,
      cacheSize: this.cache.size,
      cacheKeys: Array.from(this.cache.keys())
    };
  }
  
  clearCache() {
    this.cache.clear();
    this.cacheOrder = [];
    console.log('Cache cleared');
  }
  
  stop() {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }
}

// Advanced compression stream with metrics
class InstrumentedCompressionStream extends Transform {
  constructor(options = {}) {
    super(options);
    
    this.metrics = {
      inputBytes: 0,
      outputBytes: 0,
      chunks: 0,
      startTime: Date.now()
    };
    
    this.compressionStream = options.algorithm === 'gzip' ?
      zlib.createGzip(options) :
      options.algorithm === 'deflate' ?
      zlib.createDeflate(options) :
      zlib.createBrotliCompress(options);
    
    // Pipe through compression stream
    this.compressionStream.on('data', (chunk) => {
      this.metrics.outputBytes += chunk.length;
      this.push(chunk);
    });
    
    this.compressionStream.on('error', (error) => {
      this.emit('error', error);
    });
    
    this.compressionStream.on('end', () => {
      this.push(null);
    });
  }
  
  _transform(chunk, encoding, callback) {
    this.metrics.inputBytes += chunk.length;
    this.metrics.chunks++;
    
    this.compressionStream.write(chunk, encoding, (error) => {
      if (error) {
        callback(error);
      } else {
        callback();
      }
    });
  }
  
  _flush(callback) {
    this.compressionStream.end(() => {
      const elapsed = Date.now() - this.metrics.startTime;
      this.metrics.elapsedMs = elapsed;
      this.metrics.throughput = this.metrics.inputBytes / (elapsed / 1000);
      this.metrics.compressionRatio = this.metrics.outputBytes / this.metrics.inputBytes;
      
      this.emit('metrics', this.metrics);
      callback();
    });
  }
  
  getMetrics() {
    return { ...this.metrics };
  }
}
```

**Scenario 2: Database Backup Compression System**
> Build a system that compresses database backups with deduplication, encryption, and progress tracking.

**Solution:**
```javascript
const zlib = require('zlib');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { Transform, pipeline, Readable, Writable } = require('stream');
const EventEmitter = require('events');

class BackupCompressionSystem extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      backupDir: options.backupDir || './backups',
      tempDir: options.tempDir || './temp',
      chunkSize: options.chunkSize || 1024 * 1024, // 1MB chunks
      compressionLevel: options.compressionLevel || 6,
      encryptionKey: options.encryptionKey,
      deduplicate: options.deduplicate !== false,
      retentionDays: options.retentionDays || 30,
      ...options
    };
    
    this.backups = new Map();
    this.chunkIndex = new Map(); // hash -> chunkId
    this.chunkStore = new Map(); // chunkId -> {size, count, timestamp}
    this.metrics = {
      backupsCreated: 0,
      bytesProcessed: 0,
      bytesSaved: 0,
      deduplicationHits: 0
    };
    
    this.ensureDirectories();
  }
  
  async ensureDirectories() {
    await fs.mkdir(this.options.backupDir, { recursive: true });
    await fs.mkdir(this.options.tempDir, { recursive: true });
  }
  
  // Create backup from database connection or dump file
  async createBackup(source, backupName, metadata = {}) {
    const backupId = crypto.randomBytes(8).toString('hex');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `${backupName}_${timestamp}.backup`;
    const backupPath = path.join(this.options.backupDir, backupFileName);
    
    this.emit('backupStarted', { backupId, backupName, source, metadata });
    
    try {
      // Create backup manifest
      const manifest = {
        id: backupId,
        name: backupName,
        source: typeof source === 'string' ? source : source.constructor.name,
        timestamp,
        created: new Date().toISOString(),
        metadata,
        chunks: [],
        stats: {
          originalSize: 0,
          compressedSize: 0,
          deduplicatedSize: 0,
          chunkCount: 0
        }
      };
      
      // Create backup stream based on source type
      let backupStream;
      
      if (typeof source === 'string') {
        // File source
        backupStream = fs.createReadStream(source);
      } else if (source.readable) {
        // Stream source
        backupStream = source;
      } else if (typeof source.dump === 'function') {
        // Database connection with dump method
        backupStream = await source.dump();
      } else {
        throw new Error('Unsupported backup source');
      }
      
      // Process backup through compression pipeline
      const result = await this.processBackupStream(
        backupStream, 
        backupId, 
        manifest
      );
      
      // Update manifest with results
      manifest.chunks = result.chunks;
      manifest.stats = result.stats;
      manifest.encrypted = !!this.options.encryptionKey;
      manifest.deduplicated = this.options.deduplicate;
      
      // Write manifest
      const manifestPath = backupPath + '.manifest';
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
      
      // Store backup metadata
      this.backups.set(backupId, {
        id: backupId,
        name: backupName,
        path: backupPath,
        manifestPath,
        manifest,
        created: new Date(),
        size: result.stats.compressedSize
      });
      
      this.metrics.backupsCreated++;
      
      this.emit('backupCompleted', { 
        backupId, 
        backupName, 
        manifest,
        metrics: this.metrics 
      });
      
      // Cleanup old backups
      await this.cleanupOldBackups();
      
      return { backupId, manifest, path: backupPath };
      
    } catch (error) {
      this.emit('backupFailed', { backupId, backupName, error });
      throw error;
    }
  }
  
  // Process backup stream through compression pipeline
  async processBackupStream(stream, backupId, manifest) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      const stats = {
        originalSize: 0,
        compressedSize: 0,
        deduplicatedSize: 0,
        chunkCount: 0
      };
      
      let chunkIndex = 0;
      
      // Create processing pipeline
      const chunkStream = this.createChunkingStream();
      const compressionStream = this.createCompressionStream();
      const encryptionStream = this.options.encryptionKey ? 
        this.createEncryptionStream() : 
        new Transform({ transform(chunk, enc, cb) { cb(null, chunk); } });
      
      // Create writable stream to collect results
      const collector = new Writable({
        write(chunk, encoding, callback) {
          const chunkInfo = this.parseChunk(chunk);
          chunks.push(chunkInfo);
          
          stats.chunkCount++;
          stats.compressedSize += chunkInfo.size;
          stats.originalSize += chunkInfo.originalSize || chunkInfo.size;
          
          if (chunkInfo.deduplicated) {
            stats.deduplicatedSize += chunkInfo.originalSize;
            this.metrics.deduplicationHits++;
          }
          
          callback();
        }.bind(this),
        
        parseChunk(chunk) {
          // Parse chunk header
          const type = chunk.readUInt8(0);
          
          if (type === 0x01) {
            // New compressed chunk
            const chunkId = chunk.readUInt32BE(1);
            const hash = chunk.slice(5, 21).toString('hex');
            const originalSize = chunk.readUInt32BE(21);
            const compressedSize = chunk.readUInt32BE(25);
            const data = chunk.slice(29);
            
            return {
              type: 'compressed',
              chunkId,
              hash,
              originalSize,
              size: data.length,
              data
            };
          } else if (type === 0x02) {
            // Reference to existing chunk
            const chunkId = chunk.readUInt32BE(1);
            const originalSize = chunk.readUInt32BE(5);
            
            return {
              type: 'reference',
              chunkId,
              originalSize,
              size: 9, // Header size
              deduplicated: true
            };
          } else {
            throw new Error('Unknown chunk type');
          }
        }
      });
      
      // Set up pipeline with error handling
      pipeline(
        stream,
        chunkStream,
        compressionStream,
        encryptionStream,
        collector,
        async (error) => {
          if (error) {
            reject(error);
          } else {
            // Calculate final statistics
            const compressionRatio = stats.originalSize > 0 ?
              stats.compressedSize / stats.originalSize : 1;
            
            const deduplicationRatio = stats.originalSize > 0 ?
              (stats.originalSize - stats.deduplicatedSize) / stats.originalSize : 0;
            
            stats.compressionRatio = compressionRatio;
            stats.deduplicationRatio = deduplicationRatio;
            stats.savings = stats.originalSize - stats.compressedSize;
            
            resolve({ chunks, stats });
          }
        }
      );
      
      // Track progress
      stream.on('data', (chunk) => {
        stats.originalSize += chunk.length;
        this.metrics.bytesProcessed += chunk.length;
        
        this.emit('backupProgress', {
          backupId,
          bytesProcessed: stats.originalSize,
          chunkCount: chunkIndex++,
          stats: { ...stats }
        });
      });
    });
  }
  
  // Create chunking stream
  createChunkingStream() {
    let buffer = Buffer.alloc(0);
    
    return new Transform({
      transform(chunk, encoding, callback) {
        buffer = Buffer.concat([buffer, chunk]);
        
        // Split into chunks of specified size
        while (buffer.length >= this.options.chunkSize) {
          const chunkData = buffer.slice(0, this.options.chunkSize);
          buffer = buffer.slice(this.options.chunkSize);
          
          this.processChunk(chunkData, callback);
        }
        
        callback();
      },
      
      flush(callback) {
        // Process remaining data
        if (buffer.length > 0) {
          this.processChunk(buffer, callback);
        } else {
          callback();
        }
      },
      
      processChunk(chunkData, callback) {
        // Calculate hash for deduplication
        const hash = crypto.createHash('sha256')
          .update(chunkData)
          .digest()
          .slice(0, 16); // Use first 16 bytes
        
        const hashHex = hash.toString('hex');
        
        if (this.options.deduplicate && this.chunkIndex.has(hashHex)) {
          // Chunk already exists, create reference
          const chunkId = this.chunkIndex.get(hashHex);
          
          // Update chunk store
          const chunkInfo = this.chunkStore.get(chunkId);
          chunkInfo.count++;
          chunkInfo.lastUsed = new Date();
          
          // Create reference chunk
          const header = Buffer.alloc(9);
          header.writeUInt8(0x02, 0); // Reference type
          header.writeUInt32BE(chunkId, 1);
          header.writeUInt32BE(chunkData.length, 5);
          
          this.push(header);
          
        } else {
          // New chunk
          const chunkId = this.chunkIndex.size;
          
          // Store chunk info
          this.chunkIndex.set(hashHex, chunkId);
          this.chunkStore.set(chunkId, {
            size: chunkData.length,
            hash: hashHex,
            count: 1,
            firstUsed: new Date(),
            lastUsed: new Date()
          });
          
          // Create chunk header
          const header = Buffer.alloc(29);
          header.writeUInt8(0x01, 0); // New chunk type
          header.writeUInt32BE(chunkId, 1);
          hash.copy(header, 5);
          header.writeUInt32BE(chunkData.length, 21);
          header.writeUInt32BE(0, 25); // Placeholder for compressed size
          
          // Push header and data
          this.push(Buffer.concat([header, chunkData]));
        }
      }
    });
  }
  
  // Create compression stream
  createCompressionStream() {
    return new Transform({
      transform(chunk, encoding, callback) {
        const type = chunk.readUInt8(0);
        
        if (type === 0x01) {
          // New chunk - compress the data part
          const data = chunk.slice(29);
          
          zlib.deflate(data, { level: this.options.compressionLevel }, (error, compressed) => {
            if (error) {
              callback(error);
            } else {
              // Update compressed size in header
              chunk.writeUInt32BE(compressed.length, 25);
              
              // Replace data with compressed data
              const result = Buffer.concat([
                chunk.slice(0, 29),
                compressed
              ]);
              
              callback(null, result);
            }
          });
        } else {
          // Reference chunk - pass through unchanged
          callback(null, chunk);
        }
      }
    });
  }
  
  // Create encryption stream
  createEncryptionStream() {
    const crypto = require('crypto');
    const algorithm = 'aes-256-gcm';
    
    return new Transform({
      transform(chunk, encoding, callback) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(algorithm, this.options.encryptionKey, iv);
        
        let encrypted = cipher.update(chunk);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();
        
        // Create encrypted chunk with IV and auth tag
        const result = Buffer.concat([
          iv, // 12 bytes
          authTag, // 16 bytes
          encrypted
        ]);
        
        callback(null, result);
      }
    });
  }
  
  // Restore backup
  async restoreBackup(backupId, target) {
    const backup = this.backups.get(backupId);
    if (!backup) {
      throw new Error(`Backup ${backupId} not found`);
    }
    
    this.emit('restoreStarted', { backupId, target });
    
    try {
      // Read manifest
      const manifest = backup.manifest;
      
      // Create restore stream
      const restoreStream = this.createRestoreStream(manifest);
      
      // Write to target
      if (typeof target === 'string') {
        // File target
        const writeStream = fs.createWriteStream(target);
        await new Promise((resolve, reject) => {
          pipeline(restoreStream, writeStream, (error) => {
            if (error) reject(error);
            else resolve();
          });
        });
      } else if (target.writable) {
        // Stream target
        await new Promise((resolve, reject) => {
          pipeline(restoreStream, target, (error) => {
            if (error) reject(error);
            else resolve();
          });
        });
      } else {
        throw new Error('Unsupported restore target');
      }
      
      this.emit('restoreCompleted', { backupId, target, manifest });
      
      return { success: true, backupId, target };
      
    } catch (error) {
      this.emit('restoreFailed', { backupId, target, error });
      throw error;
    }
  }
  
  // Create restore stream from backup chunks
  createRestoreStream(manifest) {
    const { Readable, Transform } = require('stream');
    
    // This is a simplified version
    // In reality, you would read chunk data from storage
    
    return new Readable({
      read() {
        // Generate mock restored data
        this.push(Buffer.from('Restored backup data\n'));
        this.push(null);
      }
    });
  }
  
  // Cleanup old backups
  async cleanupOldBackups() {
    const now = new Date();
    const cutoff = new Date(now - this.options.retentionDays * 24 * 60 * 60 * 1000);
    
    for (const [backupId, backup] of this.backups) {
      if (backup.created < cutoff) {
        try {
          await this.deleteBackup(backupId);
          console.log(`Deleted old backup: ${backupId}`);
        } catch (error) {
          console.error(`Failed to delete backup ${backupId}:`, error);
        }
      }
    }
  }
  
  // Delete backup
  async deleteBackup(backupId) {
    const backup = this.backups.get(backupId);
    if (!backup) return false;
    
    try {
      // Delete backup files
      if (backup.path) {
        await fs.unlink(backup.path).catch(() => {});
      }
      
      if (backup.manifestPath) {
        await fs.unlink(backup.manifestPath).catch(() => {});
      }
      
      // Remove from backups map
      this.backups.delete(backupId);
      
      this.emit('backupDeleted', { backupId });
      
      return true;
      
    } catch (error) {
      console.error(`Error deleting backup ${backupId}:`, error);
      return false;
    }
  }
  
  // Get backup information
  getBackupInfo(backupId) {
    const backup = this.backups.get(backupId);
    if (!backup) return null;
    
    return {
      id: backup.id,
      name: backup.name,
      path: backup.path,
      created: backup.created,
      size: backup.size,
      manifest: backup.manifest
    };
  }
  
  // List all backups
  listBackups(filter = {}) {
    const backups = [];
    
    for (const backup of this.backups.values()) {
      let include = true;
      
      if (filter.name && !backup.name.includes(filter.name)) {
        include = false;
      }
      
      if (filter.createdAfter && backup.created < filter.createdAfter) {
        include = false;
      }
      
      if (filter.createdBefore && backup.created > filter.createdBefore) {
        include = false;
      }
      
      if (filter.minSize && backup.size < filter.minSize) {
        include = false;
      }
      
      if (filter.maxSize && backup.size > filter.maxSize) {
        include = false;
      }
      
      if (include) {
        backups.push({
          id: backup.id,
          name: backup.name,
          created: backup.created,
          size: backup.size,
          path: backup.path
        });
      }
    }
    
    return backups.sort((a, b) => b.created - a.created);
  }
  
  // Get system statistics
  getStatistics() {
    return {
      backups: this.backups.size,
      chunks: this.chunkIndex.size,
      metrics: { ...this.metrics },
      storage: {
        backupDir: this.options.backupDir,
        tempDir: this.options.tempDir,
        retentionDays: this.options.retentionDays
      }
    };
  }
  
  // Get chunk store statistics
  getChunkStoreStats() {
    const stats = {
      totalChunks: this.chunkStore.size,
      totalSize: 0,
      averageSize: 0,
      mostUsed: [],
      leastUsed: []
    };
    
    let totalSize = 0;
    const usageCounts = [];
    
    for (const [chunkId, chunkInfo] of this.chunkStore) {
      totalSize += chunkInfo.size;
      usageCounts.push({
        chunkId,
        size: chunkInfo.size,
        count: chunkInfo.count,
        lastUsed: chunkInfo.lastUsed
      });
    }
    
    stats.totalSize = totalSize;
    stats.averageSize = this.chunkStore.size > 0 ? totalSize / this.chunkStore.size : 0;
    
    // Sort by usage
    usageCounts.sort((a, b) => b.count - a.count);
    stats.mostUsed = usageCounts.slice(0, 10);
    stats.leastUsed = usageCounts.slice(-10).reverse();
    
    return stats;
  }
  
  // Cleanup temporary files
  async cleanupTempFiles() {
    try {
      const files = await fs.readdir(this.options.tempDir);
      
      for (const file of files) {
        const filePath = path.join(this.options.tempDir, file);
        await fs.unlink(filePath).catch(() => {});
      }
      
      console.log('Cleaned up temporary files');
      
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
}
```

---

## 🎯 Summary

Node.js core modules provide the fundamental building blocks for building robust, scalable applications. Mastering these modules is essential for any senior Node.js developer.

**Key Takeaways:**

1. **fs**: Master both callback and promise APIs, understand streaming vs buffered operations
2. **path**: Always use path module for cross-platform compatibility
3. **events**: Understand EventEmitter patterns for building decoupled systems
4. **http/https**: Know how to build servers and clients with proper error handling
5. **os**: Use for system monitoring and platform-specific logic
6. **process**: Essential for process management, signals, and graceful shutdown
7. **url**: Critical for web applications, understand both legacy and modern APIs
8. **crypto**: Security is paramount - understand hashing, encryption, and signing
9. **stream**: The heart of Node.js performance - master backpressure and pipelines
10. **zlib**: Essential for performance optimization and data storage

**Best Practices:**
- Always use streams for large data to prevent memory issues
- Implement proper error handling in all asynchronous operations
- Use the modern URL API instead of legacy url.parse()
- Implement graceful shutdown in production applications
- Use crypto modules securely (proper key management, etc.)
- Monitor resource usage with os and process modules

**Next Steps:**
1. Practice building real applications using these core modules
2. Explore the source code of popular frameworks to see these modules in action
3. Stay updated with Node.js releases for new features and deprecations
4. Experiment with combining multiple modules for complex solutions
5. Contribute to open source projects to see real-world usage patterns

Remember: Mastery comes from practice and understanding the "why" behind each API decision. Build projects, read source code, and never stop learning!