# Node.js Performance Optimization - Complete Guide

## Table of Contents
- [Introduction](#introduction)
- [Clustering](#clustering)
- [Worker Threads](#worker-threads)
- [Caching (Server + Database)](#caching-server--database)
- [Streams for Large Files](#streams-for-large-files)
- [Query Optimization](#query-optimization)
- [Load Testing with Artillery/JMeter](#load-testing-with-artilleryjmeter)
- [PM2 Process Manager](#pm2-process-manager)
- [Logging with Pino](#logging-with-pino)
- [Performance Monitoring & Metrics](#performance-monitoring--metrics)
- [Interview Questions](#interview-questions)
  - [Topic-wise Questions](#topic-wise-questions)
  - [Real-World Scenarios](#real-world-scenarios)

---

## Introduction

Node.js is single-threaded by nature, but modern applications demand high performance and concurrency. This guide covers comprehensive optimization techniques to handle thousands of concurrent connections efficiently.

**Key Performance Metrics to Monitor:**
- Requests per second (RPS)
- Response time (p50, p95, p99)
- CPU utilization
- Memory usage
- Event loop latency
- Garbage collection frequency

---

## Clustering

### Overview
Clustering enables you to create multiple Node.js processes (workers) that share the same server port, utilizing all CPU cores. This is essential because Node.js runs on a single thread, but most servers have multiple cores.

### Implementation Example

```javascript
// cluster-master.js
const cluster = require('cluster');
const os = require('os');
const app = require('./app');

if (cluster.isMaster) {
  const numCPUs = os.cpus().length;
  console.log(`Master ${process.pid} is running`);
  console.log(`Forking ${numCPUs} workers`);

  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  // Handle worker events
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    
    // Restart worker if it died unexpectedly
    if (!worker.exitedAfterDisconnect) {
      console.log('Starting a new worker');
      cluster.fork();
    }
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('Master received SIGTERM, shutting down workers...');
    
    for (const id in cluster.workers) {
      cluster.workers[id].kill('SIGTERM');
    }
    
    process.exit(0);
  });

} else {
  // Worker process - start your app
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Worker ${process.pid} started on port ${PORT}`);
  });
}

// Advanced cluster with load balancing and shared state
class AdvancedCluster {
  constructor() {
    this.workers = new Map();
    this.sharedState = new Map();
    this.workerQueue = [];
  }

  start() {
    const numCPUs = os.cpus().length;
    
    // Create workers
    for (let i = 0; i < numCPUs; i++) {
      this.createWorker();
    }

    // Setup IPC communication
    cluster.on('message', (worker, message) => {
      this.handleWorkerMessage(worker, message);
    });

    // Health checks
    setInterval(() => {
      this.healthCheck();
    }, 30000);
  }

  createWorker() {
    const worker = cluster.fork();
    
    worker.on('message', (message) => {
      this.handleWorkerMessage(worker, message);
    });

    this.workers.set(worker.id, {
      process: worker,
      pid: worker.process.pid,
      status: 'healthy',
      load: 0,
      lastHeartbeat: Date.now()
    });

    // Initialize worker with shared state
    worker.send({
      type: 'init',
      data: Array.from(this.sharedState.entries())
    });
  }

  handleWorkerMessage(worker, message) {
    switch (message.type) {
      case 'heartbeat':
        const workerData = this.workers.get(worker.id);
        if (workerData) {
          workerData.lastHeartbeat = Date.now();
          workerData.load = message.load || 0;
        }
        break;
      
      case 'stateUpdate':
        this.sharedState.set(message.key, message.value);
        // Broadcast to other workers
        this.broadcastStateUpdate(message.key, message.value);
        break;
      
      case 'taskCompleted':
        this.handleTaskCompletion(message.taskId, message.result);
        break;
    }
  }

  broadcastStateUpdate(key, value) {
    for (const [id, workerData] of this.workers) {
      if (id !== this.currentWorkerId) {
        workerData.process.send({
          type: 'stateUpdate',
          key,
          value
        });
      }
    }
  }

  healthCheck() {
    const now = Date.now();
    for (const [id, workerData] of this.workers) {
      if (now - workerData.lastHeartbeat > 45000) { // 45 seconds
        console.log(`Worker ${id} (PID: ${workerData.pid}) is unresponsive`);
        workerData.status = 'unhealthy';
        this.restartWorker(id);
      }
    }
  }

  restartWorker(workerId) {
    const workerData = this.workers.get(workerId);
    if (workerData) {
      console.log(`Restarting worker ${workerId}`);
      workerData.process.kill('SIGTERM');
      
      setTimeout(() => {
        this.createWorker();
      }, 1000);
    }
  }

  // Round-robin load balancing
  getNextWorker() {
    if (this.workerQueue.length === 0) {
      this.workerQueue = Array.from(this.workers.values())
        .filter(w => w.status === 'healthy')
        .sort((a, b) => a.load - b.load);
    }
    
    return this.workerQueue.shift();
  }
}

// Using cluster with shared Redis state
const cluster = require('cluster');
const Redis = require('ioredis');

if (cluster.isMaster) {
  // Master process setup
  const redis = new Redis();
  
  cluster.on('message', (worker, message) => {
    if (message.type === 'cacheUpdate') {
      // Store in Redis for all workers to access
      redis.set(message.key, JSON.stringify(message.value));
    }
  });
  
  // Fork workers...
} else {
  // Worker process with shared Redis
  const redis = new Redis();
  
  // Worker can now access shared cache
  async function getCachedData(key) {
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }
}
```

### Best Practices
1. **Worker Count**: Usually CPU cores - 1 (leaves one core for OS/other processes)
2. **Graceful Restart**: Implement zero-downtime restarts
3. **Shared State**: Use Redis or database for shared state between workers
4. **Health Checks**: Implement worker health monitoring
5. **Load Distribution**: Consider sticky sessions for certain applications

---

## Worker Threads

### Overview
Worker Threads allow CPU-intensive tasks to run in parallel without blocking the main event loop. Unlike clustering, worker threads share memory (via SharedArrayBuffer) and are lighter weight.

### Implementation Example

```javascript
// worker-pool-manager.js
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');

class WorkerPool {
  constructor(workerPath, numWorkers = os.cpus().length) {
    this.workerPath = workerPath;
    this.numWorkers = numWorkers;
    this.workers = [];
    this.taskQueue = [];
    this.availableWorkers = new Set();
    this.taskId = 0;
    this.resolvers = new Map();

    this.init();
  }

  init() {
    for (let i = 0; i < this.numWorkers; i++) {
      this.createWorker(i);
    }
  }

  createWorker(id) {
    const worker = new Worker(this.workerPath, {
      workerData: { id }
    });

    worker.on('message', (result) => {
      this.handleWorkerMessage(worker, result);
    });

    worker.on('error', (error) => {
      console.error(`Worker ${id} error:`, error);
      this.handleWorkerError(worker, error);
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        console.log(`Worker ${id} stopped with exit code ${code}`);
      }
      // Restart worker
      setTimeout(() => this.createWorker(id), 1000);
    });

    this.workers.push(worker);
    this.availableWorkers.add(worker);
  }

  handleWorkerMessage(worker, result) {
    const { taskId, data, error } = result;
    
    if (this.resolvers.has(taskId)) {
      const { resolve, reject } = this.resolvers.get(taskId);
      
      if (error) {
        reject(new Error(error));
      } else {
        resolve(data);
      }
      
      this.resolvers.delete(taskId);
    }
    
    // Worker is now available
    this.availableWorkers.add(worker);
    this.processQueue();
  }

  handleWorkerError(worker, error) {
    // Mark worker as unavailable
    this.availableWorkers.delete(worker);
    
    // Reassign tasks from this worker
    this.reassignTasks(worker);
  }

  reassignTasks(failedWorker) {
    const reassignedTasks = [];
    
    for (const [taskId, resolver] of this.resolvers.entries()) {
      const task = this.taskQueue.find(t => t.taskId === taskId);
      if (task && task.worker === failedWorker) {
        reassignedTasks.push({ taskId, resolver });
        this.resolvers.delete(taskId);
      }
    }
    
    // Add tasks back to queue
    reassignedTasks.forEach(({ taskId, resolver }) => {
      this.enqueueTask(resolver.task, resolver.resolve, resolver.reject);
    });
  }

  enqueueTask(task, resolve, reject) {
    const taskId = this.taskId++;
    this.taskQueue.push({
      taskId,
      task,
      resolve,
      reject
    });
    this.processQueue();
    
    return taskId;
  }

  processQueue() {
    if (this.taskQueue.length === 0 || this.availableWorkers.size === 0) {
      return;
    }

    const worker = this.getNextAvailableWorker();
    const nextTask = this.taskQueue.shift();

    if (worker && nextTask) {
      this.availableWorkers.delete(worker);
      this.resolvers.set(nextTask.taskId, {
        resolve: nextTask.resolve,
        reject: nextTask.reject
      });

      worker.postMessage({
        taskId: nextTask.taskId,
        task: nextTask.task
      });
    }
  }

  getNextAvailableWorker() {
    // Simple round-robin, could implement load-based selection
    return this.availableWorkers.values().next().value;
  }

  execute(task) {
    return new Promise((resolve, reject) => {
      this.enqueueTask(task, resolve, reject);
    });
  }

  async executeAll(tasks, batchSize = 10) {
    const results = [];
    
    for (let i = 0; i < tasks.length; i += batchSize) {
      const batch = tasks.slice(i, i + batchSize);
      const batchPromises = batch.map(task => this.execute(task));
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }
    
    return results;
  }

  getStats() {
    return {
      totalWorkers: this.workers.length,
      availableWorkers: this.availableWorkers.size,
      queuedTasks: this.taskQueue.length,
      activeTasks: this.resolvers.size
    };
  }

  async shutdown() {
    // Wait for current tasks to complete
    while (this.taskQueue.length > 0 || this.resolvers.size > 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Terminate all workers
    const terminationPromises = this.workers.map(worker => 
      worker.terminate().catch(() => {})
    );
    
    await Promise.all(terminationPromises);
  }
}

// image-processor-worker.js (Worker thread implementation)
const { parentPort, workerData } = require('worker_threads');
const sharp = require('sharp');
const crypto = require('crypto');

class ImageProcessor {
  constructor() {
    this.setupMessageHandler();
  }

  setupMessageHandler() {
    parentPort.on('message', async (message) => {
      const { taskId, task } = message;
      
      try {
        const result = await this.processTask(task);
        parentPort.postMessage({
          taskId,
          data: result
        });
      } catch (error) {
        parentPort.postMessage({
          taskId,
          error: error.message
        });
      }
    });
  }

  async processTask(task) {
    switch (task.type) {
      case 'resize':
        return await this.resizeImage(task.data);
      
      case 'compress':
        return await this.compressImage(task.data);
      
      case 'watermark':
        return await this.addWatermark(task.data);
      
      case 'hash':
        return this.calculateHash(task.data);
      
      default:
        throw new Error(`Unknown task type: ${task.type}`);
    }
  }

  async resizeImage({ buffer, width, height, format = 'jpeg' }) {
    return await sharp(buffer)
      .resize(width, height, {
        fit: 'cover',
        position: 'center'
      })
      .toFormat(format)
      .toBuffer();
  }

  async compressImage({ buffer, quality = 80 }) {
    return await sharp(buffer)
      .jpeg({ quality })
      .toBuffer();
  }

  async addWatermark({ buffer, watermarkBuffer, opacity = 0.5 }) {
    const image = sharp(buffer);
    const metadata = await image.metadata();

    const watermark = await sharp(watermarkBuffer)
      .resize(Math.min(metadata.width, metadata.height) / 4)
      .composite([{
        input: Buffer.from([255, 255, 255, opacity * 255]),
        raw: { width: 1, height: 1, channels: 4 },
        tile: true,
        blend: 'dest-in'
      }])
      .toBuffer();

    return await image
      .composite([{
        input: watermark,
        gravity: 'southeast'
      }])
      .toBuffer();
  }

  calculateHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }
}

// Initialize if in worker thread
if (!isMainThread) {
  new ImageProcessor();
}

// Main application usage
const WorkerPool = require('./worker-pool-manager');
const fs = require('fs').promises;

class ImageProcessingService {
  constructor() {
    this.workerPool = new WorkerPool('./image-processor-worker.js', 4);
  }

  async processBatch(images, operations) {
    const tasks = images.map(image => ({
      type: 'resize',
      data: {
        buffer: image.buffer,
        width: 800,
        height: 600,
        format: 'webp'
      }
    }));

    return await this.workerPool.executeAll(tasks);
  }

  async processLargeImage(imagePath) {
    // Stream processing with worker threads
    const chunks = await this.splitImageIntoChunks(imagePath);
    
    const tasks = chunks.map(chunk => ({
      type: 'compress',
      data: { buffer: chunk, quality: 75 }
    }));

    const processedChunks = await this.workerPool.executeAll(tasks);
    return this.mergeChunks(processedChunks);
  }

  async splitImageIntoChunks(imagePath) {
    // Implementation for splitting large images
    const buffer = await fs.readFile(imagePath);
    const chunkSize = Math.ceil(buffer.length / 4);
    const chunks = [];
    
    for (let i = 0; i < buffer.length; i += chunkSize) {
      chunks.push(buffer.slice(i, i + chunkSize));
    }
    
    return chunks;
  }

  async mergeChunks(chunks) {
    return Buffer.concat(chunks);
  }

  async getStats() {
    return this.workerPool.getStats();
  }

  async shutdown() {
    await this.workerPool.shutdown();
  }
}

// Example with SharedArrayBuffer for memory sharing
const { Worker } = require('worker_threads');

class SharedMemoryWorker {
  constructor() {
    this.sharedBuffer = new SharedArrayBuffer(1024 * 1024 * 100); // 100MB
    this.sharedArray = new Uint8Array(this.sharedBuffer);
  }

  startWorker() {
    const worker = new Worker(`
      const { parentPort, workerData } = require('worker_threads');
      const sharedArray = new Uint8Array(workerData.sharedBuffer);
      
      parentPort.on('message', (message) => {
        if (message.type === 'process') {
          // Process data directly in shared memory
          for (let i = 0; i < message.length; i++) {
            sharedArray[i] = sharedArray[i] * 2; // Example processing
          }
          
          parentPort.postMessage({ status: 'completed' });
        }
      });
    `, {
      eval: true,
      workerData: { sharedBuffer: this.sharedBuffer }
    });

    return worker;
  }
}
```

### When to Use Worker Threads
1. **CPU-intensive tasks**: Image/video processing, encryption, complex calculations
2. **Large data processing**: CSV/JSON parsing, data transformations
3. **Machine learning**: Inference on large datasets
4. **Compression/decompression**: Large file operations

---

## Caching (Server + Database)

### Multi-Layer Caching Strategy

```javascript
// caching-strategy.js
const Redis = require('ioredis');
const NodeCache = require('node-cache');

class MultiLayerCache {
  constructor() {
    // L1: In-memory cache (fastest, per instance)
    this.l1Cache = new NodeCache({
      stdTTL: 60, // 60 seconds default
      checkperiod: 120,
      useClones: false
    });

    // L2: Redis cache (shared across instances)
    this.l2Cache = new Redis({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      maxRetriesPerRequest: 3
    });

    // L3: Database (persistent storage)
    this.db = require('./database');

    this.stats = {
      l1Hits: 0,
      l2Hits: 0,
      dbHits: 0,
      misses: 0
    };
  }

  async get(key, options = {}) {
    const {
      ttl = 60,
      forceRefresh = false,
      cacheNull = false,
      tags = []
    } = options;

    // Check L1 cache first
    if (!forceRefresh) {
      const l1Value = this.l1Cache.get(key);
      if (l1Value !== undefined) {
        this.stats.l1Hits++;
        return l1Value;
      }
    }

    // Check L2 cache (Redis)
    try {
      const l2Value = await this.l2Cache.get(key);
      if (l2Value !== null) {
        this.stats.l2Hits++;
        const parsedValue = JSON.parse(l2Value);
        
        // Populate L1 cache
        this.l1Cache.set(key, parsedValue, ttl);
        
        // Update cache tags
        if (tags.length > 0) {
          await this.updateTagIndex(key, tags);
        }
        
        return parsedValue;
      }
    } catch (error) {
      console.warn('Redis cache error:', error.message);
      // Continue to database if Redis fails
    }

    // Fetch from database
    const dbValue = await this.fetchFromDatabase(key);
    
    if (dbValue === null && !cacheNull) {
      this.stats.misses++;
      return null;
    }

    this.stats.dbHits++;

    // Store in both cache layers
    await this.set(key, dbValue, { ttl, tags });

    return dbValue;
  }

  async set(key, value, options = {}) {
    const { ttl = 60, tags = [] } = options;

    // Store in L1
    this.l1Cache.set(key, value, ttl);

    // Store in L2 (Redis)
    try {
      const serializedValue = JSON.stringify(value);
      
      if (ttl > 0) {
        await this.l2Cache.setex(key, ttl, serializedValue);
      } else {
        await this.l2Cache.set(key, serializedValue);
      }

      // Update tag index for cache invalidation
      if (tags.length > 0) {
        await this.updateTagIndex(key, tags);
      }
    } catch (error) {
      console.warn('Failed to store in Redis cache:', error.message);
    }
  }

  async updateTagIndex(key, tags) {
    for (const tag of tags) {
      const tagKey = `tag:${tag}`;
      await this.l2Cache.sadd(tagKey, key);
      await this.l2Cache.expire(tagKey, 86400); // 24 hours
    }
  }

  async invalidateByTag(tag) {
    const tagKey = `tag:${tag}`;
    const keys = await this.l2Cache.smembers(tagKey);
    
    // Delete from both cache layers
    const promises = keys.map(async (key) => {
      this.l1Cache.del(key);
      await this.l2Cache.del(key);
    });
    
    await Promise.all(promises);
    await this.l2Cache.del(tagKey);
  }

  async fetchFromDatabase(key) {
    // Implement database lookup
    // This is a simplified example
    const [type, id] = key.split(':');
    
    switch (type) {
      case 'user':
        return await this.db.User.findById(id);
      case 'product':
        return await this.db.Product.findById(id);
      default:
        return null;
    }
  }

  async getWithFallback(key, fallbackFunction, options = {}) {
    const cached = await this.get(key, options);
    
    if (cached !== null) {
      return cached;
    }

    // Execute fallback function
    const freshData = await fallbackFunction();
    
    if (freshData !== null) {
      await this.set(key, freshData, options);
    }
    
    return freshData;
  }

  async memoize(func, keyGenerator, options = {}) {
    return async (...args) => {
      const cacheKey = keyGenerator(...args);
      return await this.getWithFallback(
        cacheKey,
        () => func(...args),
        options
      );
    };
  }

  getStats() {
    return {
      ...this.stats,
      l1Keys: this.l1Cache.keys().length,
      l1Size: this.getL1CacheSize()
    };
  }

  getL1CacheSize() {
    // Approximate memory usage
    let size = 0;
    const stats = this.l1Cache.getStats();
    size += stats.keys * 100; // Approximate per key overhead
    // Add actual value sizes if needed
    return size;
  }
}

// Database Query Caching
class QueryCache {
  constructor(cacheLayer) {
    this.cache = cacheLayer;
  }

  async cachedQuery(model, query, options = {}) {
    const {
      ttl = 300, // 5 minutes
      tags = [],
      forceRefresh = false
    } = options;

    const cacheKey = this.generateCacheKey(model.modelName, query);
    
    return await this.cache.getWithFallback(
      cacheKey,
      async () => {
        const result = await model.find(query).lean();
        return result;
      },
      { ttl, tags, forceRefresh }
    );
  }

  generateCacheKey(modelName, query) {
    const queryString = JSON.stringify(query);
    const hash = require('crypto')
      .createHash('md5')
      .update(queryString)
      .digest('hex');
    
    return `query:${modelName}:${hash}`;
  }

  async invalidateModel(modelName) {
    const pattern = `query:${modelName}:*`;
    await this.cache.invalidatePattern(pattern);
  }
}

// HTTP Response Caching Middleware
const responseCacheMiddleware = (cache, options = {}) => {
  const {
    ttl = 300,
    varyByHeaders = ['authorization'],
    varyByQuery = true,
    skipCache = (req) => req.method !== 'GET'
  } = options;

  return async (req, res, next) => {
    if (skipCache(req)) {
      return next();
    }

    // Generate cache key from request
    const cacheKey = generateCacheKey(req, { varyByHeaders, varyByQuery });
    
    try {
      const cachedResponse = await cache.get(cacheKey);
      
      if (cachedResponse) {
        // Set cache headers
        res.set('X-Cache', 'HIT');
        res.set('Cache-Control', `public, max-age=${ttl}`);
        
        return res.json(cachedResponse);
      }

      // Cache miss - override res.json
      const originalJson = res.json.bind(res);
      
      res.json = (body) => {
        // Store response in cache
        cache.set(cacheKey, body, { ttl }).catch(console.error);
        
        // Set cache headers
        res.set('X-Cache', 'MISS');
        res.set('Cache-Control', `public, max-age=${ttl}`);
        
        return originalJson(body);
      };
      
      next();
    } catch (error) {
      console.error('Cache middleware error:', error);
      next();
    }
  };
};

function generateCacheKey(req, options) {
  const { varyByHeaders, varyByQuery } = options;
  const parts = [
    req.originalUrl,
    req.method
  ];

  if (varyByQuery && Object.keys(req.query).length > 0) {
    parts.push(JSON.stringify(req.query));
  }

  if (varyByHeaders && varyByHeaders.length > 0) {
    const headerValues = varyByHeaders
      .map(header => req.headers[header.toLowerCase()])
      .filter(Boolean);
    
    if (headerValues.length > 0) {
      parts.push(headerValues.join(':'));
    }
  }

  return `http:${require('crypto')
    .createHash('md5')
    .update(parts.join('|'))
    .digest('hex')}`;
}
```

### Cache Strategies
1. **Cache-Aside (Lazy Loading)**: Check cache first, then database
2. **Write-Through**: Write to cache and database simultaneously
3. **Write-Behind**: Write to cache first, batch write to database
4. **Refresh-Ahead**: Proactively refresh cache before expiration

---

## Streams for Large Files

### Comprehensive Stream Handling

```javascript
// stream-manager.js
const { Transform, PassThrough, pipeline } = require('stream');
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');

class StreamProcessor {
  // Process large CSV files
  static async processCSVStream(inputPath, outputPath, processor) {
    return new Promise((resolve, reject) => {
      const readStream = fs.createReadStream(inputPath, {
        highWaterMark: 64 * 1024 // 64KB chunks
      });
      
      const writeStream = fs.createWriteStream(outputPath);
      
      const csvParser = new Transform({
        objectMode: true,
        transform(chunk, encoding, callback) {
          const lines = chunk.toString().split('\n');
          const processedLines = lines.map(line => {
            if (line.trim()) {
              return processor(line);
            }
            return line;
          });
          
          this.push(processedLines.join('\n'));
          callback();
        }
      });
      
      pipeline(
        readStream,
        csvParser,
        writeStream,
        (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        }
      );
    });
  }

  // Parallel stream processing
  static async parallelStreamProcess(inputPath, outputPath, numStreams = 4) {
    const fileSize = fs.statSync(inputPath).size;
    const chunkSize = Math.ceil(fileSize / numStreams);
    
    const promises = [];
    
    for (let i = 0; i < numStreams; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, fileSize);
      
      promises.push(this.processChunk(inputPath, start, end, i));
    }
    
    const chunks = await Promise.all(promises);
    
    // Merge chunks
    const writeStream = fs.createWriteStream(outputPath);
    
    for (const chunk of chunks.sort((a, b) => a.index - b.index)) {
      writeStream.write(chunk.data);
    }
    
    writeStream.end();
  }

  static async processChunk(filePath, start, end, index) {
    return new Promise((resolve, reject) => {
      const readStream = fs.createReadStream(filePath, {
        start,
        end: end - 1
      });
      
      const chunks = [];
      
      readStream.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      readStream.on('end', () => {
        const data = Buffer.concat(chunks);
        // Process the chunk
        const processed = this.processData(data);
        resolve({ index, data: processed });
      });
      
      readStream.on('error', reject);
    });
  }

  // Stream with backpressure handling
  static createBackpressureAwareStream(highWaterMark = 16384) {
    return new Transform({
      highWaterMark,
      transform(chunk, encoding, callback) {
        // Check if we should slow down
        const shouldSlowDown = this.readableLength > highWaterMark * 0.8;
        
        if (shouldSlowDown) {
          // Add artificial delay to handle backpressure
          setTimeout(() => {
            this.push(chunk);
            callback();
          }, 10);
        } else {
          this.push(chunk);
          callback();
        }
      }
    });
  }

  // HTTP streaming response
  static createJSONStreamResponse(dataGenerator) {
    const stream = new PassThrough({ objectMode: true });
    
    // Write opening bracket
    stream.push('[\n');
    
    let first = true;
    
    async function writeData() {
      for await (const item of dataGenerator()) {
        if (!first) {
          stream.push(',\n');
        }
        first = false;
        
        const jsonString = JSON.stringify(item);
        
        // Check backpressure
        if (!stream.write(jsonString)) {
          // Wait for drain event
          await new Promise(resolve => stream.once('drain', resolve));
        }
      }
      
      // Write closing bracket
      stream.push('\n]');
      stream.end();
    }
    
    writeData().catch(error => {
      stream.emit('error', error);
    });
    
    return stream;
  }
}

// File upload with streaming validation
const multer = require('multer');
const { pipeline } = require('stream');

class StreamingFileUpload {
  constructor(options = {}) {
    this.maxSize = options.maxSize || 100 * 1024 * 1024; // 100MB
    this.allowedTypes = options.allowedTypes || ['image/', 'application/pdf'];
  }

  async processUpload(req, res) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      let totalSize = 0;
      let isValid = true;

      const validationStream = new Transform({
        transform(chunk, encoding, callback) {
          totalSize += chunk.length;
          
          // Check size limit
          if (totalSize > this.maxSize) {
            isValid = false;
            this.emit('error', new Error('File size exceeds limit'));
            return;
          }
          
          // Update hash
          hash.update(chunk);
          
          this.push(chunk);
          callback();
        }
      });

      // Check file type from first bytes
      const typeCheckStream = new Transform({
        transform(chunk, encoding, callback) {
          if (this.isFirstChunk) {
            const fileType = this.detectFileType(chunk);
            
            if (!this.isTypeAllowed(fileType)) {
              isValid = false;
              this.emit('error', new Error('File type not allowed'));
              return;
            }
            
            this.isFirstChunk = false;
          }
          
          this.push(chunk);
          callback();
        },
        
        detectFileType(chunk) {
          // Simple magic number detection
          if (chunk.slice(0, 4).toString('hex') === '89504e47') return 'image/png';
          if (chunk.slice(0, 3).toString() === 'GIF') return 'image/gif';
          if (chunk.slice(0, 2).toString('hex') === 'ffd8') return 'image/jpeg';
          if (chunk.slice(0, 4).toString() === '%PDF') return 'application/pdf';
          return 'unknown';
        },
        
        isTypeAllowed(fileType) {
          return this.allowedTypes.some(allowed => 
            fileType.startsWith(allowed)
          );
        }
      });

      // Process the file stream
      pipeline(
        req,
        validationStream,
        typeCheckStream,
        this.createProcessingStream(),
        (error) => {
          if (error) {
            reject(error);
          } else if (isValid) {
            resolve({
              hash: hash.digest('hex'),
              size: totalSize,
              success: true
            });
          } else {
            reject(new Error('File validation failed'));
          }
        }
      );
    });
  }

  createProcessingStream() {
    // Custom processing logic
    return new Transform({
      transform(chunk, encoding, callback) {
        // Example: Compress on the fly
        zlib.gzip(chunk, (error, compressed) => {
          if (error) {
            callback(error);
          } else {
            this.push(compressed);
            callback();
          }
        });
      }
    });
  }
}

// Database streaming for large result sets
class DatabaseStreamer {
  constructor(model) {
    this.model = model;
  }

  streamQuery(query, batchSize = 1000) {
    const cursor = this.model.find(query).cursor({ batchSize });
    const stream = new PassThrough({ objectMode: true });

    cursor.on('data', (doc) => {
      if (!stream.write(doc)) {
        // Pause cursor on backpressure
        cursor.pause();
        stream.once('drain', () => cursor.resume());
      }
    });

    cursor.on('end', () => {
      stream.end();
    });

    cursor.on('error', (error) => {
      stream.emit('error', error);
    });

    return stream;
  }

  async *streamQueryAsync(query, batchSize = 1000) {
    const cursor = this.model.find(query).cursor({ batchSize });
    
    for await (const doc of cursor) {
      yield doc;
    }
  }
}
```

---

## Query Optimization

### Advanced Query Optimization Techniques

```javascript
// query-optimizer.js
const mongoose = require('mongoose');

class QueryOptimizer {
  constructor() {
    this.queryCache = new Map();
    this.slowQueryThreshold = 100; // ms
    this.slowQueries = [];
  }

  // Index optimization suggestions
  analyzeIndexUsage(model, query) {
    const analysis = {
      suggestedIndexes: [],
      missingIndexes: [],
      redundantIndexes: []
    };

    // Analyze query conditions
    const conditions = this.extractConditions(query);
    
    conditions.forEach(condition => {
      if (this.shouldIndexField(condition.field, condition.operator)) {
        if (!this.hasIndexForField(model, condition.field)) {
          analysis.missingIndexes.push({
            field: condition.field,
            operator: condition.operator,
            type: this.getIndexType(condition.operator)
          });
        }
      }
    });

    // Check for compound indexes
    const compoundFields = conditions
      .filter(c => c.field !== '_id')
      .map(c => c.field);

    if (compoundFields.length > 1) {
      analysis.suggestedIndexes.push({
        fields: compoundFields,
        type: 'compound',
        order: 'asc'
      });
    }

    return analysis;
  }

  extractConditions(query) {
    const conditions = [];
    
    for (const [key, value] of Object.entries(query)) {
      if (value && typeof value === 'object') {
        // Handle operators like $gt, $lt, $in
        for (const [operator, opValue] of Object.entries(value)) {
          conditions.push({
            field: key,
            operator,
            value: opValue
          });
        }
      } else {
        conditions.push({
          field: key,
          operator: 'eq',
          value
        });
      }
    }
    
    return conditions;
  }

  shouldIndexField(field, operator) {
    // Fields that benefit from indexing
    const indexableFields = ['email', 'username', 'createdAt', 'status', 'category'];
    const indexableOperators = ['eq', 'in', 'gt', 'lt', 'gte', 'lte'];
    
    return indexableFields.includes(field) && 
           indexableOperators.includes(operator);
  }

  // Query execution optimization
  async optimizedFind(model, query, options = {}) {
    const {
      select = '',
      populate = '',
      limit = 100,
      skip = 0,
      sort = {},
      lean = true,
      explain = false,
      useCache = true
    } = options;

    const cacheKey = this.generateCacheKey(model.modelName, query, options);
    
    if (useCache && this.queryCache.has(cacheKey)) {
      return this.queryCache.get(cacheKey);
    }

    const startTime = Date.now();
    
    let mongooseQuery = model.find(query);

    // Apply optimizations
    if (select) {
      mongooseQuery = mongooseQuery.select(select);
    }
    
    if (populate) {
      mongooseQuery = mongooseQuery.populate(populate);
    }
    
    if (Object.keys(sort).length > 0) {
      mongooseQuery = mongooseQuery.sort(sort);
    }
    
    if (skip > 0) {
      mongooseQuery = mongooseQuery.skip(skip);
    }
    
    if (limit > 0) {
      mongooseQuery = mongooseQuery.limit(limit);
    }
    
    if (lean) {
      mongooseQuery = mongooseQuery.lean();
    }
    
    if (explain) {
      mongooseQuery = mongooseQuery.explain('executionStats');
    }

    const result = await mongooseQuery.exec();
    const executionTime = Date.now() - startTime;

    // Track slow queries
    if (executionTime > this.slowQueryThreshold) {
      this.trackSlowQuery({
        model: model.modelName,
        query,
        executionTime,
        options
      });
    }

    // Cache result if appropriate
    if (useCache && this.shouldCacheQuery(query, options)) {
      this.queryCache.set(cacheKey, result);
      // Set TTL for cache entry
      setTimeout(() => {
        this.queryCache.delete(cacheKey);
      }, 60000); // 1 minute
    }

    return result;
  }

  generateCacheKey(modelName, query, options) {
    const queryString = JSON.stringify(query);
    const optionsString = JSON.stringify(options);
    
    return `${modelName}:${require('crypto')
      .createHash('md5')
      .update(queryString + optionsString)
      .digest('hex')}`;
  }

  shouldCacheQuery(query, options) {
    // Don't cache queries with skip/limit for pagination
    if (options.skip !== undefined || options.limit !== undefined) {
      return false;
    }
    
    // Don't cache queries that change frequently
    const volatileFields = ['updatedAt', 'status'];
    const hasVolatileField = Object.keys(query).some(field => 
      volatileFields.includes(field)
    );
    
    return !hasVolatileField;
  }

  trackSlowQuery(queryInfo) {
    this.slowQueries.push({
      ...queryInfo,
      timestamp: new Date().toISOString()
    });
    
    // Keep only last 1000 slow queries
    if (this.slowQueries.length > 1000) {
      this.slowQueries.shift();
    }
  }

  // Query batching for N+1 problem
  async batchQueries(model, ids, options = {}) {
    const {
      field = '_id',
      batchSize = 1000,
      concurrency = 5
    } = options;

    const batches = [];
    
    for (let i = 0; i < ids.length; i += batchSize) {
      batches.push(ids.slice(i, i + batchSize));
    }

    const results = [];
    
    for (let i = 0; i < batches.length; i += concurrency) {
      const batchPromises = batches
        .slice(i, i + concurrency)
        .map(batch => 
          model.find({ [field]: { $in: batch } }).lean().exec()
        );
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults.flat());
    }

    // Map results back to original order
    const resultMap = new Map();
    results.forEach(item => {
      resultMap.set(item[field].toString(), item);
    });

    return ids.map(id => resultMap.get(id.toString()) || null);
  }

  // Query plan analysis
  async analyzeQueryPlan(model, query) {
    const explainResult = await model.find(query).explain('executionStats');
    
    const analysis = {
      winningPlan: explainResult.queryPlanner.winningPlan,
      executionStats: explainResult.executionStats,
      suggestions: []
    };

    // Analyze execution stats
    const stats = explainResult.executionStats;
    
    if (stats.totalDocsExamined > stats.nReturned * 10) {
      analysis.suggestions.push(
        'Query examines many more documents than it returns. Consider adding indexes.'
      );
    }
    
    if (stats.executionTimeMillis > this.slowQueryThreshold) {
      analysis.suggestions.push(
        `Query is slow (${stats.executionTimeMillis}ms). Consider optimization.`
      );
    }
    
    if (stats.stage === 'COLLSCAN') {
      analysis.suggestions.push(
        'Query is performing a collection scan. Add appropriate indexes.'
      );
    }

    return analysis;
  }
}

// Database connection pooling optimization
const mongoose = require('mongoose');

class ConnectionPoolManager {
  constructor() {
    this.poolStats = {
      connections: 0,
      available: 0,
      pending: 0
    };
  }

  setupOptimalPool() {
    // Configure mongoose connection pool
    const options = {
      poolSize: 10, // Maximum number of sockets in the pool
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      maxPoolSize: 100,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      waitQueueTimeoutMS: 10000
    };

    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to MongoDB');
      this.startMonitoring();
    });

    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected');
    });

    this.startConnectionHealthCheck();
  }

  startMonitoring() {
    setInterval(() => {
      const pool = mongoose.connections[0].poolSize;
      const available = mongoose.connections[0].available;
      
      this.poolStats = {
        connections: pool,
        available: available,
        pending: mongoose.connections[0].pending
      };

      // Adjust pool size based on load
      this.autoScalePool();
    }, 30000); // Every 30 seconds
  }

  autoScalePool() {
    const { connections, pending } = this.poolStats;
    
    if (pending > 10 && connections < 50) {
      // Increase pool size
      mongoose.connections[0].poolSize = Math.min(connections + 5, 100);
    } else if (pending === 0 && connections > 10) {
      // Decrease pool size
      mongoose.connections[0].poolSize = Math.max(connections - 2, 5);
    }
  }

  startConnectionHealthCheck() {
    setInterval(async () => {
      try {
        // Run a simple query to check connection health
        await mongoose.connection.db.admin().ping();
      } catch (error) {
        console.error('Database connection health check failed:', error);
        this.handleConnectionFailure();
      }
    }, 60000); // Every minute
  }

  handleConnectionFailure() {
    // Implement reconnection logic
    mongoose.disconnect();
    
    setTimeout(() => {
      mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
    }, 5000);
  }
}
```

---

## Load Testing with Artillery/JMeter

### Artillery Implementation

```javascript
// artillery-config.yml
config:
  target: "https://api.example.com"
  phases:
    - duration: 60
      arrivalRate: 10
      name: "Warm up"
    - duration: 300
      arrivalRate: 50
      rampTo: 200
      name: "Load test"
    - duration: 60
      arrivalRate: 10
      name: "Cool down"
  defaults:
    headers:
      Content-Type: "application/json"
      Authorization: "Bearer {{ $processEnvironment.API_TOKEN }}"
  plugins:
    ensure: {}
    apdex: {}
    metrics-by-endpoint: {}
  # HTTP/2 support
  http:
    pool: 10
    timeout: 30
    maxSockets: 100
    rejectUnauthorized: false

scenarios:
  - name: "User authentication flow"
    flow:
      - post:
          url: "/api/v1/auth/login"
          json:
            email: "user{{ $randomNumber(1000, 9999) }}@test.com"
            password: "password123"
          capture:
            json: "$.token"
            as: "authToken"
      
      - think: 2
      
      - get:
          url: "/api/v1/users/me"
          headers:
            Authorization: "Bearer {{ authToken }}"
      
      - think: 1
      
      - post:
          url: "/api/v1/products"
          headers:
            Authorization: "Bearer {{ authToken }}"
          json:
            name: "Test Product {{ $randomNumber(1, 1000) }}"
            price: "{{ $randomNumber(10, 1000) }}"
          capture:
            json: "$.id"
            as: "productId"
      
      - think: 3
      
      - delete:
          url: "/api/v1/products/{{ productId }}"
          headers:
            Authorization: "Bearer {{ authToken }}"

  - name: "Product search and browse"
    weight: 3
    flow:
      - get:
          url: "/api/v1/products"
          qs:
            page: "{{ $randomNumber(1, 10) }}"
            limit: "20"
            sort: "-createdAt"
      
      - think: 1
      
      - get:
          url: "/api/v1/products/search"
          qs:
            q: "test"
            category: "{{ $randomElement(['electronics', 'clothing', 'books']) }}"

  - name: "Heavy file upload"
    weight: 1
    flow:
      - post:
          url: "/api/v1/upload"
          headers:
            Authorization: "Bearer {{ $processEnvironment.API_TOKEN }}"
          beforeRequest: "setUploadHeaders"
          afterResponse: "validateUploadResponse"

processor: "./artillery-hooks.js"

# Custom metrics
ensure:
  thresholds:
    - http.response_time.p99: 500
    - http.response_time.median: 200
    - http.errors: 0.01
    - http.codes.200: 0.95

# WebSocket testing
ws:
  scenarios:
    - name: "Real-time updates"
      engine: "ws"
      flow:
        - send: '{"type":"subscribe","channel":"prices"}'
        - think: 5
        - send: '{"type":"unsubscribe","channel":"prices"}'
        - close:

# artillery-hooks.js - Custom hooks
module.exports = {
  setUploadHeaders: (requestParams, context, ee, next) => {
    // Generate random file content
    const fileSize = 1024 * 1024; // 1MB
    const buffer = Buffer.alloc(fileSize, 'x');
    
    requestParams.headers['Content-Type'] = 'multipart/form-data';
    requestParams.body = buffer;
    
    next();
  },

  validateUploadResponse: (requestParams, response, context, ee, next) => {
    if (response.statusCode !== 200) {
      ee.emit('counter', 'upload.errors', 1);
    }
    
    // Parse response and store data for future requests
    try {
      const body = JSON.parse(response.body);
      context.vars.uploadId = body.id;
    } catch (error) {
      // Ignore parsing errors
    }
    
    next();
  },

  generateTestData: (userContext, events, done) => {
    // Generate dynamic test data
    userContext.vars.userId = require('crypto')
      .randomBytes(16)
      .toString('hex');
    
    userContext.vars.orderAmount = Math.floor(Math.random() * 1000) + 1;
    
    done();
  },

  customMetric: (userContext, events, done) => {
    // Track custom business metrics
    events.emit('histogram', 'order.value', userContext.vars.orderAmount);
    done();
  }
};

// Run script
// artillery run --output report.json artillery-config.yml
// artillery report report.json
```

### JMeter Test Plan Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.5">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="API Load Test">
      <boolProp name="TestPlan.functional_mode">false</boolProp>
      <boolProp name="TestPlan.tearDown_on_shutdown">true</boolProp>
      <boolProp name="TestPlan.serialize_threadgroups">false</boolProp>
      <elementProp name="TestPlan.user_defined_variables" elementType="Arguments">
        <collectionProp name="Arguments.arguments">
          <elementProp name="base_url" elementType="Argument">
            <stringProp name="Argument.name">base_url</stringProp>
            <stringProp name="Argument.value">https://api.example.com</stringProp>
            <stringProp name="Argument.metadata">=</stringProp>
          </elementProp>
          <elementProp name="thread_count" elementType="Argument">
            <stringProp name="Argument.name">thread_count</stringProp>
            <stringProp name="Argument.value">100</stringProp>
            <stringProp name="Argument.metadata">=</stringProp>
          </elementProp>
        </collectionProp>
      </elementProp>
    </TestPlan>
    <hashTree>
      
      <!-- Thread Group: User Registration -->
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="User Registration Flow">
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController">
          <boolProp name="LoopController.continue_forever">false</boolProp>
          <intProp name="LoopController.loops">-1</intProp>
        </elementProp>
        <stringProp name="ThreadGroup.num_threads">${thread_count}</stringProp>
        <stringProp name="ThreadGroup.ramp_time">60</stringProp>
        <boolProp name="ThreadGroup.scheduler">true</boolProp>
        <stringProp name="ThreadGroup.duration">300</stringProp>
        <stringProp name="ThreadGroup.delay">0</stringProp>
      </ThreadGroup>
      <hashTree>
        
        <!-- HTTP Request: Register User -->
        <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="Register User">
          <boolProp name="HTTPSampler.postBodyRaw">true</boolProp>
          <elementProp name="HTTPsampler.Arguments" elementType="Arguments">
            <collectionProp name="Arguments.arguments">
              <elementProp name="" elementType="HTTPArgument">
                <boolProp name="HTTPArgument.always_encode">false</boolProp>
                <stringProp name="Argument.value">{&quot;email&quot;:&quot;test${__Random(1,10000)}@example.com&quot;,&quot;password&quot;:&quot;password123&quot;,&quot;name&quot;:&quot;Test User ${__Random(1,1000)}&quot;}</stringProp>
                <stringProp name="Argument.metadata">=</stringProp>
              </elementProp>
            </collectionProp>
          </elementProp>
          <stringProp name="HTTPSampler.domain">${base_url}</stringProp>
          <stringProp name="HTTPSampler.port"></stringProp>
          <stringProp name="HTTPSampler.protocol">https</stringProp>
          <stringProp name="HTTPSampler.contentEncoding"></stringProp>
          <stringProp name="HTTPSampler.path">/api/v1/auth/register</stringProp>
          <stringProp name="HTTPSampler.method">POST</stringProp>
          <boolProp name="HTTPSampler.follow_redirects">true</boolProp>
          <boolProp name="HTTPSampler.auto_redirects">false</boolProp>
          <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
          <boolProp name="HTTPSampler.DO_MULTIPART_POST">false</boolProp>
          <boolProp name="HTTPSampler.BROWSER_COMPATIBLE_MULTIPART">true</boolProp>
          <boolProp name="HTTPSampler.monitor">false</boolProp>
          <stringProp name="HTTPSampler.embedded_url_re"></stringProp>
        </HTTPSamplerProxy>
        
        <!-- JSON Extractor to get token -->
        <JSONPostProcessor guiclass="JSONPostProcessorGui" testclass="JSONPostProcessor" testname="Extract Auth Token">
          <stringProp name="JSONPostProcessor.referenceNames">authToken</stringProp>
          <stringProp name="JSONPostProcessor.jsonPathExpr">$.token</stringProp>
          <stringProp name="JSONPostProcessor.match_numbers">0</stringProp>
          <stringProp name="JSONPostProcessor.defaultValues">NOT_FOUND</stringProp>
        </JSONPostProcessor>
        
        <!-- User-defined Variables -->
        <Arguments guiclass="ArgumentsPanel" testclass="Arguments" testname="User Variables">
          <collectionProp name="Arguments.arguments">
            <elementProp name="authToken" elementType="Argument">
              <stringProp name="Argument.name">authToken</stringProp>
              <stringProp name="Argument.value">${authToken}</stringProp>
              <stringProp name="Argument.metadata">=</stringProp>
            </elementProp>
          </collectionProp>
        </Arguments>
        
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>
```

### Automated Load Testing Script

```javascript
// load-test-runner.js
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

class LoadTestRunner {
  constructor(config) {
    this.config = {
      artilleryPath: './node_modules/.bin/artillery',
      jmeterPath: '/opt/apache-jmeter/bin/jmeter',
      resultsDir: './test-results',
      ...config
    };
  }

  async runArtilleryTest(testConfig, environment = 'staging') {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportFile = path.join(
      this.config.resultsDir,
      `artillery-report-${timestamp}.json`
    );
    
    const htmlReport = path.join(
      this.config.resultsDir,
      `artillery-report-${timestamp}.html`
    );

    // Create test config with environment variables
    const configWithEnv = this.injectEnvironmentVariables(testConfig, environment);
    const configFile = path.join(this.config.resultsDir, `config-${timestamp}.yml`);
    
    fs.writeFileSync(configFile, configWithEnv);

    return new Promise((resolve, reject) => {
      const command = `${this.config.artilleryPath} run --output ${reportFile} ${configFile}`;
      
      console.log(`Running Artillery test: ${command}`);
      
      const child = exec(command, { maxBuffer: 1024 * 1024 * 10 });
      
      let output = '';
      
      child.stdout.on('data', (data) => {
        output += data;
        console.log(data.toString());
      });
      
      child.stderr.on('data', (data) => {
        console.error(data.toString());
      });
      
      child.on('close', async (code) => {
        if (code === 0) {
          console.log('Artillery test completed');
          
          // Generate HTML report
          await this.generateArtilleryReport(reportFile, htmlReport);
          
          // Analyze results
          const results = await this.analyzeArtilleryResults(reportFile);
          
          resolve({
            success: true,
            reportFile,
            htmlReport,
            results
          });
        } else {
          reject(new Error(`Artillery test failed with code ${code}`));
        }
      });
    });
  }

  injectEnvironmentVariables(config, environment) {
    const envVars = this.getEnvironmentVariables(environment);
    
    // Replace environment variables in config
    let configString = config.toString();
    
    Object.entries(envVars).forEach(([key, value]) => {
      const regex = new RegExp(`\\{\\{\\s*\\$processEnvironment\\.${key}\\s*\\}\\}`, 'g');
      configString = configString.replace(regex, value);
    });
    
    return configString;
  }

  getEnvironmentVariables(environment) {
    // Load from environment-specific files
    const envFile = `.env.${environment}`;
    
    if (fs.existsSync(envFile)) {
      const content = fs.readFileSync(envFile, 'utf8');
      const vars = {};
      
      content.split('\n').forEach(line => {
        const match = line.match(/^([^=]+)=(.*)$/);
        if (match) {
          vars[match[1]] = match[2];
        }
      });
      
      return vars;
    }
    
    return process.env;
  }

  async generateArtilleryReport(jsonReport, htmlReport) {
    return new Promise((resolve, reject) => {
      const command = `${this.config.artilleryPath} report ${jsonReport} --output ${htmlReport}`;
      
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error('Failed to generate report:', stderr);
          reject(error);
        } else {
          console.log('HTML report generated:', htmlReport);
          resolve();
        }
      });
    });
  }

  async analyzeArtilleryResults(reportFile) {
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    
    const analysis = {
      summary: {
        duration: report.aggregate.phases.map(p => p.duration).reduce((a, b) => a + b, 0),
        requests: report.aggregate.counters['http.requests'] || 0,
        errors: report.aggregate.counters['http.errors'] || 0,
        errorRate: 0,
        rps: report.aggregate.rps.mean || 0
      },
      thresholds: {},
      recommendations: []
    };

    // Calculate error rate
    if (analysis.summary.requests > 0) {
      analysis.summary.errorRate = (analysis.summary.errors / analysis.summary.requests) * 100;
    }

    // Check response times
    const p99 = report.aggregate.summaries['http.response_time'].p99;
    const median = report.aggregate.summaries['http.response_time'].median;

    analysis.thresholds.p99 = p99;
    analysis.thresholds.median = median;

    // Generate recommendations
    if (p99 > 1000) {
      analysis.recommendations.push('P99 response time exceeds 1 second. Consider optimizing slow endpoints.');
    }

    if (analysis.summary.errorRate > 1) {
      analysis.recommendations.push(`Error rate is ${analysis.summary.errorRate.toFixed(2)}%. Investigate failed requests.`);
    }

    // Identify slowest endpoints
    if (report.aggregate.scenarios) {
      const slowEndpoints = Object.entries(report.aggregate.scenarios)
        .filter(([_, stats]) => stats.phases)
        .flatMap(([scenario, stats]) => 
          stats.phases.map(phase => ({
            scenario,
            phase: phase.name,
            p99: phase.latency.p99,
            rps: phase.rps.mean
          }))
        )
        .sort((a, b) => b.p99 - a.p99)
        .slice(0, 5);

      analysis.slowEndpoints = slowEndpoints;
    }

    return analysis;
  }

  async runStressTest(endpoint, options = {}) {
    const {
      concurrentUsers = 100,
      duration = 300, // seconds
      rampUpTime = 60,
      method = 'GET',
      headers = {},
      body = null
    } = options;

    const testId = Date.now();
    const results = {
      testId,
      startTime: new Date().toISOString(),
      requests: [],
      errors: []
    };

    const makeRequest = async (userId) => {
      const start = Date.now();
      
      try {
        const response = await axios({
          method,
          url: endpoint,
          headers,
          data: body,
          timeout: 30000
        });
        
        const duration = Date.now() - start;
        
        results.requests.push({
          userId,
          duration,
          status: response.status,
          timestamp: new Date().toISOString()
        });
        
        return { success: true, duration };
      } catch (error) {
        const duration = Date.now() - start;
        
        results.errors.push({
          userId,
          duration,
          error: error.message,
          timestamp: new Date().toISOString()
        });
        
        return { success: false, duration, error: error.message };
      }
    };

    // Create user pool
    const users = Array.from({ length: concurrentUsers }, (_, i) => i);
    
    // Ramp up users gradually
    console.log(`Ramping up ${concurrentUsers} users over ${rampUpTime} seconds`);
    
    const rampUpBatch = Math.ceil(concurrentUsers / (rampUpTime / 5));
    
    for (let i = 0; i < concurrentUsers; i += rampUpBatch) {
      const batch = users.slice(i, i + rampUpBatch);
      
      batch.forEach(userId => {
        // Start making requests for this user
        const interval = setInterval(() => {
          makeRequest(userId);
        }, Math.random() * 1000 + 500); // Random interval between requests
      });
      
      await this.sleep(5000); // Wait 5 seconds between batches
    }

    // Run test for duration
    console.log(`Running stress test for ${duration} seconds`);
    await this.sleep(duration * 1000);

    // Calculate statistics
    results.endTime = new Date().toISOString();
    results.totalDuration = Date.parse(results.endTime) - Date.parse(results.startTime);
    results.totalRequests = results.requests.length;
    results.totalErrors = results.errors.length;
    
    if (results.totalRequests > 0) {
      results.successRate = ((results.totalRequests - results.totalErrors) / results.totalRequests) * 100;
      results.avgResponseTime = results.requests.reduce((sum, req) => sum + req.duration, 0) / results.totalRequests;
      results.rps = results.totalRequests / (results.totalDuration / 1000);
    }

    // Find percentiles
    const durations = results.requests.map(r => r.duration).sort((a, b) => a - b);
    
    if (durations.length > 0) {
      results.p50 = durations[Math.floor(durations.length * 0.5)];
      results.p95 = durations[Math.floor(durations.length * 0.95)];
      results.p99 = durations[Math.floor(durations.length * 0.99)];
    }

    return results;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async monitorDuringTest(monitorUrl, interval = 5000) {
    const metrics = [];
    let monitoring = true;

    const monitor = setInterval(async () => {
      try {
        const response = await axios.get(monitorUrl, { timeout: 3000 });
        metrics.push({
          timestamp: new Date().toISOString(),
          ...response.data
        });
      } catch (error) {
        console.error('Monitoring failed:', error.message);
      }
    }, interval);

    return {
      stop: () => {
        clearInterval(monitor);
        monitoring = false;
        return metrics;
      },
      getMetrics: () => metrics
    };
  }
}
```

---

## PM2 Process Manager

### Advanced PM2 Configuration

```javascript
// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'api-primary',
      script: './src/server.js',
      instances: 'max', // Use all CPU cores
      exec_mode: 'cluster',
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        NODE_OPTIONS: '--max-old-space-size=4096'
      },
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 3001
      },
      env_development: {
        NODE_ENV: 'development',
        PORT: 3002,
        NODE_OPTIONS: '--inspect=9229'
      },
      
      // Logging configuration
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: '/var/log/pm2/api-error.log',
      out_file: '/var/log/pm2/api-out.log',
      merge_logs: true,
      time: true,
      
      // Process management
      kill_timeout: 5000,
      wait_ready: true,
      listen_timeout: 5000,
      shutdown_with_message: true,
      
      // Auto-restart policies
      autorestart: true,
      restart_delay: 3000,
      exp_backoff_restart_delay: 100,
      max_restarts: 10,
      min_uptime: '10s',
      
      // Monitoring
      vizion: true, // Enable git integration
      post_update: ['npm install', 'echo Applying migrations...'],
      
      // Control flow hooks
      pre_start: 'scripts/pre-start.sh',
      post_start: 'scripts/post-start.sh',
      pre_restart: 'scripts/pre-restart.sh',
      post_restart: 'scripts/post-restart.sh',
      pre_stop: 'scripts/pre-stop.sh'
    },
    {
      name: 'api-worker',
      script: './src/workers/main.js',
      instances: 2,
      exec_mode: 'cluster',
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        WORKER_TYPE: 'processing'
      }
    },
    {
      name: 'api-cron',
      script: './src/cron.js',
      instances: 1,
      exec_mode: 'fork',
      cron_restart: '0 */6 * * *', // Restart every 6 hours
      env: {
        NODE_ENV: 'production'
      }
    }
  ],

  // Deployment configuration
  deploy: {
    production: {
      user: 'deploy',
      host: ['server1.example.com', 'server2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:username/repo.git',
      path: '/var/www/api',
      'post-deploy': `
        npm install --production
        npm run build
        pm2 reload ecosystem.config.js --env production
        pm2 save
      `,
      env: {
        NODE_ENV: 'production'
      }
    },
    staging: {
      user: 'deploy',
      host: 'staging.example.com',
      ref: 'origin/develop',
      repo: 'git@github.com:username/repo.git',
      path: '/var/www/staging-api',
      'post-deploy': `
        npm install
        npm run build
        pm2 reload ecosystem.config.js --env staging
      `,
      env: {
        NODE_ENV: 'staging'
      }
    }
  }
};

// pm2-monitor.js - Advanced monitoring
const pm2 = require('pm2');
const os = require('os');
const axios = require('axios');

class PM2Monitor {
  constructor() {
    this.metrics = {
      processes: [],
      system: {},
      alerts: []
    };
    
    this.alertThresholds = {
      memory: 80, // percentage
      cpu: 70,
      restarts: 5,
      uptime: 60000 // 1 minute minimum
    };
  }

  connect() {
    return new Promise((resolve, reject) => {
      pm2.connect((err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  async startMonitoring(interval = 10000) {
    await this.connect();
    
    setInterval(async () => {
      await this.collectMetrics();
      await this.checkThresholds();
      await this.sendMetrics();
    }, interval);
  }

  async collectMetrics() {
    return new Promise((resolve, reject) => {
      pm2.list((err, processes) => {
        if (err) {
          reject(err);
        } else {
          this.metrics.processes = processes.map(proc => ({
            name: proc.name,
            pid: proc.pid,
            pm_id: proc.pm_id,
            status: proc.pm2_env.status,
            cpu: proc.monit.cpu,
            memory: proc.monit.memory,
            uptime: Date.now() - proc.pm2_env.pm_uptime,
            restarts: proc.pm2_env.restart_time,
            unstable_restarts: proc.pm2_env.unstable_restarts
          }));
          
          // System metrics
          this.metrics.system = {
            timestamp: new Date().toISOString(),
            loadAverage: os.loadavg(),
            freeMemory: os.freemem(),
            totalMemory: os.totalmem(),
            uptime: os.uptime(),
            cpus: os.cpus().length
          };
          
          resolve();
        }
      });
    });
  }

  async checkThresholds() {
    for (const proc of this.metrics.processes) {
      // Memory threshold check
      const memoryPercentage = (proc.memory / this.metrics.system.totalMemory) * 100;
      
      if (memoryPercentage > this.alertThresholds.memory) {
        this.addAlert({
          type: 'high_memory',
          process: proc.name,
          value: memoryPercentage.toFixed(2),
          threshold: this.alertThresholds.memory,
          timestamp: new Date().toISOString()
        });
      }
      
      // CPU threshold check
      if (proc.cpu > this.alertThresholds.cpu) {
        this.addAlert({
          type: 'high_cpu',
          process: proc.name,
          value: proc.cpu,
          threshold: this.alertThresholds.cpu,
          timestamp: new Date().toISOString()
        });
      }
      
      // Frequent restarts check
      if (proc.restarts > this.alertThresholds.restarts) {
        this.addAlert({
          type: 'frequent_restarts',
          process: proc.name,
          value: proc.restarts,
          threshold: this.alertThresholds.restarts,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  addAlert(alert) {
    this.metrics.alerts.push(alert);
    
    // Keep only last 100 alerts
    if (this.metrics.alerts.length > 100) {
      this.metrics.alerts.shift();
    }
    
    // Send real-time alert (e.g., to Slack, PagerDuty)
    this.sendAlert(alert);
  }

  async sendAlert(alert) {
    // Example: Send to Slack
    const slackWebhook = process.env.SLACK_WEBHOOK_URL;
    
    if (slackWebhook) {
      const message = {
        text: `🚨 PM2 Alert: ${alert.type}`,
        attachments: [{
          color: 'danger',
          fields: [
            { title: 'Process', value: alert.process, short: true },
            { title: 'Value', value: `${alert.value}%`, short: true },
            { title: 'Threshold', value: `${alert.threshold}%`, short: true },
            { title: 'Time', value: alert.timestamp, short: true }
          ]
        }]
      };
      
      try {
        await axios.post(slackWebhook, message);
      } catch (error) {
        console.error('Failed to send Slack alert:', error.message);
      }
    }
  }

  async sendMetrics() {
    // Send metrics to monitoring service (e.g., Datadog, Prometheus)
    const metricsEndpoint = process.env.METRICS_ENDPOINT;
    
    if (metricsEndpoint) {
      try {
        await axios.post(metricsEndpoint, this.metrics, {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        console.error('Failed to send metrics:', error.message);
      }
    }
  }

  async gracefulRestart(processName) {
    return new Promise((resolve, reject) => {
      pm2.restart(processName, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  async scaleProcess(processName, instances) {
    return new Promise((resolve, reject) => {
      pm2.scale(processName, instances, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  async autoScaleBasedOnLoad() {
    const loadAverage = os.loadavg()[0]; // 1-minute load average
    const cpuCount = os.cpus().length;
    
    // If load average exceeds 70% of CPU capacity, scale up
    if (loadAverage > cpuCount * 0.7) {
      const processes = this.metrics.processes;
      
      for (const proc of processes) {
        if (proc.name.startsWith('api-primary')) {
          const currentInstances = processes.filter(p => p.name === proc.name).length;
          const newInstances = Math.min(currentInstances + 1, cpuCount * 2);
          
          if (newInstances > currentInstances) {
            console.log(`Scaling ${proc.name} from ${currentInstances} to ${newInstances} instances`);
            await this.scaleProcess(proc.name, newInstances);
          }
        }
      }
    }
  }
}

// Zero-downtime deployment script
const shell = require('shelljs');

class ZeroDowntimeDeploy {
  constructor() {
    this.backupDir = '/tmp/pm2-backup';
  }

  async deploy() {
    try {
      // 1. Backup current deployment
      await this.backupCurrent();
      
      // 2. Pull latest changes
      await this.pullChanges();
      
      // 3. Install dependencies
      await this.installDependencies();
      
      // 4. Run tests
      await this.runTests();
      
      // 5. Graceful reload
      await this.gracefulReload();
      
      // 6. Verify deployment
      await this.verifyDeployment();
      
      console.log('Deployment completed successfully');
      
    } catch (error) {
      console.error('Deployment failed:', error);
      
      // Rollback on failure
      await this.rollback();
      throw error;
    }
  }

  async backupCurrent() {
    console.log('Backing up current deployment...');
    
    shell.mkdir('-p', this.backupDir);
    shell.cp('-r', './*', this.backupDir);
    
    // Backup PM2 processes
    shell.exec('pm2 save', { silent: true });
  }

  async pullChanges() {
    console.log('Pulling latest changes...');
    
    const branch = process.env.BRANCH || 'main';
    const result = shell.exec(`git pull origin ${branch}`, { silent: true });
    
    if (result.code !== 0) {
      throw new Error('Git pull failed');
    }
  }

  async installDependencies() {
    console.log('Installing dependencies...');
    
    const result = shell.exec('npm ci --production', { silent: true });
    
    if (result.code !== 0) {
      throw new Error('npm install failed');
    }
  }

  async runTests() {
    console.log('Running tests...');
    
    if (shell.test('-f', 'package.json') && 
        JSON.parse(shell.cat('package.json')).scripts.test) {
      const result = shell.exec('npm test', { silent: true });
      
      if (result.code !== 0) {
        throw new Error('Tests failed');
      }
    }
  }

  async gracefulReload() {
    console.log('Performing graceful reload...');
    
    // Start new instances before stopping old ones
    const result = shell.exec('pm2 reload ecosystem.config.js --update-env', { silent: true });
    
    if (result.code !== 0) {
      throw new Error('PM2 reload failed');
    }
    
    // Wait for new instances to be ready
    await this.sleep(5000);
    
    // Delete old instances
    shell.exec('pm2 delete all', { silent: true });
    shell.exec('pm2 start ecosystem.config.js', { silent: true });
  }

  async verifyDeployment() {
    console.log('Verifying deployment...');
    
    // Check if processes are running
    const result = shell.exec('pm2 status', { silent: true });
    
    if (result.code !== 0 || result.stdout.includes('errored')) {
      throw new Error('Deployment verification failed');
    }
    
    // Health check
    const healthResult = shell.exec('curl -f http://localhost:3000/health', { silent: true });
    
    if (healthResult.code !== 0) {
      throw new Error('Health check failed');
    }
  }

  async rollback() {
    console.log('Rolling back to previous version...');
    
    // Restore from backup
    if (shell.test('-d', this.backupDir)) {
      shell.cp('-r', `${this.backupDir}/*`, './');
      
      // Restart with backup
      shell.exec('pm2 delete all', { silent: true });
      shell.exec('pm2 start ecosystem.config.js', { silent: true });
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

---

## Logging with Pino

### Advanced Pino Configuration

```javascript
// logger.js
const pino = require('pino');
const pinoHttp = require('pino-http');
const os = require('os');
const fs = require('fs');
const path = require('path');

class LoggerFactory {
  static createLogger(options = {}) {
    const {
      name = 'app',
      level = process.env.LOG_LEVEL || 'info',
      environment = process.env.NODE_ENV || 'development',
      enableFileLogging = true,
      enableConsoleLogging = true,
      enableHttpLogging = true
    } = options;

    const streams = [];

    // Console stream for development
    if (enableConsoleLogging) {
      streams.push({
        level: environment === 'production' ? 'info' : 'debug',
        stream: pino.transport({
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname'
          }
        })
      });
    }

    // File streams for production
    if (enableFileLogging) {
      const logDir = path.join(__dirname, '../logs');
      
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }

      // Error logs
      streams.push({
        level: 'error',
        stream: pino.destination({
          dest: path.join(logDir, 'error.log'),
          sync: false,
          minLength: 4096
        })
      });

      // Combined logs
      streams.push({
        level: 'info',
        stream: pino.destination({
          dest: path.join(logDir, 'combined.log'),
          sync: false,
          minLength: 4096
        })
      });

      // Debug logs (development only)
      if (environment !== 'production') {
        streams.push({
          level: 'debug',
          stream: pino.destination({
            dest: path.join(logDir, 'debug.log'),
            sync: false
          })
        });
      }
    }

    // Create logger instance
    const logger = pino(
      {
        name,
        level,
        timestamp: pino.stdTimeFunctions.isoTime,
        serializers: {
          err: pino.stdSerializers.err,
          req: pino.stdSerializers.req,
          res: pino.stdSerializers.res,
          error: pino.stdSerializers.err
        },
        base: {
          pid: process.pid,
          hostname: os.hostname(),
          environment
        },
        formatters: {
          level: (label) => {
            return { level: label.toUpperCase() };
          },
          bindings: (bindings) => {
            return {
              pid: bindings.pid,
              hostname: bindings.hostname,
              environment: bindings.environment
            };
          }
        },
        redact: {
          paths: [
            'password',
            '*.password',
            'token',
            '*.token',
            'authorization',
            '*.authorization',
            'creditCard',
            '*.creditCard',
            'ssn',
            '*.ssn'
          ],
          censor: '[REDACTED]'
        },
        transport: environment === 'development' ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname'
          }
        } : undefined
      },
      pino.multistream(streams)
    );

    // Add custom methods
    logger.audit = (event, data) => {
      logger.info({
        type: 'audit',
        event,
        ...data,
        timestamp: new Date().toISOString(),
        userId: data.userId || 'system'
      });
    };

    logger.metric = (name, value, tags = {}) => {
      logger.info({
        type: 'metric',
        name,
        value,
        tags,
        timestamp: new Date().toISOString()
      });
    };

    logger.business = (event, data) => {
      logger.info({
        type: 'business',
        event,
        ...data,
        timestamp: new Date().toISOString()
      });
    };

    logger.perf = (operation, duration, context = {}) => {
      logger.info({
        type: 'performance',
        operation,
        duration,
        ...context,
        timestamp: new Date().toISOString()
      });
    };

    return logger;
  }

  static createHttpLogger(logger, options = {}) {
    const {
      autoLogging = true,
      quietReqLogger = false,
      customSuccessMessage = (res) => {
        return `HTTP ${res.req.method} ${res.req.url} ${res.statusCode}`;
      },
      customErrorMessage = (error, res) => {
        return `HTTP ${res.req.method} ${res.req.url} ${res.statusCode} - ${error.message}`;
      }
    } = options;

    return pinoHttp({
      logger,
      autoLogging,
      quietReqLogger,
      customSuccessMessage,
      customErrorMessage,
      serializers: {
        req: (req) => {
          const serialized = pino.stdSerializers.req(req);
          // Add additional request context
          serialized.ip = req.ip;
          serialized.userAgent = req.headers['user-agent'];
          serialized.referer = req.headers.referer;
          return serialized;
        },
        res: (res) => {
          const serialized = pino.stdSerializers.res(res);
          // Add response time
          serialized.responseTime = res.responseTime;
          return serialized;
        }
      },
      customAttributeKeys: {
        req: 'request',
        res: 'response',
        err: 'error',
        responseTime: 'responseTime'
      },
      wrapSerializers: false,
      reqCustomProps: (req) => {
        return {
          requestId: req.id,
          userId: req.user?.id,
          sessionId: req.session?.id
        };
      }
    });
  }
}

// Structured logging with correlation IDs
const { v4: uuidv4 } = require('uuid');

class CorrelationLogger {
  constructor(baseLogger) {
    this.baseLogger = baseLogger;
  }

  middleware() {
    return (req, res, next) => {
      const correlationId = req.headers['x-correlation-id'] || uuidv4();
      
      // Store in request for later use
      req.correlationId = correlationId;
      
      // Create child logger with correlation ID
      req.log = this.baseLogger.child({ correlationId });
      
      // Add correlation ID to response headers
      res.setHeader('X-Correlation-ID', correlationId);
      
      next();
    };
  }

  child(correlationId, additionalContext = {}) {
    return this.baseLogger.child({ 
      correlationId, 
      ...additionalContext 
    });
  }
}

// Log aggregation and analysis
class LogAnalyzer {
  constructor(logFile, patterns) {
    this.logFile = logFile;
    this.patterns = patterns;
  }

  async analyze(timeRange = '1h') {
    const logs = await this.readLogs(timeRange);
    
    const analysis = {
      totalLogs: logs.length,
      byLevel: {},
      byEndpoint: {},
      errors: [],
      slowRequests: [],
      patterns: {}
    };

    logs.forEach(log => {
      // Count by log level
      analysis.byLevel[log.level] = (analysis.byLevel[log.level] || 0) + 1;

      // Extract endpoint from HTTP logs
      if (log.req && log.req.url) {
        const endpoint = log.req.url.split('?')[0];
        analysis.byEndpoint[endpoint] = (analysis.byEndpoint[endpoint] || 0) + 1;
      }

      // Collect errors
      if (log.level === 'error' || log.level === 'fatal') {
        analysis.errors.push({
          message: log.msg,
          timestamp: log.time,
          context: log
        });
      }

      // Find slow requests
      if (log.responseTime && log.responseTime > 1000) {
        analysis.slowRequests.push({
          url: log.req?.url,
          method: log.req?.method,
          responseTime: log.responseTime,
          timestamp: log.time
        });
      }

      // Check for patterns
      this.checkPatterns(log, analysis);
    });

    // Calculate rates
    const durationMs = this.parseTimeRange(timeRange);
    analysis.logsPerSecond = analysis.totalLogs / (durationMs / 1000);
    analysis.errorRate = (analysis.byLevel.error || 0) / analysis.totalLogs;

    return analysis;
  }

  checkPatterns(log, analysis) {
    this.patterns.forEach(pattern => {
      if (pattern.test(log.msg)) {
        const patternName = pattern.toString();
        analysis.patterns[patternName] = (analysis.patterns[patternName] || 0) + 1;
      }
    });
  }

  async readLogs(timeRange) {
    // Read and filter logs based on time range
    const logs = [];
    const cutoff = Date.now() - this.parseTimeRange(timeRange);
    
    const stream = fs.createReadStream(this.logFile, { encoding: 'utf8' });
    
    return new Promise((resolve, reject) => {
      let buffer = '';
      
      stream.on('data', (chunk) => {
        buffer += chunk;
        const lines = buffer.split('\n');
        
        // Keep last line if incomplete
        buffer = lines.pop() || '';
        
        lines.forEach(line => {
          if (line.trim()) {
            try {
              const log = JSON.parse(line);
              
              // Filter by time
              const logTime = new Date(log.time).getTime();
              if (logTime >= cutoff) {
                logs.push(log);
              }
            } catch (error) {
              // Skip invalid JSON
            }
          }
        });
      });
      
      stream.on('end', () => {
        resolve(logs);
      });
      
      stream.on('error', reject);
    });
  }

  parseTimeRange(range) {
    const match = range.match(/^(\d+)([mhd])$/);
    if (!match) return 3600000; // Default 1 hour
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 'm': return value * 60000;
      case 'h': return value * 3600000;
      case 'd': return value * 86400000;
      default: return 3600000;
    }
  }

  async generateReport() {
    const analysis = await this.analyze('24h');
    
    const report = {
      summary: {
        totalLogs: analysis.totalLogs,
        errorCount: analysis.byLevel.error || 0,
        errorRate: analysis.errorRate,
        logsPerSecond: analysis.logsPerSecond
      },
      topEndpoints: Object.entries(analysis.byEndpoint)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10),
      recentErrors: analysis.errors.slice(-10),
      slowEndpoints: analysis.slowRequests
        .sort((a, b) => b.responseTime - a.responseTime)
        .slice(0, 10),
      patterns: analysis.patterns
    };

    return report;
  }
}

// Usage example
const logger = LoggerFactory.createLogger({
  name: 'api-server',
  level: 'info',
  environment: process.env.NODE_ENV,
  enableFileLogging: true,
  enableConsoleLogging: process.env.NODE_ENV !== 'production'
});

const httpLogger = LoggerFactory.createHttpLogger(logger, {
  customSuccessMessage: (res) => {
    return `${res.req.method} ${res.req.url} ${res.statusCode} ${res.responseTime}ms`;
  }
});

const correlationLogger = new CorrelationLogger(logger);

// Export for use in application
module.exports = {
  logger,
  httpLogger,
  correlationLogger,
  LoggerFactory,
  LogAnalyzer
};
```

---

## Performance Monitoring & Metrics

```javascript
// performance-monitor.js
const promClient = require('prom-client');
const os = require('os');
const v8 = require('v8');

class PerformanceMonitor {
  constructor() {
    this.registry = new promClient.Registry();
    this.setupMetrics();
    this.startCollection();
  }

  setupMetrics() {
    // HTTP metrics
    this.httpRequestDuration = new promClient.Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.5, 1, 2, 5, 10]
    });

    this.httpRequestsTotal = new promClient.Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code']
    });

    // Database metrics
    this.dbQueryDuration = new promClient.Histogram({
      name: 'db_query_duration_seconds',
      help: 'Duration of database queries in seconds',
      labelNames: ['collection', 'operation'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2]
    });

    this.dbConnections = new promClient.Gauge({
      name: 'db_connections',
      help: 'Number of active database connections'
    });

    // Node.js metrics
    this.eventLoopLag = new promClient.Gauge({
      name: 'node_eventloop_lag_seconds',
      help: 'Event loop lag in seconds'
    });

    this.heapUsed = new promClient.Gauge({
      name: 'node_heap_used_bytes',
      help: 'Heap used in bytes'
    });

    this.heapTotal = new promClient.Gauge({
      name: 'node_heap_total_bytes',
      help: 'Total heap size in bytes'
    });

    this.activeHandles = new promClient.Gauge({
      name: 'node_active_handles',
      help: 'Number of active handles'
    });

    this.activeRequests = new promClient.Gauge({
      name: 'node_active_requests',
      help: 'Number of active requests'
    });

    // System metrics
    this.cpuUsage = new promClient.Gauge({
      name: 'system_cpu_usage',
      help: 'System CPU usage percentage'
    });

    this.memoryUsage = new promClient.Gauge({
      name: 'system_memory_usage_bytes',
      help: 'System memory usage in bytes',
      labelNames: ['type']
    });

    this.loadAverage = new promClient.Gauge({
      name: 'system_load_average',
      help: 'System load average',
      labelNames: ['period']
    });

    // Business metrics
    this.activeUsers = new promClient.Gauge({
      name: 'business_active_users',
      help: 'Number of active users'
    });

    this.ordersPerSecond = new promClient.Counter({
      name: 'business_orders_per_second',
      help: 'Orders per second'
    });

    // Register all metrics
    [
      this.httpRequestDuration,
      this.httpRequestsTotal,
      this.dbQueryDuration,
      this.dbConnections,
      this.eventLoopLag,
      this.heapUsed,
      this.heapTotal,
      this.activeHandles,
      this.activeRequests,
      this.cpuUsage,
      this.memoryUsage,
      this.loadAverage,
      this.activeUsers,
      this.ordersPerSecond
    ].forEach(metric => this.registry.registerMetric(metric));
  }

  startCollection() {
    // Collect Node.js metrics every 5 seconds
    setInterval(() => {
      this.collectNodeMetrics();
      this.collectSystemMetrics();
    }, 5000);
  }

  collectNodeMetrics() {
    // Event loop lag
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const lag = Number(process.hrtime.bigint() - start) / 1e9;
      this.eventLoopLag.set(lag);
    });

    // Heap statistics
    const heapStats = process.memoryUsage();
    this.heapUsed.set(heapStats.heapUsed);
    this.heapTotal.set(heapStats.heapTotal);

    // Active handles and requests
    this.activeHandles.set(process._getActiveHandles().length);
    this.activeRequests.set(process._getActiveRequests().length);
  }

  collectSystemMetrics() {
    // CPU usage
    const cpuUsage = process.cpuUsage();
    const totalCpu = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
    this.cpuUsage.set(totalCpu);

    // Memory usage
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    
    this.memoryUsage.labels('total').set(totalMem);
    this.memoryUsage.labels('used').set(usedMem);
    this.memoryUsage.labels('free').set(freeMem);

    // Load average
    const load = os.loadavg();
    this.loadAverage.labels('1m').set(load[0]);
    this.loadAverage.labels('5m').set(load[1]);
    this.loadAverage.labels('15m').set(load[2]);
  }

  // HTTP middleware
  httpMiddleware() {
    return (req, res, next) => {
      const start = process.hrtime();
      
      // Add metrics to response
      res.on('finish', () => {
        const duration = process.hrtime(start);
        const durationSeconds = duration[0] + duration[1] / 1e9;
        
        const route = req.route?.path || req.path;
        
        this.httpRequestDuration
          .labels(req.method, route, res.statusCode)
          .observe(durationSeconds);
        
        this.httpRequestsTotal
          .labels(req.method, route, res.statusCode)
          .inc();
      });
      
      next();
    };
  }

  // Database query instrumentation
  instrumentMongoose(mongoose) {
    const originalExec = mongoose.Query.prototype.exec;
    
    mongoose.Query.prototype.exec = async function(...args) {
      const start = process.hrtime();
      const collection = this.model.collection.collectionName;
      const operation = this.op;
      
      try {
        const result = await originalExec.apply(this, args);
        
        const duration = process.hrtime(start);
        const durationSeconds = duration[0] + duration[1] / 1e9;
        
        this.monitor.dbQueryDuration
          .labels(collection, operation)
          .observe(durationSeconds);
        
        return result;
      } catch (error) {
        const duration = process.hrtime(start);
        const durationSeconds = duration[0] + duration[1] / 1e9;
        
        this.monitor.dbQueryDuration
          .labels(collection, 'error')
          .observe(durationSeconds);
        
        throw error;
      }
    };
    
    // Keep reference to monitor
    mongoose.Query.prototype.monitor = this;
  }

  // Get metrics for Prometheus
  async getMetrics() {
    return await this.registry.metrics();
  }

  // Generate performance report
  async generateReport() {
    const metrics = await this.registry.getMetricsAsJSON();
    
    const report = {
      timestamp: new Date().toISOString(),
      http: {
        requestRate: this.calculateRate(metrics, 'http_requests_total'),
        p95ResponseTime: this.calculatePercentile(metrics, 'http_request_duration_seconds', 0.95),
        errorRate: this.calculateErrorRate(metrics)
      },
      database: {
        avgQueryTime: this.calculateAverage(metrics, 'db_query_duration_seconds'),
        queryRate: this.calculateRate(metrics, 'db_query_duration_seconds_count')
      },
      nodejs: {
        eventLoopLag: this.getLastValue(metrics, 'node_eventloop_lag_seconds'),
        heapUsage: this.calculateHeapUsage(metrics),
        gcFrequency: this.calculateGCFrequency()
      },
      system: {
        cpuUsage: this.getLastValue(metrics, 'system_cpu_usage'),
        memoryUsage: this.calculateMemoryUsage(metrics),
        loadAverage: this.getLastValue(metrics, 'system_load_average', { period: '1m' })
      }
    };

    return report;
  }

  calculateRate(metrics, metricName) {
    const metric = metrics.find(m => m.name === metricName);
    if (!metric || !metric.values || metric.values.length === 0) return 0;
    
    // Simplified rate calculation
    const latest = metric.values[metric.values.length - 1];
    return latest.value;
  }

  calculateHeapUsage(metrics) {
    const heapUsed = this.getLastValue(metrics, 'node_heap_used_bytes');
    const heapTotal = this.getLastValue(metrics, 'node_heap_total_bytes');
    
    if (heapTotal > 0) {
      return (heapUsed / heapTotal) * 100;
    }
    
    return 0;
  }

  calculateMemoryUsage(metrics) {
    const total = this.getLastValue(metrics, 'system_memory_usage_bytes', { type: 'total' });
    const used = this.getLastValue(metrics, 'system_memory_usage_bytes', { type: 'used' });
    
    if (total > 0) {
      return (used / total) * 100;
    }
    
    return 0;
  }

  getLastValue(metrics, metricName, labels = {}) {
    const metric = metrics.find(m => m.name === metricName);
    if (!metric || !metric.values) return 0;
    
    const matchingValues = metric.values.filter(value => {
      return Object.keys(labels).every(key => value.labels[key] === labels[key]);
    });
    
    if (matchingValues.length === 0) return 0;
    
    return matchingValues[matchingValues.length - 1].value;
  }
}

// Export singleton instance
const monitor = new PerformanceMonitor();
module.exports = monitor;
```

---

## Interview Questions

### Topic-wise Questions

#### Clustering
1. **Q:** When would you choose clustering over worker threads, and vice versa?
   **A:** Clustering is for scaling across CPU cores for I/O-bound workloads (HTTP servers). Worker threads are for CPU-intensive tasks within a single process.

2. **Q:** How do you handle shared state between clustered workers?
   **A:** Use external stores like Redis, database, or shared memory with careful synchronization. Never rely on in-memory state between workers.

3. **Q:** What are the challenges with sticky sessions in clustering?
   **A:** Load imbalance, single point of failure if a worker crashes, and complications with horizontal scaling. Better to use stateless design with external session stores.

#### Worker Threads
1. **Q:** When should you use worker threads vs child processes?
   **A:** Worker threads share memory and are lighter weight for CPU tasks. Child processes are better for isolation, security, or running different programs.

2. **Q:** How do you handle communication between main thread and worker threads?
   **A:** Use `postMessage` and `on('message')` for message passing, or SharedArrayBuffer for shared memory with Atomics for synchronization.

3. **Q:** What are the memory considerations when using worker threads?
   **A:** Each thread has its own V8 isolate and heap. Memory is not automatically shared. Use Transferable objects or SharedArrayBuffer to minimize copying.

#### Caching
1. **Q:** How do you design a cache invalidation strategy?
   **A:** Use TTL for time-based invalidation, write-through for consistency, or cache tags for related data invalidation. Consider cache stampede protection.

2. **Q:** What are the trade-offs between different cache eviction policies (LRU, LFU, FIFO)?
   **A:** LRU is good for temporal locality, LFU for frequency-based access patterns, FIFO is simple but may evict hot data. Choose based on access patterns.

3. **Q:** How do you handle cache penetration and cache stampede?
   **A:** Use bloom filters for penetration, mutex locks or probabilistic early expiration for stampede protection.

#### Streams
1. **Q:** How do you handle backpressure in Node.js streams?
   **A:** Monitor `writeable.write()` return value, pause readable streams when false, implement proper `drain` event handling.

2. **Q:** What's the difference between flowing and paused modes in readable streams?
   **A:** Flowing mode automatically pushes data, paused mode requires explicit `read()` calls. Flowing is simpler but offers less control.

#### Query Optimization
1. **Q:** How do you identify and fix N+1 query problems?
   **A:** Use eager loading, batch queries, or data loaders. Monitor query counts and implement query analysis tools.

2. **Q:** What indexes would you create for a compound query with sorting and filtering?
   **A:** Create compound indexes that match query predicates and sort order. Follow ESR rule: Equality, Sort, Range.

#### Load Testing
1. **Q:** How do you determine the right load for stress testing?
   **A:** Start with 2-3x expected peak load, then increase until failure. Monitor resource utilization and error rates.

2. **Q:** What metrics are most important during load testing?
   **A:** Response time percentiles (p95, p99), error rate, throughput (RPS), and resource utilization (CPU, memory, I/O).

#### PM2
1. **Q:** How do you achieve zero-downtime deployments with PM2?
   **A:** Use `pm2 reload` with `--wait-ready` signal, implement health checks, and use rolling updates.

2. **Q:** What's the difference between fork mode and cluster mode in PM2?
   **A:** Fork mode runs single instance, cluster mode runs multiple instances with load balancing. Use cluster for stateless web servers.

#### Logging
1. **Q:** How do you balance detailed logging with performance?
   **A:** Use structured logging with configurable levels, async logging, and sample expensive log operations.

2. **Q:** What information should always be included in production logs?
   **A:** Timestamp, log level, correlation ID, user ID, request ID, error stack traces, and relevant context.

### Real-World Scenarios

#### Scenario 1: Sudden Traffic Spike
**Q:** Your e-commerce API normally handles 1000 RPS, but during a flash sale it spikes to 10,000 RPS. Response times increase from 50ms to 2s. How do you diagnose and fix this?

**Expected Answer:**
1. **Diagnose:** Check metrics - CPU, memory, database queries, cache hit rate
2. **Short-term:** Increase instances, add CDN, enable aggressive caching
3. **Long-term:** Implement rate limiting, optimize slow queries, add database replicas
4. **Monitoring:** Set up alerts for key metrics, implement auto-scaling

#### Scenario 2: Memory Leak Investigation
**Q:** Your Node.js service memory usage grows steadily until it crashes every 24 hours. How do you investigate and fix this?

**Expected Answer:**
1. **Tools:** Use heap snapshots, memory profiler, clinic.js
2. **Patterns:** Check for global variables, unclosed resources, event listeners
3. **Fix:** Implement proper cleanup, use streams for large data, monitor GC
4. **Prevention:** Add memory limits, automatic restarts, regular profiling

#### Scenario 3: Database Performance Degradation
**Q:** Database queries that normally take 10ms now take 500ms. The database CPU is at 90%. How do you approach this?

**Expected Answer:**
1. **Immediate:** Check for missing indexes, long-running queries, locks
2. **Analyze:** Use `explain()`, query profiling, slow query logs
3. **Optimize:** Add indexes, rewrite queries, implement query caching
4. **Scale:** Consider read replicas, connection pooling, query batching

#### Scenario 4: File Processing Bottleneck
**Q:** Your service processes uploaded CSV files. With 100 concurrent uploads, the system becomes unresponsive. How do you optimize?

**Expected Answer:**
1. **Streams:** Process files as streams, not loading entire files in memory
2. **Workers:** Use worker threads for CPU-intensive parsing
3. **Queue:** Implement job queue with rate limiting
4. **Storage:** Use cloud storage with direct uploads to avoid server processing

#### Scenario 5: Microservices Performance
**Q:** A user request now calls 5 microservices sequentially, causing high latency. How do you optimize?

**Expected Answer:**
1. **Parallelize:** Make independent calls in parallel
2. **Cache:** Implement response caching at API gateway
3. **Batch:** Use GraphQL or batch endpoints
4. **Timeout:** Set appropriate timeouts and circuit breakers

#### Scenario 6: Real-time Application Scaling
**Q:** Your real-time chat application with WebSockets needs to handle 100,000 concurrent connections. How do you architect this?

**Expected Answer:**
1. **Load Balancer:** Use WebSocket-aware load balancer
2. **Redis Pub/Sub:** For cross-instance messaging
3. **Connection Pooling:** Optimize WebSocket connections
4. **Monitoring:** Track connection counts, message rates, latency

#### Scenario 7: Canary Deployment Failure
**Q:** During a canary deployment, the new version causes 30% error rate. How do you respond?

**Expected Answer:**
1. **Rollback:** Immediately revert to previous version
2. **Analyze:** Check logs, metrics, and differences between versions
3. **Test:** Improve testing - load test, chaos engineering
4. **Process:** Implement better canary analysis and automated rollback

These scenarios test the ability to diagnose, prioritize, and solve complex performance issues under pressure - key skills for senior developers.