# Node.js Fundamentals - Complete Guide

## 📚 Table of Contents
- [1. What is Node.js?](#1-what-is-nodejs)
- [2. Event Loop](#2-event-loop)
- [3. Call Stack, Thread Pool, libuv](#3-call-stack-thread-pool-libuv)
- [4. Asynchronous vs Synchronous Execution](#4-asynchronous-vs-synchronous-execution)
- [5. Why Node.js is Good for I/O-heavy Apps](#5-why-nodejs-is-good-for-io-heavy-apps)
- [6. CommonJS vs ES Modules](#6-commonjs-vs-es-modules)
- [7. Node REPL](#7-node-repl)
- [8. Node Process Lifecycle](#8-node-process-lifecycle)

---

## 1. What is Node.js?

### In-depth Explanation
Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine. It's designed to build scalable network applications using an event-driven, non-blocking I/O model. Unlike traditional web-serving techniques where each connection spawns a new thread, Node.js operates on a single thread, using non-blocking I/O calls, allowing it to support tens of thousands of concurrent connections.

**Key Characteristics:**
- **Single-threaded with Event Loop**: Uses a single main thread with an event loop
- **Non-blocking I/O**: Asynchronous operations don't block the main thread
- **Built on V8**: Google's high-performance JavaScript engine
- **Cross-platform**: Runs on Windows, Linux, macOS, etc.
- **NPM ecosystem**: Largest package registry with over 1.5 million packages

**Architecture:**
```
┌─────────────────┐
│   JavaScript    │
│    (Your Code)  │
└────────┬────────┘
         │
┌────────▼────────┐
│      V8         │  ← JavaScript Engine
│ (Chrome's V8)   │
└────────┬────────┘
         │
┌────────▼────────┐
│   Node.js Bindings│
└────────┬────────┘
         │
┌────────▼────────┐
│      libuv      │  ← C library for async I/O
│   (Event Loop,  │
│   Thread Pool)  │
└─────────────────┘
```

### 🔥 Interview Questions

**Junior to Mid-level:**
1. What is Node.js and how is it different from browser JavaScript?
2. Explain the role of V8 engine in Node.js.
3. Why is Node.js considered "non-blocking"?
4. What are the main advantages of using Node.js?

**Senior Level:**
5. How does Node.js handle CPU-intensive operations despite being single-threaded?
6. Explain the evolution of Node.js from callback pattern to async/await.
7. How does Node.js compare to Deno and Bun in terms of architecture?
8. What are the security considerations specific to Node.js applications?

### 🌍 Real-World Scenarios

**Scenario 1: API Gateway**
> You're building an API gateway that needs to handle 10,000+ concurrent connections with minimal latency. The gateway needs to perform authentication, rate limiting, and request routing. Why would you choose Node.js for this?

**Solution Considerations:**
- Event-driven architecture handles high concurrency efficiently
- Non-blocking I/O for external service calls (auth services, databases)
- Middleware pattern (Express/Koa) fits gateway architecture
- Cluster module for utilizing multi-core systems

**Scenario 2: Real-time Collaboration Tool**
> Building a real-time collaborative document editor where multiple users can edit simultaneously with instant updates across all clients.

**Solution Approach:**
```javascript
// Using WebSockets with Socket.io
const server = require('http').createServer();
const io = require('socket.io')(server, {
  cors: { origin: "*" }
});

io.on('connection', (socket) => {
  // Handle real-time updates
  socket.on('document-edit', (data) => {
    // Broadcast to other users in same room
    socket.to(data.roomId).emit('update', data.changes);
  });
  
  // Handle presence
  socket.on('user-joined', (data) => {
    socket.join(data.roomId);
    io.to(data.roomId).emit('user-presence', data.userId);
  });
});
```

---

## 2. Event Loop

### In-depth Explanation
The Event Loop is Node.js's mechanism for handling asynchronous operations. It's what allows Node.js to perform non-blocking I/O operations despite JavaScript being single-threaded.

**Event Loop Phases:**
```
   ┌───────────────────────────┐
┌─►│        timers          │ ← setTimeout, setInterval
│  └─────────────┬─────────────┘
│  ┌─────────────▼─────────────┐
│  │     pending callbacks     │ ← I/O callbacks (TCP errors, etc.)
│  └─────────────┬─────────────┘
│  ┌─────────────▼─────────────┐
│  │       idle, prepare       │ ← internal use only
│  └─────────────┬─────────────┘
│  ┌─────────────▼─────────────┐    ┌───────────────┐
│  │           poll            │←───┤  incoming:    │
│  └─────────────┬─────────────┘    │ connections,  │
│  ┌─────────────▼─────────────┐    │ data, events  │
│  │           check           │    └───────────────┘
│  └─────────────┬─────────────┘
│  ┌─────────────▼─────────────┐
└──┤      close callbacks      │ ← socket.on('close', ...)
   └───────────────────────────┘
```

**Microtasks Queue:**
- **Processed between each phase** of the event loop
- **Two microtask queues**:
  1. `process.nextTick()` queue (highest priority)
  2. Promise queue (`.then/catch/finally`)

**Execution Order Example:**
```javascript
console.log('1. Script start');

setTimeout(() => console.log('6. Timeout'), 0);

Promise.resolve()
  .then(() => console.log('4. Promise 1'))
  .then(() => console.log('5. Promise 2'));

process.nextTick(() => console.log('3. NextTick'));

console.log('2. Script end');

// Output order:
// 1. Script start
// 2. Script end
// 3. NextTick
// 4. Promise 1
// 5. Promise 2
// 6. Timeout
```

### 🔥 Interview Questions

**Mid-level:**
1. Explain the different phases of the Node.js event loop.
2. What's the difference between `setImmediate()` and `setTimeout(fn, 0)`?
3. How does `process.nextTick()` differ from `setImmediate()`?
4. What is the microtask queue and when is it processed?

**Senior Level:**
5. Explain how the event loop handles different types of operations:
   - File I/O vs Network I/O
   - Crypto operations vs DNS lookups
6. How would you debug event loop starvation?
7. What are the performance implications of too many `process.nextTick()` calls?
8. Explain the relationship between event loop phases and the thread pool.

### 🌍 Real-World Scenarios

**Scenario 1: High-Latency Operations**
> Your Node.js service is experiencing high latency during peak traffic. After investigation, you find that the event loop is frequently blocked.

**Debugging Steps:**
```javascript
// Monitor event loop lag
const monitoring = require('event-loop-lag')(1000);

setInterval(() => {
  const lag = monitoring();
  if (lag > 100) { // More than 100ms lag
    console.error(`Event loop lag: ${lag}ms`);
    // Take action: scale, optimize, or shed load
  }
}, 5000);

// Identify blocking operations
const blocked = require('blocked-at');
blocked((time, stack) => {
  console.log(`Blocked for ${time}ms, operation:`, stack);
}, { threshold: 100 }); // 100ms threshold
```

**Scenario 2: Priority Scheduling**
> You need to ensure critical database cleanup operations happen before less important logging tasks, both scheduled as callbacks.

**Solution:**
```javascript
class PriorityScheduler {
  constructor() {
    this.highPriorityQueue = [];
    this.lowPriorityQueue = [];
  }
  
  scheduleHighPriority(task) {
    this.highPriorityQueue.push(task);
    process.nextTick(this.processQueues.bind(this));
  }
  
  scheduleLowPriority(task) {
    this.lowPriorityQueue.push(task);
    setImmediate(this.processQueues.bind(this));
  }
  
  processQueues() {
    // Process high priority first
    while (this.highPriorityQueue.length > 0) {
      const task = this.highPriorityQueue.shift();
      task();
    }
    
    // Then low priority if event loop isn't busy
    if (this.lowPriorityQueue.length > 0) {
      const task = this.lowPriorityQueue.shift();
      setTimeout(() => task(), 0);
    }
  }
}
```

---

## 3. Call Stack, Thread Pool, libuv

### In-depth Explanation

**Call Stack:**
- Single-threaded LIFO (Last In, First Out) structure
- Tracks function calls and execution context
- Stack overflow occurs with deep recursion or infinite loops

**Thread Pool:**
- Managed by **libuv** (default: 4 threads, configurable via `UV_THREADPOOL_SIZE`)
- Handles "expensive" operations:
  - File system operations (most)
  - DNS lookups (`dns.lookup()`)
  - Crypto operations (PBKDF2, randomBytes, etc.)
  - Compression (zlib)

**libuv (Cross-platform asynchronous I/O library):**
- Written in C
- Provides event loop implementation
- Manages thread pool for offloading work
- Abstracts OS-specific async APIs

**How They Work Together:**
```javascript
const crypto = require('crypto');
const fs = require('fs');

// This uses thread pool (libuv)
crypto.pbkdf2('password', 'salt', 100000, 64, 'sha512', (err, derivedKey) => {
  console.log('Crypto done (thread pool)');
});

// This uses OS async APIs (libuv, not thread pool on Linux/Mac)
fs.readFile('/large/file.txt', (err, data) => {
  console.log('File read (OS async)');
});

// This is immediate (call stack)
console.log('Immediate log');
```

### 🔥 Interview Questions

**Mid-level:**
1. What is libuv and what role does it play in Node.js?
2. Which operations use the thread pool vs OS async APIs?
3. How can you increase the thread pool size and when should you?
4. What happens when the call stack overflows?

**Senior Level:**
5. How does libuv handle file I/O differently on Windows vs Unix systems?
6. Explain the performance implications of thread pool exhaustion.
7. How would you implement a custom async operation that uses the thread pool?
8. What are the trade-offs between increasing thread pool size vs using worker threads?

### 🌍 Real-World Scenarios

**Scenario 1: Image Processing Service**
> You're building a service that processes uploaded images (resizing, compression, watermarking). Users complain about timeouts during peak hours.

**Analysis:**
```javascript
// Problem: All crypto operations share same thread pool
app.post('/upload', async (req, res) => {
  // These operations compete for thread pool
  const hash = await crypto.createHash('md5').update(buffer).digest('hex');
  const encrypted = await crypto.pbkdf2Sync('key', 'salt', 100000, 64, 'sha512');
  
  // Solution options:
  // 1. Increase thread pool size
  process.env.UV_THREADPOOL_SIZE = 12;
  
  // 2. Use Worker Threads for CPU-intensive tasks
  const { Worker } = require('worker_threads');
  const worker = new Worker('./image-processor.js', { workerData: buffer });
  
  // 3. Batch and queue operations
  const queue = new PQueue({ concurrency: 4 });
  const result = await queue.add(() => processImage(buffer));
});
```

**Scenario 2: Real-time Analytics**
> Processing streaming data with multiple hash computations causing thread pool contention.

**Optimization Strategy:**
```javascript
const { createHash } = require('crypto');
const { pipeline } = require('stream');
const { Worker, isMainThread, parentPort } = require('worker_threads');

if (isMainThread) {
  // Main thread - offload hash computation
  module.exports = function hashStream(stream) {
    return new Promise((resolve, reject) => {
      const worker = new Worker(__filename, {
        workerData: { action: 'hash' }
      });
      
      pipeline(stream, worker, (err) => {
        if (err) reject(err);
      });
      
      let hash = '';
      worker.on('message', (msg) => {
        if (msg.type === 'hash') hash = msg.value;
      });
      worker.on('exit', () => resolve(hash));
    });
  };
} else {
  // Worker thread - dedicated for CPU work
  const hash = createHash('sha256');
  process.stdin.on('data', (chunk) => {
    hash.update(chunk);
  });
  process.stdin.on('end', () => {
    parentPort.postMessage({
      type: 'hash',
      value: hash.digest('hex')
    });
  });
}
```

---

## 4. Asynchronous vs Synchronous Execution

### In-depth Explanation

**Synchronous Execution:**
- Blocking operations
- Simple control flow
- Can cause performance issues

**Asynchronous Patterns Evolution:**
1. **Callbacks (Callback Hell)**
2. **Promises (ES2015)**
3. **Async/Await (ES2017)**

**Comparison:**
```javascript
// 1. Synchronous (Blocking)
try {
  const data = fs.readFileSync('file.txt');
  console.log(data.toString());
} catch (error) {
  console.error(error);
}

// 2. Callback Pattern
fs.readFile('file.txt', (error, data) => {
  if (error) {
    console.error(error);
    return;
  }
  console.log(data.toString());
});

// 3. Promises
fs.promises.readFile('file.txt')
  .then(data => console.log(data.toString()))
  .catch(error => console.error(error));

// 4. Async/Await (Modern)
async function readFile() {
  try {
    const data = await fs.promises.readFile('file.txt');
    console.log(data.toString());
  } catch (error) {
    console.error(error);
  }
}
```

**Error Handling Differences:**
```javascript
// Sync - try/catch works
try {
  JSON.parse(invalidJson);
} catch (err) {
  // Caught here
}

// Async - different patterns
// Callback
asyncFunction((err, result) => {
  if (err) { /* handle */ }
});

// Promise
asyncFunction()
  .then(result => { /* success */ })
  .catch(err => { /* handle */ });

// Async/await
try {
  const result = await asyncFunction();
} catch (err) {
  // Handle error
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What are the disadvantages of using synchronous methods in Node.js?
2. Explain the "pyramid of doom" problem with callbacks.
3. How do Promises solve callback hell?
4. What's the difference between `Promise.all()` and `Promise.allSettled()`?

**Senior Level:**
5. How does async/await work under the hood with generators?
6. Explain the performance implications of excessive `await` in loops.
7. How would you handle partial failures in batch async operations?
8. What are the memory leak risks with improper async code?

### 🌍 Real-World Scenarios

**Scenario 1: E-commerce Checkout**
> Processing checkout with multiple dependent async operations: inventory check, payment processing, email notification, and order creation.

**Solution with Error Handling:**
```javascript
class CheckoutService {
  async processCheckout(orderData) {
    try {
      // Execute in sequence with dependency
      const inventoryValid = await this.checkInventory(orderData.items);
      if (!inventoryValid) throw new Error('Out of stock');
      
      // Execute in parallel (independent operations)
      const [paymentResult, userData] = await Promise.all([
        this.processPayment(orderData.payment),
        this.getUserDetails(orderData.userId)
      ]);
      
      if (!paymentResult.success) throw new Error('Payment failed');
      
      // Create order after successful payment
      const order = await this.createOrder({
        ...orderData,
        paymentId: paymentResult.id
      });
      
      // Fire-and-forget notifications (don't block response)
      this.sendNotifications(order, userData).catch(console.error);
      
      return { success: true, orderId: order.id };
      
    } catch (error) {
      // Compensating transactions for rollback
      await this.rollbackCheckout(orderData);
      
      // Structured error handling
      if (error.type === 'PAYMENT_FAILED') {
        await this.notifyPaymentTeam(error);
      }
      
      throw this.formatCheckoutError(error);
    }
  }
  
  async sendNotifications(order, userData) {
    // Execute notifications with timeout
    const notifications = [
      this.sendEmail(userData.email, order),
      this.sendSMS(userData.phone, order),
      this.logAnalytics(order)
    ];
    
    // Continue even if some fail
    const results = await Promise.allSettled(notifications);
    
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Notification ${index} failed:`, result.reason);
      }
    });
  }
}
```

**Scenario 2: Data Migration Tool**
> Migrating millions of records with progress tracking, rate limiting, and resume capability.

**Advanced Async Pattern:**
```javascript
class DataMigrator {
  constructor(concurrency = 10) {
    this.queue = new AsyncQueue(concurrency);
    this.migratedCount = 0;
    this.failedRecords = [];
  }
  
  async migrateBatch(records, onProgress) {
    const migrationPromises = records.map(record => 
      this.queue.add(async () => {
        try {
          await this.migrateRecord(record);
          this.migratedCount++;
          
          // Throttle progress updates
          if (this.migratedCount % 100 === 0) {
            onProgress?.({
              migrated: this.migratedCount,
              failed: this.failedRecords.length
            });
          }
        } catch (error) {
          this.failedRecords.push({ record, error });
          throw error;
        }
      })
    );
    
    // Process with timeout per record
    const timeout = ms => new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), ms)
    );
    
    for (const promise of migrationPromises) {
      try {
        await Promise.race([promise, timeout(5000)]);
      } catch (error) {
        if (error.message === 'Timeout') {
          console.warn('Record migration timeout, continuing...');
        }
      }
    }
    
    return {
      total: records.length,
      succeeded: this.migratedCount,
      failed: this.failedRecords.length
    };
  }
}

// Async Queue implementation
class AsyncQueue {
  constructor(concurrency = 1) {
    this.concurrency = concurrency;
    this.running = 0;
    this.queue = [];
  }
  
  add(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this.run();
    });
  }
  
  run() {
    while (this.running < this.concurrency && this.queue.length) {
      const { task, resolve, reject } = this.queue.shift();
      this.running++;
      
      task()
        .then(resolve)
        .catch(reject)
        .finally(() => {
          this.running--;
          this.run();
        });
    }
  }
}
```

---

## 5. Why Node.js is Good for I/O-heavy Apps

### In-depth Explanation

**I/O Bottlenecks in Traditional Models:**
- Thread-per-connection model (Apache, Java Servlet)
- Memory overhead per thread (~1MB stack)
- Context switching overhead
- Limited concurrent connections (~thread pool size)

**Node.js Advantages:**

1. **Event-driven Architecture**
   - Single thread handles thousands of connections
   - No context switching overhead
   - Efficient memory usage

2. **Non-blocking I/O**
   - OS-level async I/O (epoll/kqueue/IOCP)
   - No threads blocked waiting for I/O
   - Callback/promise-based API

3. **Stream Processing**
   - Handle data as it arrives
   - Backpressure handling
   - Memory efficient for large data

**Performance Comparison:**
```javascript
// Traditional blocking server (pseudocode)
server.onConnection((socket) => {
  // Blocks thread while reading
  const data = socket.read(); // BLOCKING
  const response = process(data);
  socket.write(response); // BLOCKING
});

// Node.js non-blocking
server.onConnection((socket) => {
  socket.on('data', (chunk) => {
    // Process chunk without blocking
    process.nextTick(() => {
      const response = processChunk(chunk);
      socket.write(response); // Non-blocking
    });
  });
});
```

**Use Cases:**
- **APIs/Microservices**: High concurrency, low CPU
- **Real-time apps**: Chat, gaming, collaboration
- **Proxy/API Gateway**: Request routing, aggregation
- **Data Streaming**: Processing logs, file uploads
- **IoT**: Many concurrent device connections

### 🔥 Interview Questions

**Mid-level:**
1. Why is Node.js particularly suitable for chat applications?
2. How does Node.js handle 10,000 concurrent connections with one thread?
3. What types of applications should NOT use Node.js?
4. Explain the C10K problem and how Node.js solves it.

**Senior Level:**
5. How would you scale a Node.js application beyond single machine limits?
6. What are the limitations of Node.js for CPU-intensive tasks?
7. How does Node.js compare to Go or Rust for I/O heavy applications?
8. Explain how HTTP/2 affects Node.js performance characteristics.

### 🌍 Real-World Scenarios

**Scenario 1: Real-time Dashboard**
> Building a dashboard that shows real-time metrics from 50,000+ IoT devices sending data every 10 seconds.

**Architecture:**
```javascript
const WebSocket = require('ws');
const { Server } = require('http');
const { EventEmitter } = require('events');

class IoTDashboard extends EventEmitter {
  constructor() {
    super();
    this.connections = new Map(); // deviceId -> WebSocket[]
    this.metrics = new Map();     // deviceId -> latest metrics
  }
  
  async start() {
    const server = new Server();
    const wss = new WebSocket.Server({ server });
    
    wss.on('connection', (ws, req) => {
      const deviceId = this.extractDeviceId(req);
      
      // Store connection (O(1) lookup)
      if (!this.connections.has(deviceId)) {
        this.connections.set(deviceId, new Set());
      }
      this.connections.get(deviceId).add(ws);
      
      // Send latest metrics immediately
      if (this.metrics.has(deviceId)) {
        ws.send(JSON.stringify(this.metrics.get(deviceId)));
      }
      
      ws.on('close', () => {
        this.connections.get(deviceId)?.delete(ws);
        if (this.connections.get(deviceId)?.size === 0) {
          this.connections.delete(deviceId);
        }
      });
    });
    
    // Handle incoming metrics
    this.on('metric', (deviceId, data) => {
      this.metrics.set(deviceId, data);
      
      // Broadcast to all dashboard connections for this device
      const connections = this.connections.get(deviceId);
      if (connections) {
        const message = JSON.stringify(data);
        connections.forEach(ws => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(message); // Non-blocking
          }
        });
      }
    });
    
    // HTTP endpoint for device data
    server.on('request', async (req, res) => {
      if (req.method === 'POST' && req.url === '/metrics') {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
          const data = JSON.parse(Buffer.concat(chunks));
          this.emit('metric', data.deviceId, data);
          res.writeHead(202).end(); // Accepted
        });
      }
    });
    
    server.listen(8080);
  }
}
```

**Scenario 2: High-Throughput API Gateway**
> Building a gateway that handles 50,000 RPS, needs to perform auth, rate limiting, request/response transformation.

**Optimized Gateway:**
```javascript
const fastify = require('fastify');
const { createHash } = require('crypto');
const Redis = require('ioredis');

class APIGateway {
  constructor() {
    this.app = fastify({ 
      logger: true,
      connectionTimeout: 5000,
      bodyLimit: 1048576, // 1MB
      disableRequestLogging: true // Manual logging for perf
    });
    
    this.redis = new Redis.Cluster([
      { host: 'redis1', port: 6379 },
      { host: 'redis2', port: 6379 }
    ], {
      scaleReads: 'slave',
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 1
    });
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupMonitoring();
  }
  
  setupMiddleware() {
    // Async middleware chain
    this.app.addHook('preHandler', async (request, reply) => {
      // 1. Rate limiting (Redis-based, non-blocking)
      const ip = request.ip;
      const key = `rate_limit:${ip}`;
      const requests = await this.redis.incr(key);
      
      if (requests === 1) {
        await this.redis.expire(key, 60); // 1 minute window
      }
      
      if (requests > 100) {
        throw new Error('Rate limit exceeded');
      }
      
      // 2. Authentication (JWT verification)
      const token = request.headers.authorization;
      if (token) {
        request.user = await this.verifyToken(token);
      }
      
      // 3. Request ID for tracing
      request.id = createHash('sha256')
        .update(`${Date.now()}${Math.random()}`)
        .digest('hex');
    });
    
    // Response transformation
    this.app.addHook('onSend', async (request, reply, payload) => {
      return {
        data: JSON.parse(payload),
        meta: {
          requestId: request.id,
          timestamp: Date.now()
        }
      };
    });
  }
  
  async setupRoutes() {
    // Proxy routes with connection pooling
    this.app.register(async (app) => {
      // Health check (no dependencies)
      app.get('/health', async () => ({ status: 'healthy' }));
      
      // API endpoints with circuit breakers
      app.get('/api/users/:id', async (request) => {
        return this.withCircuitBreaker('user-service', async () => {
          return this.fetchFromService('user-service', `/users/${request.params.id}`);
        });
      });
      
      // Batch endpoint with parallel requests
      app.post('/api/batch', async (request) => {
        const { requests } = request.body;
        
        // Execute parallel requests with concurrency control
        const results = await this.processBatch(requests, 10);
        return { results };
      });
    });
  }
  
  async processBatch(requests, concurrency) {
    const queue = [];
    const results = new Array(requests.length);
    
    for (let i = 0; i < requests.length; i++) {
      queue.push(async () => {
        try {
          results[i] = await this.processRequest(requests[i]);
        } catch (error) {
          results[i] = { error: error.message };
        }
      });
    }
    
    // Process in batches
    for (let i = 0; i < queue.length; i += concurrency) {
      const batch = queue.slice(i, i + concurrency);
      await Promise.all(batch.map(fn => fn()));
    }
    
    return results;
  }
}
```

---

## 6. CommonJS vs ES Modules

### In-depth Explanation

**CommonJS (Node.js default until v12):**
- Synchronous loading
- `require()` / `module.exports`
- Cached after first load
- Runtime evaluation

**ES Modules (ECMAScript Standard):**
- Asynchronous loading
- `import` / `export`
- Static analysis possible
- Top-level await support

**Comparison Table:**

| Feature | CommonJS | ES Modules |
|---------|----------|------------|
| Loading | Synchronous | Asynchronous |
| Syntax | `require()`, `module.exports` | `import`, `export` |
| Cache | Per module instance | Per module specifier |
| Top-level await | Not allowed | Allowed |
| Static analysis | Limited | Full |
| File extension | `.js`, `.cjs` | `.mjs`, `.js` (with package.json type) |
| Circular deps | Supported with limitations | Supported |
| Default export | `module.exports = value` | `export default value` |

**Interoperability:**
```javascript
// CommonJS consuming ES Module
// package.json: { "type": "module" }
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const cjsModule = require('./cjs-module.cjs');

// ES Module in CommonJS project
(async () => {
  const esm = await import('./esm-module.mjs');
})();

// Dual package (support both)
// package.json
{
  "name": "my-package",
  "exports": {
    "require": "./dist/cjs/index.js",
    "import": "./dist/esm/index.js",
    "default": "./dist/esm/index.js"
  },
  "type": "module",
  "main": "./dist/cjs/index.js"
}
```

**Performance Implications:**
- ES Modules enable better tree-shaking (dead code elimination)
- CommonJS enables dynamic requires (plugin systems)
- ES Modules have faster startup in some cases (parallel loading)

### 🔥 Interview Questions

**Mid-level:**
1. What are the main differences between `require()` and `import`?
2. How do you use ES Modules in Node.js?
3. What's the purpose of the `__dirname` and `__filename` in ES Modules?
4. How do you create a dual package that supports both CJS and ESM?

**Senior Level:**
5. Explain the performance implications of dynamic imports vs static imports.
6. How does module resolution differ between CJS and ESM?
7. What are the security implications of each module system?
8. How would you migrate a large CommonJS codebase to ES Modules?

### 🌍 Real-World Scenarios

**Scenario 1: Plugin Architecture**
> Building a system where plugins can be loaded dynamically at runtime. Need to support both CJS and ESM plugins.

**Solution:**
```javascript
// plugin-loader.js
const { pathToFileURL } = require('url');
const Module = require('module');

class PluginLoader {
  constructor() {
    this.plugins = new Map();
    this.cache = new Map();
  }
  
  async loadPlugin(pluginPath) {
    // Check cache first
    if (this.cache.has(pluginPath)) {
      return this.cache.get(pluginPath);
    }
    
    try {
      let plugin;
      
      // Determine module type
      const packageJsonPath = path.join(pluginPath, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (pkg.type === 'module') {
          // ES Module
          const moduleUrl = pathToFileURL(path.join(pluginPath, pkg.main || 'index.js'));
          plugin = await import(moduleUrl);
        } else {
          // CommonJS
          plugin = require(path.join(pluginPath, pkg.main || 'index.js'));
        }
      } else {
        // Try to detect from extension
        if (pluginPath.endsWith('.mjs')) {
          const moduleUrl = pathToFileURL(pluginPath);
          plugin = await import(moduleUrl);
        } else {
          plugin = require(pluginPath);
        }
      }
      
      // Validate plugin interface
      if (!plugin.initialize || typeof plugin.initialize !== 'function') {
        throw new Error('Plugin must export initialize() function');
      }
      
      this.cache.set(pluginPath, plugin);
      this.plugins.set(pluginPath, plugin);
      
      return plugin;
      
    } catch (error) {
      console.error(`Failed to load plugin ${pluginPath}:`, error);
      throw error;
    }
  }
  
  async initializeAllPlugins(config) {
    const initializationPromises = [];
    
    for (const [path, plugin] of this.plugins) {
      initializationPromises.push(
        (async () => {
          try {
            await plugin.initialize(config);
            console.log(`Plugin ${path} initialized successfully`);
          } catch (error) {
            console.error(`Failed to initialize plugin ${path}:`, error);
            // Continue with other plugins
          }
        })()
      );
    }
    
    // Initialize in parallel with concurrency limit
    const results = await Promise.allSettled(initializationPromises);
    return results.map((r, i) => ({
      path: Array.from(this.plugins.keys())[i],
      status: r.status,
      error: r.status === 'rejected' ? r.reason : null
    }));
  }
}
```

**Scenario 2: Monorepo with Mixed Modules**
> Managing a monorepo with some packages using CJS and others using ESM, needing to share types and ensure compatibility.

**Advanced Configuration:**
```json
// package.json for monorepo root
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": ["packages/*"],
  "scripts": {
    "build": "turbo run build",
    "type-check": "turbo run type-check"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "tsup": "^7.0.0",
    "turbo": "^1.10.0"
  }
}

// packages/common/package.json (ESM)
{
  "name": "@myapp/common",
  "type": "module",
  "exports": {
    ".": {
      "import": "./dist/index.mjs",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    },
    "./utils": {
      "import": "./dist/utils.mjs",
      "require": "./dist/utils.cjs",
      "types": "./dist/utils.d.ts"
    }
  },
  "scripts": {
    "build": "tsup src/index.ts src/utils.ts --format cjs,esm --dts",
    "type-check": "tsc --noEmit"
  }
}

// packages/server/package.json (CJS)
{
  "name": "@myapp/server",
  "type": "commonjs",
  "main": "./dist/index.js",
  "scripts": {
    "build": "tsup src/index.ts --format cjs",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    "@myapp/common": "workspace:*"
  }
}
```

**TypeScript Configuration:**
```json
// tsconfig.base.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  }
}

// Build tool configuration (tsup)
// tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'node18',
  external: [
    // External dependencies
  ],
  noExternal: [
    // Bundle these dependencies
  ]
});
```

---

## 7. Node REPL

### In-depth Explanation

**REPL (Read-Eval-Print-Loop):**
- Interactive programming environment
- Useful for experimentation, debugging, learning
- Built into Node.js (`node` command without arguments)

**Features:**
1. **Tab Completion**: Context-aware suggestions
2. **Command History**: Up/down arrows, persistent history
3. **Special Commands**: `.help`, `.break`, `.clear`
4. **REPL Server**: Programmatic access

**Advanced Usage:**
```javascript
// Start REPL with custom context
const repl = require('repl');
const vm = require('vm');

class CustomREPL {
  start() {
    const r = repl.start({
      prompt: 'my-app> ',
      eval: this.customEval.bind(this),
      writer: this.customWriter.bind(this),
      completer: this.customCompleter.bind(this)
    });
    
    // Add custom commands
    Object.defineProperty(r.context, 'app', {
      configurable: false,
      enumerable: true,
      value: {
        version: '1.0.0',
        services: this.services,
        help: () => console.log('Available: .services, .version')
      }
    });
    
    // Load history
    this.loadHistory(r);
    
    return r;
  }
  
  customEval(code, context, filename, callback) {
    try {
      // Add custom global variables
      const script = new vm.Script(code, {
        filename: filename,
        lineOffset: 0,
        columnOffset: 0,
        displayErrors: true
      });
      
      const result = script.runInContext(context, {
        displayErrors: false,
        breakOnSigint: true
      });
      
      callback(null, result);
    } catch (err) {
      callback(err);
    }
  }
  
  customWriter(output) {
    // Pretty print objects
    if (output && typeof output === 'object') {
      return require('util').inspect(output, {
        colors: true,
        depth: 3,
        maxArrayLength: 10
      });
    }
    return output;
  }
  
  customCompleter(line) {
    const completions = [
      'app.', 'services.', 'version',
      '.help', '.break', '.clear',
      '.load', '.save'
    ];
    
    const hits = completions.filter(c => c.startsWith(line));
    return [hits.length ? hits : completions, line];
  }
}
```

### 🔥 Interview Questions

**Mid-level:**
1. What is the Node.js REPL and what is it used for?
2. How do you load a JavaScript file into the REPL?
3. What are the special REPL commands and what do they do?
4. How can you customize the REPL prompt?

**Senior Level:**
5. How would you implement a domain-specific REPL for your application?
6. What are the security considerations when exposing a REPL in production?
7. How can you persist REPL history between sessions?
8. Explain how the REPL integrates with the Node.js debugger.

### 🌍 Real-World Scenarios

**Scenario 1: Database Administration Tool**
> Building a CLI tool with REPL for database administration with auto-completion for collections and queries.

**Implementation:**
```javascript
const repl = require('repl');
const { MongoClient } = require('mongodb');

class DatabaseREPL {
  constructor(connectionString) {
    this.connectionString = connectionString;
    this.db = null;
    this.collections = new Set();
  }
  
  async start() {
    // Connect to database
    const client = new MongoClient(this.connectionString);
    await client.connect();
    this.db = client.db();
    
    // Get collection names for autocomplete
    const collectionNames = await this.db.listCollections().toArray();
    this.collections = new Set(collectionNames.map(c => c.name));
    
    // Start REPL
    const r = repl.start({
      prompt: 'db> ',
      completer: this.completer.bind(this),
      ignoreUndefined: true
    });
    
    // Add db methods to context
    r.context.db = this.db;
    r.context.find = this.find.bind(this);
    r.context.insert = this.insert.bind(this);
    r.context.aggregate = this.aggregate.bind(this);
    
    // Add helper functions
    r.context.pretty = (doc) => console.dir(doc, { depth: null, colors: true });
    r.context.count = async (collection) => {
      return this.db.collection(collection).countDocuments();
    };
    
    // Command history
    r.setupHistory('.db_repl_history', (err) => {
      if (err) console.error('History error:', err);
    });
    
    r.on('exit', () => {
      console.log('Closing database connection...');
      client.close();
    });
    
    return r;
  }
  
  completer(line) {
    const parts = line.split('.');
    const lastPart = parts[parts.length - 1];
    
    if (line.includes('db.')) {
      // Database collections
      const hits = Array.from(this.collections)
        .filter(c => c.startsWith(lastPart))
        .map(c => `db.${c}`);
      return [hits, line];
    }
    
    // Command completion
    const commands = ['find', 'insert', 'aggregate', 'count', 'pretty'];
    const hits = commands.filter(c => c.startsWith(lastPart));
    return [hits, line];
  }
  
  async find(collection, query = {}, options = {}) {
    const cursor = this.db.collection(collection).find(query, options);
    
    if (options.limit) {
      return cursor.limit(options.limit).toArray();
    }
    
    // For REPL, limit large results
    return cursor.limit(100).toArray();
  }
}
```

**Scenario 2: Microservices Debug REPL**
> Creating a REPL that can connect to different microservices for debugging and inspection.

**Advanced REPL with Multiple Contexts:**
```javascript
const repl = require('repl');
const chalk = require('chalk');
const axios = require('axios');

class MicroservicesREPL {
  constructor(services) {
    this.services = services;
    this.currentService = null;
    this.history = [];
  }
  
  async start() {
    const r = repl.start({
      prompt: this.getPrompt.bind(this),
      eval: this.evaluator.bind(this),
      writer: this.outputWriter.bind(this),
      completer: this.serviceCompleter.bind(this)
    });
    
    // Initialize contexts
    r.context.services = this.services;
    r.context.connect = this.connectToService.bind(this);
    r.context.disconnect = () => {
      this.currentService = null;
      console.log(chalk.yellow('Disconnected from service'));
    };
    
    r.context.call = async (method, endpoint, data) => {
      if (!this.currentService) {
        throw new Error('Not connected to any service');
      }
      
      const service = this.services[this.currentService];
      const url = `${service.url}${endpoint}`;
      
      try {
        const response = await axios({
          method,
          url,
          data,
          headers: {
            'x-repl-session': 'debug-mode'
          }
        });
        
        this.history.push({
          timestamp: new Date(),
          service: this.currentService,
          method,
          endpoint,
          status: response.status
        });
        
        return response.data;
      } catch (error) {
        console.error(chalk.red(`API Error: ${error.message}`));
        return { error: error.response?.data || error.message };
      }
    };
    
    // Add command shortcuts
    r.defineCommand('services', {
      help: 'List all available services',
      action: () => {
        console.log(chalk.cyan('\nAvailable services:'));
        Object.keys(this.services).forEach(name => {
          console.log(`  ${chalk.green(name)}: ${this.services[name].url}`);
        });
        r.displayPrompt();
      }
    });
    
    r.defineCommand('history', {
      help: 'Show API call history',
      action: () => {
        console.log(chalk.cyan('\nAPI Call History:'));
        this.history.forEach((entry, i) => {
          console.log(
            `${i + 1}. ${entry.timestamp.toISOString()} ` +
            `${chalk.green(entry.service)} ${entry.method} ${entry.endpoint} ` +
            `(${entry.status})`
          );
        });
        r.displayPrompt();
      }
    });
    
    return r;
  }
  
  getPrompt() {
    if (this.currentService) {
      return chalk.blue(`${this.currentService}> `);
    }
    return chalk.yellow('global> ');
  }
  
  async evaluator(code, context, filename, callback) {
    // Custom evaluation with service context
    try {
      if (code.startsWith('.')) {
        // REPL command
        return callback(null, null);
      }
      
      // Check if it's a service-specific command
      if (this.currentService && code.includes('call(')) {
        // Already handled by context.call
        return callback(null, null);
      }
      
      // Default evaluation
      const result = eval(code);
      callback(null, result);
    } catch (error) {
      callback(error);
    }
  }
  
  outputWriter(output) {
    // Colorize output based on type
    if (output && typeof output === 'object') {
      return util.inspect(output, {
        colors: true,
        depth: 4,
        maxArrayLength: 20
      });
    }
    
    if (typeof output === 'string') {
      return chalk.white(output);
    }
    
    return output;
  }
  
  connectToService(serviceName) {
    if (!this.services[serviceName]) {
      throw new Error(`Service ${serviceName} not found`);
    }
    
    this.currentService = serviceName;
    console.log(chalk.green(`Connected to ${serviceName}`));
    return true;
  }
}
```

---

## 8. Node Process Lifecycle

### In-depth Explanation

**Process Startup:**
1. **Initialization**: Load dependencies, parse CLI arguments
2. **Event Loop Setup**: Initialize libuv, create event loop
3. **Execution**: Run main module, handle I/O
4. **Cleanup**: Close handles, exit

**Process Events:**
```javascript
process.on('beforeExit', (code) => {
  // Sync operations only
  console.log('Process beforeExit with code:', code);
});

process.on('exit', (code) => {
  // Only sync operations allowed
  console.log('Process exiting with code:', code);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Perform cleanup
  server.close(() => {
    console.log('Server closed due to uncaught exception');
    process.exit(1);
  });
  
  // Force exit after timeout
  setTimeout(() => process.exit(1), 5000);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('warning', (warning) => {
  console.warn('Node.js warning:', warning);
});
```

**Graceful Shutdown:**
```javascript
class GracefulShutdown {
  constructor() {
    this.isShuttingDown = false;
    this.cleanupTasks = [];
    this.timeout = 30000; // 30 seconds
    
    this.setupSignalHandlers();
  }
  
  setupSignalHandlers() {
    // SIGTERM (Docker/K8s stop)
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));
    
    // SIGINT (Ctrl+C)
    process.on('SIGINT', () => this.shutdown('SIGINT'));
    
    // SIGUSR2 (Nodemon restart)
    process.on('SIGUSR2', () => this.shutdown('SIGUSR2'));
  }
  
  addCleanupTask(name, task, timeout = 5000) {
    this.cleanupTasks.push({ name, task, timeout });
  }
  
  async shutdown(signal) {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;
    
    console.log(`Received ${signal}, starting graceful shutdown...`);
    
    // Set overall timeout
    const shutdownTimer = setTimeout(() => {
      console.error('Shutdown timeout, forcing exit');
      process.exit(1);
    }, this.timeout);
    
    try {
      // Execute cleanup tasks in sequence
      for (const { name, task, timeout } of this.cleanupTasks) {
        console.log(`Cleaning up: ${name}`);
        
        await Promise.race([
          task(),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error(`Timeout cleaning up ${name}`)), timeout)
          )
        ]);
        
        console.log(`Completed: ${name}`);
      }
      
      clearTimeout(shutdownTimer);
      console.log('Graceful shutdown completed');
      process.exit(0);
      
    } catch (error) {
      console.error('Shutdown failed:', error);
      clearTimeout(shutdownTimer);
      process.exit(1);
    }
  }
}
```

**Process Monitoring:**
```javascript
// Monitor process metrics
const monitorProcess = () => {
  setInterval(() => {
    const metrics = {
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      cpu: process.cpuUsage(),
      pid: process.pid,
      ppid: process.ppid,
      platform: process.platform,
      version: process.version,
      argv: process.argv,
      execArgv: process.execArgv,
      cwd: process.cwd(),
      title: process.title,
      arch: process.arch
    };
    
    // Log if memory usage is high
    if (metrics.memory.heapUsed / metrics.memory.heapTotal > 0.8) {
      console.warn('High memory usage:', metrics.memory);
    }
    
    // Export metrics for monitoring systems
    if (process.send) {
      process.send({ type: 'metrics', data: metrics });
    }
    
  }, 10000); // Every 10 seconds
};
```

### 🔥 Interview Questions

**Mid-level:**
1. What is the difference between `process.exit()` and throwing an uncaught exception?
2. How do you handle graceful shutdown in Node.js?
3. What are the different signals a Node.js process can receive?
4. How can you monitor memory usage in a Node.js process?

**Senior Level:**
5. Explain the Node.js process startup sequence in detail.
6. How would you implement zero-downtime deployments with Node.js?
7. What are the implications of the `--max-old-space-size` flag?
8. How does Node.js handle orphaned processes and zombie processes?

### 🌍 Real-World Scenarios

**Scenario 1: High-Availability Microservice**
> Implementing a microservice that needs 99.99% uptime with zero-downtime deployments and graceful failure handling.

**Production-Ready Process Manager:**
```javascript
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;

class ProductionProcessManager {
  constructor() {
    this.workers = new Map();
    this.isShuttingDown = false;
    this.workerRestartDelay = 1000;
    this.maxWorkerRestarts = 5;
    this.workerRestartCounts = new Map();
  }
  
  start() {
    if (cluster.isMaster) {
      this.startMaster();
    } else {
      this.startWorker();
    }
  }
  
  startMaster() {
    console.log(`Master ${process.pid} is running`);
    
    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
      this.forkWorker();
    }
    
    // Handle cluster events
    cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died (${signal || code})`);
      this.workers.delete(worker.id);
      
      if (!this.isShuttingDown) {
        this.restartWorker(worker);
      }
    });
    
    // Graceful shutdown handler
    this.setupGracefulShutdown();
    
    // Health check endpoint
    require('http').createServer((req, res) => {
      if (req.url === '/health') {
        const health = {
          status: 'healthy',
          workers: Array.from(this.workers.values()).map(w => ({
            id: w.id,
            pid: w.process.pid,
            state: w.state
          })),
          memory: process.memoryUsage(),
          uptime: process.uptime()
        };
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(health));
      }
    }).listen(8081);
  }
  
  forkWorker() {
    const worker = cluster.fork();
    this.workers.set(worker.id, worker);
    this.workerRestartCounts.set(worker.id, 0);
    
    worker.on('message', (message) => {
      if (message.type === 'ready') {
        console.log(`Worker ${worker.process.pid} is ready`);
      }
      
      if (message.type === 'error') {
        console.error(`Worker ${worker.process.pid} error:`, message.error);
      }
    });
  }
  
  restartWorker(deadWorker) {
    const restartCount = this.workerRestartCounts.get(deadWorker.id) || 0;
    
    if (restartCount >= this.maxWorkerRestarts) {
      console.error(`Worker ${deadWorker.id} restarted too many times, giving up`);
      return;
    }
    
    setTimeout(() => {
      console.log(`Restarting worker ${deadWorker.id} (attempt ${restartCount + 1})`);
      this.workerRestartCounts.set(deadWorker.id, restartCount + 1);
      this.forkWorker();
    }, this.workerRestartDelay);
  }
  
  setupGracefulShutdown() {
    const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
    
    signals.forEach(signal => {
      process.on(signal, async () => {
        console.log(`Received ${signal}, starting graceful shutdown...`);
        this.isShuttingDown = true;
        
        // Stop accepting new connections
        const promises = [];
        
        for (const worker of this.workers.values()) {
          promises.push(new Promise(resolve => {
            worker.on('disconnect', resolve);
            worker.send({ type: 'shutdown' });
            
            // Force kill after timeout
            setTimeout(() => {
              if (worker.isConnected()) {
                worker.kill('SIGKILL');
              }
              resolve();
            }, 30000);
          }));
        }
        
        await Promise.all(promises);
        console.log('All workers stopped, exiting master');
        process.exit(0);
      });
    });
  }
  
  startWorker() {
    const app = require('./app'); // Your application
    const server = app.listen(0, () => {
      console.log(`Worker ${process.pid} listening on port ${server.address().port}`);
      process.send({ type: 'ready' });
    });
    
    // Handle worker shutdown
    process.on('message', async (message) => {
      if (message.type === 'shutdown') {
        console.log(`Worker ${process.pid} received shutdown signal`);
        
        // Stop accepting new connections
        server.close(() => {
          console.log(`Worker ${process.pid} server closed`);
          
          // Close database connections, etc.
          this.cleanup().then(() => {
            console.log(`Worker ${process.pid} cleanup completed`);
            process.exit(0);
          });
        });
        
        // Force exit after timeout
        setTimeout(() => {
          console.log(`Worker ${process.pid} shutdown timeout, forcing exit`);
          process.exit(1);
        }, 29000);
      }
    });
    
    // Error handling
    process.on('uncaughtException', (error) => {
      console.error(`Worker ${process.pid} uncaught exception:`, error);
      process.send({ type: 'error', error: error.message });
      
      // Don't exit immediately, let master handle restart
      setTimeout(() => process.exit(1), 1000);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error(`Worker ${process.pid} unhandled rejection:`, reason);
      process.send({ type: 'error', error: 'Unhandled rejection' });
    });
  }
}
```

**Scenario 2: Resource-Constrained Environment**
> Running Node.js in a container with strict memory limits, needing to prevent OOM kills and optimize resource usage.

**Resource-Aware Application:**
```javascript
const v8 = require('v8');
const stream = require('stream');

class ResourceAwareApp {
  constructor() {
    this.memoryLimit = process.env.MEMORY_LIMIT || 512 * 1024 * 1024; // 512MB
    this.memoryCheckInterval = 5000; // 5 seconds
    this.concurrencyLimit = 10;
    this.activeRequests = 0;
    
    this.setupResourceMonitoring();
    this.setupCircuitBreakers();
  }
  
  setupResourceMonitoring() {
    // Monitor heap usage
    setInterval(() => {
      const heapStats = v8.getHeapStatistics();
      const memoryUsage = process.memoryUsage();
      
      const metrics = {
        heapUsed: heapStats.used_heap_size,
        heapTotal: heapStats.total_heap_size,
        heapLimit: heapStats.heap_size_limit,
        rss: memoryUsage.rss,
        external: memoryUsage.external,
        arrayBuffers: memoryUsage.arrayBuffers
      };
      
      // Check if we're approaching memory limit
      const usageRatio = metrics.heapUsed / this.memoryLimit;
      
      if (usageRatio > 0.8) {
        console.warn('High memory usage, enabling backpressure');
        this.enableBackpressure = true;
        this.reduceConcurrency();
      }
      
      if (usageRatio > 0.9) {
        console.error('Critical memory usage, shedding load');
        this.shedLoad();
      }
      
      // Log memory statistics
      if (usageRatio > 0.7) {
        console.log('Memory metrics:', metrics);
      }
      
    }, this.memoryCheckInterval);
    
    // Handle GC events
    if (global.gc) {
      // Enable manual GC triggers under memory pressure
      v8.setFlagsFromString('--expose_gc');
    }
  }
  
  setupCircuitBreakers() {
    // Circuit breaker for memory-intensive operations
    this.circuitBreakers = {
      imageProcessing: {
        failures: 0,
        lastFailure: 0,
        state: 'CLOSED', // CLOSED, OPEN, HALF_OPEN
        threshold: 5,
        resetTimeout: 60000
      }
    };
    
    setInterval(() => {
      for (const [name, breaker] of Object.entries(this.circuitBreakers)) {
        if (breaker.state === 'OPEN' && 
            Date.now() - breaker.lastFailure > breaker.resetTimeout) {
          breaker.state = 'HALF_OPEN';
          console.log(`Circuit breaker ${name} moving to HALF_OPEN`);
        }
      }
    }, 10000);
  }
  
  async handleRequestWithBackpressure(req, res) {
    // Check concurrency limit
    if (this.activeRequests >= this.concurrencyLimit && this.enableBackpressure) {
      res.writeHead(503, { 'Retry-After': '5' });
      res.end('Service temporarily unavailable');
      return;
    }
    
    this.activeRequests++;
    
    try {
      // Process request with streaming to avoid large memory usage
      const transform = new stream.Transform({
        transform(chunk, encoding, callback) {
          // Process chunk by chunk
          const processed = this.processChunk(chunk);
          callback(null, processed);
        },
        flush(callback) {
          callback(null, this.finalize());
        }
      });
      
      req.pipe(transform).pipe(res);
      
      // Handle stream completion
      transform.on('end', () => {
        this.activeRequests--;
      });
      
      transform.on('error', (error) => {
        console.error('Stream error:', error);
        this.activeRequests--;
        if (!res.headersSent) {
          res.writeHead(500).end('Internal server error');
        }
      });
      
    } catch (error) {
      this.activeRequests--;
      throw error;
    }
  }
  
  reduceConcurrency() {
    // Dynamically reduce concurrency based on memory pressure
    const newLimit = Math.max(1, Math.floor(this.concurrencyLimit * 0.7));
    console.log(`Reducing concurrency from ${this.concurrencyLimit} to ${newLimit}`);
    this.concurrencyLimit = newLimit;
  }
  
  shedLoad() {
    // Implement load shedding strategies
    console.log('Shedding load due to resource pressure');
    
    // Options:
    // 1. Return 503 for non-critical endpoints
    // 2. Degrade functionality (return cached/stale data)
    // 3. Reject new WebSocket connections
    // 4. Trigger manual garbage collection
    
    if (global.gc) {
      global.gc();
    }
  }
  
  async executeWithCircuitBreaker(name, operation) {
    const breaker = this.circuitBreakers[name];
    
    if (!breaker) {
      return operation();
    }
    
    if (breaker.state === 'OPEN') {
      throw new Error(`Circuit breaker ${name} is OPEN`);
    }
    
    try {
      const result = await operation();
      
      // Reset on success
      if (breaker.state === 'HALF_OPEN') {
        breaker.state = 'CLOSED';
        breaker.failures = 0;
      }
      
      return result;
      
    } catch (error) {
      breaker.failures++;
      breaker.lastFailure = Date.now();
      
      if (breaker.failures >= breaker.threshold) {
        breaker.state = 'OPEN';
        console.error(`Circuit breaker ${name} opened due to ${breaker.failures} failures`);
      }
      
      throw error;
    }
  }
}
```

---

## 🎯 Summary

Node.js is a powerful runtime that excels in I/O-heavy applications due to its event-driven, non-blocking architecture. Understanding the fundamentals—from the event loop and libuv to module systems and process management—is crucial for building scalable, performant applications.

**Key Takeaways:**
1. **Event Loop**: Master the phases and understand microtask vs macrotask queues
2. **Async Patterns**: Use async/await with proper error handling for maintainable code
3. **Resource Management**: Monitor and optimize memory usage in long-running processes
4. **Scalability**: Leverage clustering and worker threads for CPU-intensive tasks
5. **Production Readiness**: Implement graceful shutdown, health checks, and circuit breakers

**Further Learning:**
- Explore Deno and Bun for alternative runtimes
- Study Node.js internals through the source code
- Practice with real-world scenarios like building APIs, WebSocket servers, and CLI tools
- Stay updated with Node.js releases and new features

Remember: The best way to master Node.js is through building real applications and understanding the trade-offs in different architectural decisions.