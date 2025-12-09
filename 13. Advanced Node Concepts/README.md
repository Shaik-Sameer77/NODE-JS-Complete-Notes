# 🚀 Advanced Node.js Concepts Guide

## 📑 Table of Contents
1. [Request Lifecycle in Express](#request-lifecycle-in-express)
2. [Streams & Buffers Deeply](#streams-buffers-deeply)
3. [Backpressure](#backpressure)
4. [Load Balancing](#load-balancing)
5. [Child Processes](#child-processes)
6. [Worker Threads](#worker-threads)
7. [Cluster Mode](#cluster-mode)
8. [Event Emitter Custom Usage](#event-emitter-custom-usage)
9. [Creating Your Own Framework (Mini Express)](#creating-your-own-framework)
10. [File Watchers](#file-watchers)

---

## 1. Request Lifecycle in Express <a name="request-lifecycle-in-express"></a>

### Overview
Understanding the complete journey of an HTTP request through Express.js is crucial for debugging, optimization, and building middleware.

### Detailed Lifecycle Flow

```javascript
const express = require('express');
const app = express();

// 1. HTTP Request Received
// -------------------------
// Node.js HTTP server receives raw HTTP request
// Creates req (IncomingMessage) and res (ServerResponse) objects

// 2. Express Application Layer
// ----------------------------
app.on('request', (req, res) => {
  console.log('Request received at Express level');
});

// 3. Built-in Middleware (Order matters!)
// ----------------------------------------
// These execute in the order they're added

// a. Pre-processing middleware
app.use((req, res, next) => {
  console.log('1. Request starts');
  req.startTime = Date.now();
  next(); // Pass control to next middleware
});

// b. Body parsing (if enabled)
app.use(express.json()); // Creates req.body
app.use(express.urlencoded({ extended: true }));

// c. Cookie parsing
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// d. Static file serving
app.use(express.static('public'));

// 4. Custom Middleware Stack
// ---------------------------
const authMiddleware = (req, res, next) => {
  console.log('2. Authentication check');
  if (!req.headers.authorization) {
    // Short-circuit the lifecycle - response sent here
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = { id: 123, name: 'John' };
  next(); // Continue to next middleware
};

const loggingMiddleware = (req, res, next) => {
  console.log('3. Logging request');
  next();
};

const validationMiddleware = (schema) => (req, res, next) => {
  console.log('4. Validating request');
  // Validate req.body against schema
  next();
};

// 5. Route Matching & Execution
// ------------------------------
app.get('/api/users/:id', 
  authMiddleware,
  loggingMiddleware,
  validationMiddleware(userSchema),
  async (req, res, next) => {
    console.log('5. Route handler executing');
    
    try {
      // Route-specific logic
      const user = await User.findById(req.params.id);
      
      // Send response
      res.json(user);
      
      console.log('6. Response sent');
    } catch (error) {
      // Error handling
      next(error); // Pass to error middleware
    }
  }
);

// 6. Error Handling Middleware
// -----------------------------
// Executes when next(error) is called
app.use((error, req, res, next) => {
  console.error('Error occurred:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: error.message 
  });
});

// 7. 404 Handler (Catches unmatched routes)
// -----------------------------------------
app.use((req, res, next) => {
  console.log('No route matched');
  res.status(404).json({ error: 'Not found' });
});

// 8. Response Completion Events
// ------------------------------
app.use((req, res, next) => {
  // Hook into response finish
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    console.log(`Request completed in ${duration}ms`);
  });
  
  res.on('close', () => {
    console.log('Client disconnected prematurely');
  });
  
  next();
});

// 9. Lifecycle Visualization Helper
class RequestTracker {
  constructor() {
    this.phases = [];
  }
  
  track(phase, data = {}) {
    this.phases.push({
      phase,
      timestamp: Date.now(),
      data
    });
  }
  
  getTimeline() {
    return this.phases.map(p => ({
      ...p,
      duration: p.timestamp - this.phases[0].timestamp
    }));
  }
}

// Usage in middleware
app.use((req, res, next) => {
  req.tracker = new RequestTracker();
  req.tracker.track('request_received', {
    method: req.method,
    url: req.url,
    ip: req.ip
  });
  next();
});

// 10. Advanced: Custom Router Implementation
class CustomRouter {
  constructor() {
    this.routes = [];
    this.middleware = [];
  }
  
  use(fn) {
    this.middleware.push(fn);
  }
  
  get(path, ...handlers) {
    this.routes.push({
      method: 'GET',
      path,
      handlers: [...this.middleware, ...handlers]
    });
  }
  
  async handleRequest(req, res) {
    // Find matching route
    const route = this.routes.find(r => 
      r.method === req.method && 
      this.matchPath(r.path, req.url)
    );
    
    if (!route) {
      res.status(404).end();
      return;
    }
    
    // Execute middleware chain
    let index = 0;
    const next = async (err) => {
      if (err) {
        // Error handling
        res.status(500).json({ error: err.message });
        return;
      }
      
      const handler = route.handlers[index++];
      if (!handler) return;
      
      try {
        await handler(req, res, next);
      } catch (error) {
        next(error);
      }
    };
    
    await next();
  }
  
  matchPath(routePath, requestPath) {
    // Simple path matching logic
    return routePath === requestPath;
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Trace the exact order of middleware execution when a POST request hits `/api/users` with Express.json() middleware enabled."
2. "How does Express handle async errors in middleware vs sync errors? What's the difference in behavior?"
3. "Explain the role of `next('route')` and how it differs from regular `next()`."

**Scenario-Based Questions:**
1. "A request hangs indefinitely. Using your knowledge of Express lifecycle, what would be your systematic debugging approach?"
2. "You need to implement request timing that includes time spent in database calls. How would you instrument the entire request lifecycle?"
3. "Users report that some POST requests are being processed twice. What in the Express lifecycle could cause this and how would you debug it?"

**Real-World Challenge:**
> "Design a request tracing system for a microservices architecture that: 1) Tracks a request across multiple Express services, 2) Correlates logs from different middleware layers, 3) Measures time spent in each middleware, 4) Handles async/await middleware properly, 5) Provides real-time visualization of request flow."

---

## 2. Streams & Buffers Deeply <a name="streams-buffers-deeply"></a>

### Overview
Streams are Node.js's solution for handling I/O efficiently, allowing data processing in chunks rather than loading everything into memory.

### Buffer Deep Dive

```javascript
// Buffer: Binary data handling
class BufferMasterclass {
  // 1. Buffer Creation
  static createBuffers() {
    // From string
    const buf1 = Buffer.from('Hello World', 'utf8');
    
    // From array
    const buf2 = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    
    // Allocated buffer
    const buf3 = Buffer.alloc(1024); // 1KB zero-filled buffer
    const buf4 = Buffer.allocUnsafe(1024); // Faster, but contains old data
    
    // From buffer
    const buf5 = Buffer.from(buf1);
    
    return { buf1, buf2, buf3, buf4, buf5 };
  }

  // 2. Buffer Operations
  static bufferOperations() {
    const buffer = Buffer.alloc(10);
    
    // Writing data
    buffer.write('Hello', 0, 'utf8');
    buffer.write('World', 5, 'utf8');
    
    // Reading data
    console.log(buffer.toString('utf8', 0, 5)); // Hello
    console.log(buffer.toString('utf8', 5, 10)); // World
    
    // Buffer slicing (shares memory!)
    const slice = buffer.slice(0, 5);
    slice[0] = 0x4A; // Changes original buffer too!
    
    // Copying (doesn't share memory)
    const copy = Buffer.alloc(5);
    buffer.copy(copy, 0, 0, 5);
    
    // Buffer comparison
    const bufA = Buffer.from('ABC');
    const bufB = Buffer.from('ABCD');
    console.log(Buffer.compare(bufA, bufB)); // -1
    
    // Concatenation
    const combined = Buffer.concat([bufA, bufB]);
    
    // Iteration
    for (const byte of buffer) {
      console.log(byte);
    }
    
    // Search
    const index = buffer.indexOf('World');
    
    return { buffer, slice, copy, combined, index };
  }

  // 3. Buffer Encoding/Decoding
  static encodingDecoding() {
    const text = 'Node.js Streams 🚀';
    
    // Different encodings
    const utf8 = Buffer.from(text, 'utf8');
    const base64 = Buffer.from(text).toString('base64');
    const hex = Buffer.from(text).toString('hex');
    const ascii = Buffer.from(text).toString('ascii'); // Lossy!
    
    // Base64 URL encoding (for URLs)
    const base64url = Buffer.from(text)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    // Binary string
    const binary = Buffer.from(text).toString('binary');
    
    return { utf8, base64, hex, ascii, base64url, binary };
  }

  // 4. Buffer Performance
  static bufferPerformance() {
    // Pool size configuration
    console.log('Buffer pool size:', Buffer.poolSize); // 8192
    
    // Memory allocation strategies
    const size = 1000000; // 1MB
    
    console.time('alloc');
    const safeBuffer = Buffer.alloc(size);
    console.timeEnd('alloc');
    
    console.time('allocUnsafe');
    const unsafeBuffer = Buffer.allocUnsafe(size);
    // Must fill to avoid security issues
    unsafeBuffer.fill(0);
    console.timeEnd('allocUnsafe');
    
    console.time('allocUnsafeSlow');
    const unsafeSlow = Buffer.allocUnsafeSlow(size);
    console.timeEnd('allocUnsafeSlow');
    
    return { safeBuffer, unsafeBuffer, unsafeSlow };
  }

  // 5. Buffer Security
  static bufferSecurity() {
    // Timing attack prevention
    const safeCompare = (a, b) => {
      if (a.length !== b.length) return false;
      
      let result = 0;
      for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
      }
      return result === 0;
    };
    
    // Zero out sensitive data
    const sensitiveBuffer = Buffer.from('SECRET_PASSWORD');
    sensitiveBuffer.fill(0); // Overwrite with zeros
    
    // Prevent buffer overflow
    const validateBufferSize = (buffer, maxSize) => {
      if (buffer.length > maxSize) {
        throw new Error(`Buffer exceeds max size: ${maxSize}`);
      }
      return buffer;
    };
    
    return { safeCompare, sensitiveBuffer };
  }
}
```

### Streams Deep Dive

```javascript
const { 
  Readable, 
  Writable, 
  Duplex, 
  Transform,
  pipeline,
  finished
} = require('stream');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);
const finishedAsync = promisify(finished);

// 1. Custom Readable Stream
class CustomReadable extends Readable {
  constructor(dataSource, options = {}) {
    super({
      ...options,
      // High water mark - internal buffer size
      highWaterMark: options.highWaterMark || 16384,
      // Object mode for non-buffer data
      objectMode: options.objectMode || false,
      // Encoding for strings
      encoding: options.encoding || null
    });
    
    this.dataSource = dataSource;
    this.index = 0;
  }

  _read(size) {
    // size is advisory - can push more or less
    console.log(`_read called with size: ${size}`);
    
    if (this.index >= this.dataSource.length) {
      // No more data
      this.push(null); // Signal end
      return;
    }
    
    // Push data in chunks
    const chunk = this.dataSource.slice(
      this.index, 
      this.index + Math.min(size, 1024)
    );
    
    this.index += chunk.length;
    
    // Push returns false when buffer is full (backpressure)
    const canPushMore = this.push(chunk);
    
    if (!canPushMore) {
      console.log('Backpressure: Pausing data production');
      // In real implementation, you might pause your data source
    }
  }

  // Optional: Destroy handling
  _destroy(err, callback) {
    console.log('Stream destroyed:', err?.message);
    // Clean up resources
    this.dataSource = null;
    callback(err);
  }
}

// 2. Custom Writable Stream
class CustomWritable extends Writable {
  constructor(options = {}) {
    super({
      ...options,
      decodeStrings: true, // Convert strings to buffers
      writev: options.writev || null // For batch writes
    });
    
    this.data = [];
    this.byteCount = 0;
  }

  _write(chunk, encoding, callback) {
    console.log(`_write: ${chunk.length} bytes`);
    
    this.data.push(chunk);
    this.byteCount += chunk.length;
    
    // Simulate async processing
    setTimeout(() => {
      callback(); // Signal ready for more
    }, 10);
  }

  _writev(chunks, callback) {
    // Batch write optimization
    console.log(`_writev: ${chunks.length} chunks`);
    
    let totalBytes = 0;
    for (const { chunk } of chunks) {
      this.data.push(chunk);
      totalBytes += chunk.length;
    }
    this.byteCount += totalBytes;
    
    setTimeout(callback, 5);
  }

  _final(callback) {
    console.log(`Stream finished. Total bytes: ${this.byteCount}`);
    callback();
  }

  _destroy(err, callback) {
    console.log('Writable destroyed');
    this.data = null;
    callback(err);
  }
}

// 3. Custom Transform Stream
class EncryptionTransform extends Transform {
  constructor(algorithm = 'aes-256-gcm', key) {
    super({
      // Transform specific options
      allowHalfOpen: false,
      transform: this._transform.bind(this),
      flush: this._flush.bind(this)
    });
    
    this.algorithm = algorithm;
    this.key = key;
    this.cipher = null;
    this.iv = null;
  }

  _transform(chunk, encoding, callback) {
    if (!this.cipher) {
      this.iv = crypto.randomBytes(16);
      this.cipher = crypto.createCipheriv(
        this.algorithm, 
        this.key, 
        this.iv
      );
      // Push IV first
      this.push(this.iv);
    }
    
    try {
      const encrypted = this.cipher.update(chunk);
      this.push(encrypted);
      callback();
    } catch (error) {
      callback(error);
    }
  }

  _flush(callback) {
    try {
      const finalBlock = this.cipher.final();
      const authTag = this.cipher.getAuthTag();
      
      this.push(finalBlock);
      this.push(authTag);
      callback();
    } catch (error) {
      callback(error);
    }
  }
}

// 4. Custom Duplex Stream
class ThrottledDuplex extends Duplex {
  constructor(options = {}) {
    super({
      ...options,
      allowHalfOpen: false,
      read: this._read.bind(this),
      write: this._write.bind(this)
    });
    
    this.buffer = [];
    this.reading = false;
    this.throttleMs = options.throttleMs || 100;
  }

  _read(size) {
    this.reading = true;
    this._pushFromBuffer();
  }

  _write(chunk, encoding, callback) {
    this.buffer.push(chunk);
    
    if (this.reading) {
      this._pushFromBuffer();
    }
    
    callback();
  }

  _pushFromBuffer() {
    if (this.buffer.length === 0 || !this.reading) {
      return;
    }
    
    const chunk = this.buffer.shift();
    const canPushMore = this.push(chunk);
    
    if (!canPushMore) {
      this.reading = false;
      return;
    }
    
    // Throttle
    setTimeout(() => this._pushFromBuffer(), this.throttleMs);
  }

  _final(callback) {
    // Flush remaining buffer
    while (this.buffer.length > 0 && this.reading) {
      const chunk = this.buffer.shift();
      const canPushMore = this.push(chunk);
      
      if (!canPushMore) {
        break;
      }
    }
    
    this.push(null); // Signal end
    callback();
  }
}

// 5. Advanced Stream Patterns
class StreamPatterns {
  // Fork a stream to multiple destinations
  static forkStream(source, destinations) {
    const tee = new Transform({
      transform(chunk, encoding, callback) {
        destinations.forEach(dest => {
          dest.write(chunk);
        });
        callback();
      },
      
      flush(callback) {
        destinations.forEach(dest => {
          dest.end();
        });
        callback();
      }
    });
    
    source.pipe(tee);
    return tee;
  }

  // Merge multiple streams
  static mergeStreams(sources) {
    const merged = new PassThrough();
    let endedCount = 0;
    
    sources.forEach((source, index) => {
      source.pipe(merged, { end: false });
      
      source.on('end', () => {
        endedCount++;
        if (endedCount === sources.length) {
          merged.end();
        }
      });
      
      source.on('error', (err) => {
        merged.destroy(err);
      });
    });
    
    return merged;
  }

  // Stream with retry logic
  static createRetryStream(sourceFactory, maxRetries = 3) {
    const output = new PassThrough();
    let retries = 0;
    
    const connect = () => {
      const source = sourceFactory();
      
      source.pipe(output, { end: false });
      
      source.on('error', (err) => {
        if (retries < maxRetries) {
          retries++;
          console.log(`Retry ${retries}/${maxRetries}`);
          setTimeout(connect, 1000 * retries); // Exponential backoff
        } else {
          output.destroy(err);
        }
      });
      
      source.on('end', () => {
        output.end();
      });
    };
    
    connect();
    return output;
  }

  // Stream statistics
  static createMonitoredStream(stream, name = 'stream') {
    let bytes = 0;
    let chunks = 0;
    let startTime = Date.now();
    
    const monitor = new Transform({
      transform(chunk, encoding, callback) {
        bytes += chunk.length;
        chunks++;
        this.push(chunk);
        callback();
      },
      
      flush(callback) {
        const duration = Date.now() - startTime;
        console.log(`${name}: ${bytes} bytes, ${chunks} chunks, ${duration}ms`);
        callback();
      }
    });
    
    return stream.pipe(monitor);
  }
}

// 6. Real-world Example: Large File Processor
class FileProcessor {
  constructor() {
    this.fs = require('fs');
    this.zlib = require('zlib');
    this.csv = require('csv-parser');
  }

  async processLargeCSV(inputPath, outputPath, transformFn) {
    const readStream = this.fs.createReadStream(inputPath, {
      highWaterMark: 64 * 1024 // 64KB chunks
    });
    
    const writeStream = this.fs.createWriteStream(outputPath);
    
    const transformStream = new Transform({
      objectMode: true,
      transform(row, encoding, callback) {
        try {
          const transformed = transformFn(row);
          callback(null, JSON.stringify(transformed) + '\n');
        } catch (error) {
          callback(error);
        }
      }
    });
    
    // Error handling with pipeline
    try {
      await pipelineAsync(
        readStream,
        this.csv(),
        transformStream,
        writeStream
      );
      console.log('Processing complete');
    } catch (error) {
      console.error('Processing failed:', error);
      // Clean up partial output
      this.fs.unlink(outputPath, () => {});
    }
  }

  async compressAndEncrypt(inputPath, outputPath, key) {
    const readStream = this.fs.createReadStream(inputPath);
    const writeStream = this.fs.createWriteStream(outputPath);
    
    const encryptStream = new EncryptionTransform('aes-256-gcm', key);
    const compressStream = this.zlib.createGzip({
      level: 9 // Maximum compression
    });
    
    // Monitor progress
    let bytesRead = 0;
    readStream.on('data', (chunk) => {
      bytesRead += chunk.length;
      console.log(`Read: ${bytesRead} bytes`);
    });
    
    await pipelineAsync(
      readStream,
      compressStream,
      encryptStream,
      writeStream
    );
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the difference between `objectMode` and regular binary streams. When would you use each?"
2. "How does the `highWaterMark` property affect stream performance and memory usage?"
3. "What's the difference between `pipe()` and `pipeline()`? When would you choose one over the other?"

**Scenario-Based Questions:**
1. "You're processing a 10GB CSV file. How would you implement a stream that filters rows, transforms data, and writes to a new file without loading everything into memory?"
2. "Users report that file uploads are consuming too much memory. How would you implement a streaming upload processor that validates and processes data in chunks?"
3. "You need to implement a real-time video transcoding service. How would you use streams to handle video chunks with varying sizes and frame rates?"

**Real-World Challenge:**
> "Design a distributed log processing system that: 1) Reads log files from multiple sources using streams, 2) Parses and filters log entries in real-time, 3) Compresses and encrypts log chunks for storage, 4) Handles backpressure when storage is slow, 5) Provides real-time progress monitoring and error recovery for failed chunks."

---

## 3. Backpressure <a name="backpressure"></a>

### Overview
Backpressure is the mechanism that prevents faster data producers from overwhelming slower data consumers in stream-based systems.

### Deep Dive Implementation

```javascript
const { Readable, Writable, pipeline } = require('stream');
const { promisify } = require('util');

class BackpressureMasterclass {
  // 1. Understanding Backpressure Signals
  static demonstrateBackpressure() {
    const fastProducer = new Readable({
      read(size) {
        // Produce data faster than it can be consumed
        for (let i = 0; i < 100; i++) {
          const chunk = Buffer.alloc(1024); // 1KB chunks
          const canPushMore = this.push(chunk);
          
          if (!canPushMore) {
            console.log('Backpressure! Buffer full, pausing production');
            // In real scenario, you'd pause your data source
            break;
          }
        }
        
        if (this.count >= 1000) {
          this.push(null); // End stream
        }
      }
    });
    
    const slowConsumer = new Writable({
      highWaterMark: 8 * 1024, // 8KB buffer
      write(chunk, encoding, callback) {
        console.log(`Consumer received ${chunk.length} bytes`);
        
        // Simulate slow processing
        setTimeout(() => {
          console.log('Consumer processed chunk');
          callback();
        }, 100); // 100ms delay
      }
    });
    
    // Monitor backpressure
    fastProducer.on('pause', () => {
      console.log('Producer paused by backpressure');
    });
    
    fastProducer.on('resume', () => {
      console.log('Producer resumed');
    });
    
    // Pipe with backpressure handling
    fastProducer.pipe(slowConsumer);
  }

  // 2. Custom Backpressure-Aware Producer
  static createBackpressureAwareStream(dataGenerator) {
    let isPaused = false;
    let dataQueue = [];
    
    return new Readable({
      objectMode: true,
      highWaterMark: 100, // Limit queue size
      
      read(size) {
        // If we were paused, resume production
        if (isPaused) {
          isPaused = false;
          this.emit('resume');
        }
        
        // Fill the buffer
        while (this.readableLength < this.readableHighWaterMark) {
          const data = dataGenerator.next();
          if (data.done) {
            this.push(null);
            break;
          }
          
          const canPushMore = this.push(data.value);
          if (!canPushMore) {
            isPaused = true;
            this.emit('pause');
            break;
          }
        }
      }
    });
  }

  // 3. Backpressure Management Strategies
  static backpressureStrategies() {
    return {
      // Strategy 1: Buffering with overflow handling
      bufferingStrategy: class BufferingStream extends Transform {
        constructor(maxBufferSize = 1000) {
          super({
            objectMode: true,
            highWaterMark: maxBufferSize / 2 // Keep some headroom
          });
          this.buffer = [];
          this.maxBufferSize = maxBufferSize;
        }
        
        _transform(chunk, encoding, callback) {
          // Buffer incoming data
          this.buffer.push(chunk);
          
          // If buffer is getting full, apply backpressure
          if (this.buffer.length >= this.maxBufferSize * 0.9) {
            console.warn('Buffer nearly full, applying backpressure');
            // Don't push more until buffer drains
            callback();
            return;
          }
          
          // Process and forward
          this._processBuffer();
          callback();
        }
        
        _processBuffer() {
          while (this.buffer.length > 0) {
            const chunk = this.buffer.shift();
            const canPushMore = this.push(chunk);
            
            if (!canPushMore) {
              // Backpressure applied, stop pushing
              break;
            }
          }
        }
        
        _flush(callback) {
          // Process remaining buffer
          this._processBuffer();
          callback();
        }
      },
      
      // Strategy 2: Dynamic throttling
      throttlingStrategy: class ThrottlingStream extends Transform {
        constructor(targetRate = 1000) { // 1000 bytes/second
          super();
          this.targetRate = targetRate;
          this.bytesProcessed = 0;
          this.startTime = Date.now();
          this.isThrottled = false;
        }
        
        _transform(chunk, encoding, callback) {
          this.bytesProcessed += chunk.length;
          const elapsed = Date.now() - this.startTime;
          const currentRate = (this.bytesProcessed / elapsed) * 1000;
          
          if (currentRate > this.targetRate && !this.isThrottled) {
            console.log(`Rate ${currentRate.toFixed(2)}bps exceeds target, throttling`);
            this.isThrottled = true;
            
            // Apply throttle
            setTimeout(() => {
              this.isThrottled = false;
              this.push(chunk);
              callback();
            }, 100);
          } else {
            this.push(chunk);
            callback();
          }
        }
      },
      
      // Strategy 3: Load shedding (drop data when overloaded)
      loadSheddingStrategy: class LoadSheddingStream extends Transform {
        constructor(dropThreshold = 0.8) {
          super({
            highWaterMark: 1000
          });
          this.dropThreshold = dropThreshold;
          this.droppedCount = 0;
        }
        
        _transform(chunk, encoding, callback) {
          const bufferFullness = this.writableLength / this.writableHighWaterMark;
          
          if (bufferFullness > this.dropThreshold) {
            // Buffer too full, drop this chunk
            this.droppedCount++;
            console.log(`Dropping chunk, buffer ${(bufferFullness * 100).toFixed(1)}% full`);
            
            if (this.droppedCount % 100 === 0) {
              console.warn(`Dropped ${this.droppedCount} chunks due to backpressure`);
            }
            
            callback(); // Acknowledge but don't forward
          } else {
            this.push(chunk);
            callback();
          }
        }
      }
    };
  }

  // 4. Backpressure in Pipeline Chains
  static async complexPipelineBackpressure() {
    const source = this.createFastDataSource();
    
    const processor1 = new Transform({
      transform(chunk, encoding, callback) {
        // CPU-intensive processing
        const processed = this._heavyComputation(chunk);
        callback(null, processed);
      },
      
      _heavyComputation(chunk) {
        // Simulate heavy processing
        for (let i = 0; i < 1000000; i++) {
          Math.sqrt(i);
        }
        return chunk;
      }
    });
    
    const processor2 = new Transform({
      transform(chunk, encoding, callback) {
        // I/O-bound processing
        setTimeout(() => {
          callback(null, chunk);
        }, 50);
      }
    });
    
    const databaseWriter = new Writable({
      async write(chunk, encoding, callback) {
        // Simulate slow database write
        await this._writeToDatabase(chunk);
        callback();
      },
      
      async _writeToDatabase(chunk) {
        return new Promise(resolve => setTimeout(resolve, 100));
      }
    });
    
    // Monitor each stage for backpressure
    [processor1, processor2].forEach((stream, index) => {
      stream.on('pause', () => {
        console.log(`Processor ${index + 1} paused due to backpressure`);
      });
      
      stream.on('resume', () => {
        console.log(`Processor ${index + 1} resumed`);
      });
    });
    
    // Use pipeline for automatic backpressure propagation
    try {
      await promisify(pipeline)(
        source,
        processor1,
        processor2,
        databaseWriter
      );
      console.log('Pipeline completed successfully');
    } catch (error) {
      console.error('Pipeline failed:', error);
    }
  }

  // 5. Backpressure Metrics and Monitoring
  static createMonitoredPipeline() {
    class MonitoringTransform extends Transform {
      constructor(name) {
        super();
        this.name = name;
        this.metrics = {
          bytesProcessed: 0,
          chunksProcessed: 0,
          pauseCount: 0,
          pauseDuration: 0,
          lastPause: null
        };
      }
      
      _transform(chunk, encoding, callback) {
        this.metrics.bytesProcessed += chunk.length;
        this.metrics.chunksProcessed++;
        
        // Check if we're applying backpressure
        const writableHighWaterMark = this.writableHighWaterMark;
        const writableLength = this.writableLength;
        const bufferUsage = writableLength / writableHighWaterMark;
        
        if (bufferUsage > 0.7) {
          console.log(`${this.name} buffer ${(bufferUsage * 100).toFixed(1)}% full`);
        }
        
        this.push(chunk);
        callback();
      }
      
      getMetrics() {
        return {
          ...this.metrics,
          averageChunkSize: this.metrics.bytesProcessed / this.metrics.chunksProcessed
        };
      }
    }
    
    return MonitoringTransform;
  }

  // 6. Real-world Example: HTTP Upload with Backpressure
  static createUploadHandler() {
    const { createWriteStream } = require('fs');
    
    return async (req, res) => {
      // Create file write stream with backpressure handling
      const fileStream = createWriteStream('upload.dat', {
        highWaterMark: 64 * 1024 // 64KB buffer
      });
      
      let bytesReceived = 0;
      let lastReport = Date.now();
      
      // Monitor upload progress
      req.on('data', (chunk) => {
        bytesReceived += chunk.length;
        
        // Report progress every second
        const now = Date.now();
        if (now - lastReport > 1000) {
          const rate = (bytesReceived / (now - lastReport)) * 1000;
          console.log(`Upload: ${bytesReceived} bytes at ${(rate / 1024).toFixed(2)} KB/s`);
          lastReport = now;
        }
        
        // Check if file stream is applying backpressure
        if (fileStream.writableLength > fileStream.writableHighWaterMark * 0.9) {
          console.log('File write slow, applying backpressure to HTTP stream');
          // Pause the HTTP request to avoid memory buildup
          req.pause();
          
          fileStream.once('drain', () => {
            console.log('File writer caught up, resuming HTTP stream');
            req.resume();
          });
        }
      });
      
      // Pipe with backpressure handling
      req.pipe(fileStream);
      
      fileStream.on('finish', () => {
        res.status(200).json({
          message: 'Upload complete',
          bytes: bytesReceived
        });
      });
      
      fileStream.on('error', (error) => {
        console.error('Upload failed:', error);
        res.status(500).json({ error: 'Upload failed' });
      });
    };
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does the `drain` event work in Writable streams and how should it be used to handle backpressure?"
2. "What happens when you ignore backpressure signals in a Readable stream? What are the consequences?"
3. "Explain how backpressure propagates through a chain of piped streams. What happens if one stream in the middle is slow?"

**Scenario-Based Questions:**
1. "You're building a real-time analytics system that processes sensor data. Some sensors send data at 1000 events/second while others send at 10 events/second. How would you handle the backpressure?"
2. "Users report that file uploads fail when network speed exceeds disk write speed. How would you implement backpressure in your upload handler?"
3. "Your stream processing pipeline has one CPU-bound transform that's much slower than the others. How would you prevent it from becoming a bottleneck?"

**Real-World Challenge:**
> "Design a video streaming service that: 1) Handles variable network speeds (mobile vs broadband), 2) Adapts video quality based on client buffer levels, 3) Prevents server memory exhaustion during slow client downloads, 4) Implements fair bandwidth sharing between concurrent streams, 5) Provides real-time metrics on backpressure events for monitoring."

---

## 4. Load Balancing <a name="load-balancing"></a>

### Overview
Load balancing distributes network traffic across multiple servers to ensure no single server bears too much demand.

### Comprehensive Implementation Guide

```javascript
const http = require('http');
const https = require('https');
const cluster = require('cluster');
const net = require('net');

// 1. Layer 4 (TCP) Load Balancer
class TCPLoadBalancer {
  constructor(servers, algorithm = 'round-robin') {
    this.servers = servers; // Array of {host, port, weight}
    this.algorithm = algorithm;
    this.currentIndex = 0;
    this.serverStats = new Map();
    
    // Initialize stats
    servers.forEach(server => {
      this.serverStats.set(this.getServerKey(server), {
        connections: 0,
        errors: 0,
        responseTimes: [],
        healthy: true
      });
    });
    
    // Health check interval
    setInterval(() => this.healthCheck(), 30000);
  }
  
  getServerKey(server) {
    return `${server.host}:${server.port}`;
  }
  
  // Selection algorithms
  selectServer() {
    switch (this.algorithm) {
      case 'round-robin':
        return this.roundRobin();
      case 'least-connections':
        return this.leastConnections();
      case 'weighted-round-robin':
        return this.weightedRoundRobin();
      case 'ip-hash':
        return this.ipHash();
      default:
        return this.roundRobin();
    }
  }
  
  roundRobin() {
    const server = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    return server;
  }
  
  leastConnections() {
    return this.servers.reduce((least, server) => {
      const stats = this.serverStats.get(this.getServerKey(server));
      const leastStats = this.serverStats.get(this.getServerKey(least));
      
      if (stats.healthy && (!leastStats.healthy || stats.connections < leastStats.connections)) {
        return server;
      }
      return least;
    });
  }
  
  weightedRoundRobin() {
    // Calculate total weight
    const totalWeight = this.servers.reduce((sum, server) => sum + (server.weight || 1), 0);
    
    // Select based on weight
    let random = Math.random() * totalWeight;
    for (const server of this.servers) {
      random -= server.weight || 1;
      if (random <= 0) {
        return server;
      }
    }
    
    return this.servers[0];
  }
  
  ipHash(clientIP) {
    // Simple hash function for IP-based routing
    const hash = clientIP.split('.').reduce((acc, octet) => {
      return ((acc << 5) - acc) + parseInt(octet);
    }, 0);
    
    const index = Math.abs(hash) % this.servers.length;
    return this.servers[index];
  }
  
  // Health checking
  async healthCheck() {
    for (const server of this.servers) {
      try {
        const startTime = Date.now();
        await this.checkServerHealth(server);
        const responseTime = Date.now() - startTime;
        
        const stats = this.serverStats.get(this.getServerKey(server));
        stats.healthy = true;
        stats.responseTimes.push(responseTime);
        
        // Keep only last 100 response times
        if (stats.responseTimes.length > 100) {
          stats.responseTimes.shift();
        }
      } catch (error) {
        console.error(`Health check failed for ${this.getServerKey(server)}:`, error.message);
        const stats = this.serverStats.get(this.getServerKey(server));
        stats.healthy = false;
        stats.errors++;
      }
    }
  }
  
  checkServerHealth(server) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(server.port, server.host);
      
      socket.setTimeout(5000);
      
      socket.on('connect', () => {
        socket.end();
        resolve();
      });
      
      socket.on('error', reject);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Timeout'));
      });
    });
  }
  
  // Start load balancer
  start(port = 80) {
    const server = net.createServer((clientSocket) => {
      const clientIP = clientSocket.remoteAddress;
      const targetServer = this.selectServer(clientIP);
      
      if (!targetServer) {
        clientSocket.end();
        return;
      }
      
      const stats = this.serverStats.get(this.getServerKey(targetServer));
      stats.connections++;
      
      console.log(`Routing ${clientIP} to ${targetServer.host}:${targetServer.port}`);
      
      // Create connection to backend server
      const backendSocket = net.createConnection(
        targetServer.port,
        targetServer.host
      );
      
      // Pipe sockets bidirectionally
      clientSocket.pipe(backendSocket);
      backendSocket.pipe(clientSocket);
      
      // Handle connection cleanup
      const cleanup = () => {
        stats.connections--;
        clientSocket.destroy();
        backendSocket.destroy();
      };
      
      clientSocket.on('error', cleanup);
      backendSocket.on('error', cleanup);
      clientSocket.on('end', cleanup);
      backendSocket.on('end', cleanup);
    });
    
    server.listen(port, () => {
      console.log(`TCP Load balancer listening on port ${port}`);
    });
    
    return server;
  }
}

// 2. Layer 7 (HTTP) Load Balancer
class HTTPLoadBalancer {
  constructor(options = {}) {
    this.servers = options.servers || [];
    this.algorithm = options.algorithm || 'round-robin';
    this.ssl = options.ssl;
    this.stickySessions = options.stickySessions || false;
    this.sessionTimeout = options.sessionTimeout || 1800000; // 30 minutes
    
    this.sessionMap = new Map(); // sessionId -> server
    this.serverStats = new Map();
    
    // Initialize reverse proxy
    this.proxy = require('http-proxy').createProxyServer({});
    
    this.setupProxyEvents();
  }
  
  setupProxyEvents() {
    this.proxy.on('error', (err, req, res) => {
      console.error('Proxy error:', err);
      
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Gateway' }));
      }
    });
    
    this.proxy.on('proxyReq', (proxyReq, req, res, options) => {
      // Add headers for backend
      proxyReq.setHeader('X-Forwarded-For', req.connection.remoteAddress);
      proxyReq.setHeader('X-Forwarded-Proto', req.protocol);
      proxyReq.setHeader('X-Forwarded-Host', req.headers.host);
    });
    
    this.proxy.on('proxyRes', (proxyRes, req, res) => {
      // Log response
      const server = options.target;
      const stats = this.serverStats.get(this.getServerKey(server));
      
      if (stats) {
        stats.requests++;
        stats.lastResponseTime = Date.now();
      }
      
      // Handle sticky sessions
      if (this.stickySessions && !res.headersSent) {
        const sessionId = this.getSessionId(req);
        if (sessionId) {
          res.setHeader('Set-Cookie', `sessionId=${sessionId}; Path=/; HttpOnly`);
        }
      }
    });
  }
  
  getSessionId(req) {
    const cookies = req.headers.cookie;
    if (!cookies) return null;
    
    const match = cookies.match(/sessionId=([^;]+)/);
    return match ? match[1] : null;
  }
  
  selectServer(req) {
    // Sticky sessions first
    if (this.stickySessions) {
      const sessionId = this.getSessionId(req);
      if (sessionId && this.sessionMap.has(sessionId)) {
        const server = this.sessionMap.get(sessionId);
        
        // Check if server is still healthy
        const stats = this.serverStats.get(this.getServerKey(server));
        if (stats && stats.healthy) {
          return server;
        }
      }
    }
    
    // Algorithm-based selection
    let server;
    switch (this.algorithm) {
      case 'least-connections':
        server = this.selectLeastConnections();
        break;
      case 'response-time':
        server = this.selectBestResponseTime();
        break;
      case 'ip-hash':
        server = this.selectByIPHash(req.connection.remoteAddress);
        break;
      default: // round-robin
        server = this.selectRoundRobin();
    }
    
    // Store session if using sticky sessions
    if (this.stickySessions && server) {
      const sessionId = require('crypto').randomBytes(16).toString('hex');
      this.sessionMap.set(sessionId, server);
      
      // Cleanup old sessions
      setTimeout(() => {
        this.sessionMap.delete(sessionId);
      }, this.sessionTimeout);
      
      // We'll set the cookie in proxyRes handler
    }
    
    return server;
  }
  
  selectLeastConnections() {
    return this.servers.reduce((best, server) => {
      const bestStats = this.serverStats.get(this.getServerKey(best));
      const serverStats = this.serverStats.get(this.getServerKey(server));
      
      if (!serverStats || !serverStats.healthy) return best;
      if (!bestStats || !bestStats.healthy) return server;
      
      return serverStats.connections < bestStats.connections ? server : best;
    });
  }
  
  selectBestResponseTime() {
    return this.servers.reduce((best, server) => {
      const bestStats = this.serverStats.get(this.getServerKey(best));
      const serverStats = this.serverStats.get(this.getServerKey(server));
      
      if (!serverStats || !serverStats.healthy) return best;
      if (!bestStats || !bestStats.healthy) return server;
      
      const bestAvg = bestStats.responseTimes.reduce((a, b) => a + b, 0) / bestStats.responseTimes.length;
      const serverAvg = serverStats.responseTimes.reduce((a, b) => a + b, 0) / serverStats.responseTimes.length;
      
      return serverAvg < bestAvg ? server : best;
    });
  }
  
  selectByIPHash(ip) {
    const hash = ip.split('.').reduce((acc, octet) => {
      return ((acc << 5) - acc) + parseInt(octet);
    }, 0);
    
    const healthyServers = this.servers.filter(server => {
      const stats = this.serverStats.get(this.getServerKey(server));
      return stats && stats.healthy;
    });
    
    if (healthyServers.length === 0) return null;
    
    const index = Math.abs(hash) % healthyServers.length;
    return healthyServers[index];
  }
  
  selectRoundRobin() {
    const healthyServers = this.servers.filter(server => {
      const stats = this.serverStats.get(this.getServerKey(server));
      return stats && stats.healthy;
    });
    
    if (healthyServers.length === 0) return null;
    
    if (!this.roundRobinIndex || this.roundRobinIndex >= healthyServers.length) {
      this.roundRobinIndex = 0;
    }
    
    return healthyServers[this.roundRobinIndex++];
  }
  
  // Request handler
  handleRequest(req, res) {
    const targetServer = this.selectServer(req);
    
    if (!targetServer) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'No healthy servers available' }));
    }
    
    // Update connection count
    const stats = this.serverStats.get(this.getServerKey(targetServer));
    if (stats) {
      stats.connections++;
      
      // Decrement on response finish
      res.on('finish', () => {
        stats.connections--;
      });
    }
    
    // Proxy the request
    this.proxy.web(req, res, {
      target: `http://${targetServer.host}:${targetServer.port}`,
      changeOrigin: true,
      autoRewrite: true,
      protocolRewrite: 'http'
    });
  }
  
  // Start HTTP load balancer
  start(port = 3000) {
    const server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
    
    if (this.ssl) {
      const httpsServer = https.createServer(this.ssl, (req, res) => {
        this.handleRequest(req, res);
      });
      
      httpsServer.listen(443, () => {
        console.log('HTTPS Load balancer listening on port 443');
      });
      
      // Redirect HTTP to HTTPS
      http.createServer((req, res) => {
        res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
        res.end();
      }).listen(80);
    } else {
      server.listen(port, () => {
        console.log(`HTTP Load balancer listening on port ${port}`);
      });
    }
    
    return server;
  }
}

// 3. DNS-based Load Balancing
class DNSLoadBalancer {
  constructor(zones) {
    this.zones = zones; // Map of domain -> servers[]
    this.dns = require('dns');
    this.cache = new Map();
    this.ttl = 300; // 5 minutes in seconds
  }
  
  async resolve(hostname) {
    // Check cache
    const cached = this.cache.get(hostname);
    if (cached && Date.now() < cached.expires) {
      return cached.ips;
    }
    
    // Get zone configuration
    const zone = this.zones[hostname];
    if (!zone) {
      // Fallback to system DNS
      return new Promise((resolve, reject) => {
        this.dns.resolve4(hostname, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses);
        });
      });
    }
    
    // Select IP based on algorithm
    const ips = this.selectIPs(zone);
    
    // Cache result
    this.cache.set(hostname, {
      ips,
      expires: Date.now() + (this.ttl * 1000)
    });
    
    return ips;
  }
  
  selectIPs(zone) {
    const { servers, algorithm = 'round-robin' } = zone;
    
    switch (algorithm) {
      case 'weighted':
        return this.weightedSelection(servers);
      case 'geo':
        return this.geoSelection(servers);
      default:
        return servers.map(s => s.ip);
    }
  }
  
  weightedSelection(servers) {
    const totalWeight = servers.reduce((sum, server) => sum + server.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const server of servers) {
      random -= server.weight;
      if (random <= 0) {
        return [server.ip];
      }
    }
    
    return [servers[0].ip];
  }
  
  geoSelection(servers) {
    // Simplified geographic selection
    // In production, use MaxMind or similar for client IP geolocation
    return servers
      .sort((a, b) => b.priority - a.priority)
      .map(s => s.ip);
  }
  
  // DNS server implementation (simplified)
  startDNSServer(port = 53) {
    const dgram = require('dgram');
    const server = dgram.createSocket('udp4');
    
    server.on('message', async (msg, rinfo) => {
      try {
        // Parse DNS query (simplified)
        const hostname = this.parseDNSQuery(msg);
        const ips = await this.resolve(hostname);
        
        // Build DNS response
        const response = this.buildDNSResponse(msg, ips);
        
        server.send(response, rinfo.port, rinfo.address);
      } catch (error) {
        console.error('DNS error:', error);
      }
    });
    
    server.bind(port);
    console.log(`DNS load balancer listening on port ${port}`);
    
    return server;
  }
  
  parseDNSQuery(msg) {
    // Simplified parsing - real implementation would use DNS packet parsing
    return 'example.com';
  }
  
  buildDNSResponse(query, ips) {
    // Build proper DNS response
    // This is a simplified example
    return Buffer.from('response');
  }
}

// 4. Application-Level Load Balancing with Service Discovery
class ServiceRegistry {
  constructor() {
    this.services = new Map(); // serviceName -> instances[]
    this.heartbeats = new Map();
    this.ttl = 30000; // 30 seconds
  }
  
  register(serviceName, instance) {
    if (!this.services.has(serviceName)) {
      this.services.set(serviceName, []);
    }
    
    const instances = this.services.get(serviceName);
    const existingIndex = instances.findIndex(i => i.id === instance.id);
    
    if (existingIndex >= 0) {
      instances[existingIndex] = instance;
    } else {
      instances.push(instance);
    }
    
    // Update heartbeat
    this.heartbeats.set(instance.id, Date.now());
    
    console.log(`Registered ${serviceName}: ${instance.host}:${instance.port}`);
  }
  
  deregister(serviceName, instanceId) {
    const instances = this.services.get(serviceName);
    if (!instances) return;
    
    const index = instances.findIndex(i => i.id === instanceId);
    if (index >= 0) {
      instances.splice(index, 1);
      this.heartbeats.delete(instanceId);
      console.log(`Deregistered ${serviceName}: ${instanceId}`);
    }
  }
  
  discover(serviceName) {
    const instances = this.services.get(serviceName) || [];
    
    // Filter out stale instances
    const now = Date.now();
    const activeInstances = instances.filter(instance => {
      const lastHeartbeat = this.heartbeats.get(instance.id);
      return lastHeartbeat && (now - lastHeartbeat) < this.ttl;
    });
    
    // Update services list
    this.services.set(serviceName, activeInstances);
    
    return activeInstances;
  }
  
  // Heartbeat cleanup
  startCleanup() {
    setInterval(() => {
      const now = Date.now();
      
      for (const [serviceName, instances] of this.services.entries()) {
        const activeInstances = instances.filter(instance => {
          const lastHeartbeat = this.heartbeats.get(instance.id);
          return lastHeartbeat && (now - lastHeartbeat) < this.ttl;
        });
        
        if (activeInstances.length !== instances.length) {
          console.log(`Cleaned up ${instances.length - activeInstances.length} stale instances from ${serviceName}`);
          this.services.set(serviceName, activeInstances);
        }
      }
    }, this.ttl);
  }
}

class SmartLoadBalancer {
  constructor(serviceRegistry) {
    this.registry = serviceRegistry;
    this.metrics = new Map();
    this.circuitBreakers = new Map();
  }
  
  async selectInstance(serviceName, req) {
    const instances = this.registry.discover(serviceName);
    
    if (instances.length === 0) {
      throw new Error(`No instances available for ${serviceName}`);
    }
    
    // Filter out instances with open circuit breakers
    const availableInstances = instances.filter(instance => {
      const breaker = this.circuitBreakers.get(instance.id);
      return !breaker || breaker.state !== 'OPEN';
    });
    
    if (availableInstances.length === 0) {
      // All circuit breakers are open, try half-open
      const halfOpenInstances = instances.filter(instance => {
        const breaker = this.circuitBreakers.get(instance.id);
        return breaker && breaker.state === 'HALF_OPEN';
      });
      
      if (halfOpenInstances.length > 0) {
        return this.selectByAlgorithm(halfOpenInstances, 'round-robin');
      }
      
      throw new Error(`All instances for ${serviceName} are unavailable`);
    }
    
    // Select based on metrics
    return this.selectByMetrics(availableInstances);
  }
  
  selectByMetrics(instances) {
    // Combine multiple metrics for selection
    return instances.reduce((best, instance) => {
      const bestMetrics = this.metrics.get(best.id) || { score: 0 };
      const instanceMetrics = this.metrics.get(instance.id) || { score: 0 };
      
      // Calculate score based on multiple factors
      const instanceScore = this.calculateScore(instance, instanceMetrics);
      const bestScore = this.calculateScore(best, bestMetrics);
      
      return instanceScore > bestScore ? instance : best;
    });
  }
  
  calculateScore(instance, metrics) {
    let score = 100; // Base score
    
    // Adjust based on error rate
    if (metrics.errorRate > 0.1) score -= 50;
    if (metrics.errorRate > 0.3) score -= 30;
    
    // Adjust based on response time
    if (metrics.avgResponseTime > 1000) score -= 20;
    if (metrics.avgResponseTime > 5000) score -= 30;
    
    // Adjust based on CPU/memory if available
    if (metrics.cpuUsage > 80) score -= 20;
    if (metrics.memoryUsage > 90) score -= 20;
    
    return score;
  }
  
  updateMetrics(instanceId, success, responseTime) {
    if (!this.metrics.has(instanceId)) {
      this.metrics.set(instanceId, {
        requests: 0,
        errors: 0,
        responseTimes: [],
        errorRate: 0,
        avgResponseTime: 0
      });
    }
    
    const metrics = this.metrics.get(instanceId);
    metrics.requests++;
    
    if (!success) {
      metrics.errors++;
    }
    
    metrics.responseTimes.push(responseTime);
    if (metrics.responseTimes.length > 100) {
      metrics.responseTimes.shift();
    }
    
    // Calculate derived metrics
    metrics.errorRate = metrics.errors / metrics.requests;
    metrics.avgResponseTime = metrics.responseTimes.reduce((a, b) => a + b, 0) / metrics.responseTimes.length;
    
    // Update circuit breaker
    this.updateCircuitBreaker(instanceId, success);
  }
  
  updateCircuitBreaker(instanceId, success) {
    if (!this.circuitBreakers.has(instanceId)) {
      this.circuitBreakers.set(instanceId, {
        state: 'CLOSED',
        failures: 0,
        lastFailure: null,
        halfOpenAfter: null
      });
    }
    
    const breaker = this.circuitBreakers.get(instanceId);
    
    switch (breaker.state) {
      case 'CLOSED':
        if (!success) {
          breaker.failures++;
          if (breaker.failures >= 5) { // Threshold
            breaker.state = 'OPEN';
            breaker.openTime = Date.now();
            breaker.halfOpenAfter = Date.now() + 30000; // 30 seconds
            console.log(`Circuit breaker OPEN for ${instanceId}`);
          }
        } else {
          breaker.failures = Math.max(0, breaker.failures - 1);
        }
        break;
        
      case 'OPEN':
        if (Date.now() >= breaker.halfOpenAfter) {
          breaker.state = 'HALF_OPEN';
          breaker.testRequest = false;
          console.log(`Circuit breaker HALF_OPEN for ${instanceId}`);
        }
        break;
        
      case 'HALF_OPEN':
        if (success) {
          breaker.state = 'CLOSED';
          breaker.failures = 0;
          console.log(`Circuit breaker CLOSED for ${instanceId}`);
        } else {
          breaker.state = 'OPEN';
          breaker.openTime = Date.now();
          breaker.halfOpenAfter = Date.now() + 60000; // Longer backoff
          console.log(`Circuit breaker re-OPEN for ${instanceId}`);
        }
        break;
    }
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Compare layer 4 (TCP) and layer 7 (HTTP) load balancing. When would you choose one over the other?"
2. "How does sticky session (session affinity) work in load balancing and what are its trade-offs?"
3. "Explain the circuit breaker pattern in the context of load balancing. How does it prevent cascading failures?"

**Scenario-Based Questions:**
1. "Your load balancer needs to handle a sudden 10x traffic spike. What strategies would you implement for autoscaling?"
2. "Users report that after adding a new server to the pool, some requests fail with 'invalid session' errors. How would you debug this?"
3. "You notice that one server in your pool is consistently slower than others. How would your load balancer detect and handle this?"

**Real-World Challenge:**
> "Design a global load balancing solution for a multi-region e-commerce platform that: 1) Routes users to the nearest data center, 2) Handles failover between regions during outages, 3) Maintains user sessions during regional failover, 4) Implements canary deployments for new features, 5) Provides real-time metrics on traffic distribution and server health."

---

## 5. Child Processes <a name="child-processes"></a>

### Overview
Child processes allow Node.js to execute system commands, run other programs, and perform CPU-intensive tasks in separate processes.

### Comprehensive Implementation Guide

```javascript
const { 
  spawn, 
  exec, 
  execFile, 
  fork,
  execSync,
  spawnSync
} = require('child_process');
const { promisify } = require('util');
const path = require('path');

// Promisify for async/await
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

class ChildProcessMasterclass {
  // 1. Spawn - Streaming I/O, best for large outputs
  static async useSpawn() {
    console.log('=== Using spawn() ===');
    
    // Basic spawn
    const ls = spawn('ls', ['-la', '/usr']);
    
    // Stream stdout
    ls.stdout.on('data', (data) => {
      console.log(`stdout: ${data.toString().slice(0, 100)}...`);
    });
    
    // Stream stderr
    ls.stderr.on('data', (data) => {
      console.error(`stderr: ${data}`);
    });
    
    // Handle process events
    ls.on('close', (code) => {
      console.log(`Process exited with code ${code}`);
    });
    
    ls.on('error', (err) => {
      console.error('Failed to start process:', err);
    });
    
    // Send input to process
    // ls.stdin.write('some input\n');
    // ls.stdin.end();
    
    // Kill process after timeout
    setTimeout(() => {
      if (!ls.killed) {
        console.log('Killing process...');
        ls.kill('SIGTERM');
      }
    }, 5000);
  }

  // 2. Exec - Simple commands, buffers output
  static async useExec() {
    console.log('\n=== Using exec() ===');
    
    try {
      // Basic exec
      const { stdout, stderr } = await execAsync('find /usr -name "*.js" | head -20');
      
      if (stderr) {
        console.error('stderr:', stderr);
      }
      
      console.log('Found JS files:', stdout.split('\n').slice(0, 5));
      
      // With options
      const options = {
        cwd: '/tmp', // Working directory
        env: { ...process.env, CUSTOM_ENV: 'value' },
        timeout: 5000, // Kill after 5 seconds
        maxBuffer: 1024 * 1024, // 1MB output limit
        encoding: 'utf8',
        shell: '/bin/bash' // Custom shell
      };
      
      const { stdout: dirContents } = await execAsync('ls -la', options);
      console.log('Directory contents:', dirContents.split('\n').length, 'lines');
      
    } catch (error) {
      console.error('exec error:', error.message);
      console.error('exit code:', error.code);
      console.error('signal:', error.signal);
    }
  }

  // 3. ExecFile - More secure than exec, no shell
  static async useExecFile() {
    console.log('\n=== Using execFile() ===');
    
    try {
      // Execute a binary file
      const { stdout } = await execFileAsync('node', ['--version']);
      console.log('Node version:', stdout.trim());
      
      // With arguments and options
      const scriptPath = path.join(__dirname, 'worker.js');
      const { stdout: result } = await execFileAsync('node', [scriptPath, '--task', 'process'], {
        timeout: 10000,
        windowsHide: true // Hide subprocess window on Windows
      });
      
      console.log('Worker output:', result);
      
    } catch (error) {
      console.error('execFile error:', error);
    }
  }

  // 4. Fork - Specialized spawn for Node.js modules
  static async useFork() {
    console.log('\n=== Using fork() ===');
    
    // Fork a Node.js module
    const worker = fork(path.join(__dirname, 'compute-worker.js'), 
      ['--data', '1000000'], // Arguments
      {
        // Fork options
        cwd: process.cwd(),
        env: { ...process.env, NODE_ENV: 'production' },
        execPath: process.execPath, // Node.js binary path
        execArgv: ['--max-old-space-size=4096'], // Node.js flags
        silent: false, // Pipe stdio to parent
        stdio: ['pipe', 'pipe', 'pipe', 'ipc'] // IPC channel
      }
    );
    
    // Send message to child
    worker.send({ 
      task: 'calculate',
      data: { numbers: [1, 2, 3, 4, 5] }
    });
    
    // Receive messages from child
    worker.on('message', (message) => {
      console.log('Message from child:', message);
      
      if (message.type === 'result') {
        console.log('Calculation result:', message.result);
      }
      
      if (message.type === 'progress') {
        console.log(`Progress: ${message.percent}%`);
      }
    });
    
    // Handle child process events
    worker.on('close', (code, signal) => {
      console.log(`Child process closed with code ${code}, signal ${signal}`);
    });
    
    worker.on('error', (err) => {
      console.error('Child process error:', err);
    });
    
    worker.on('exit', (code, signal) => {
      console.log(`Child process exited with code ${code}, signal ${signal}`);
    });
    
    // Disconnect IPC channel
    setTimeout(() => {
      if (worker.connected) {
        worker.disconnect();
        console.log('Disconnected from child process');
      }
    }, 10000);
  }

  // 5. SpawnSync/ExecSync - Synchronous execution
  static useSyncMethods() {
    console.log('\n=== Using synchronous methods ===');
    
    try {
      // spawnSync - returns buffers
      const result = spawnSync('node', ['-e', 'console.log(process.pid)'], {
        encoding: 'utf8',
        timeout: 5000
      });
      
      console.log('spawnSync result:', {
        pid: result.pid,
        stdout: result.stdout,
        stderr: result.stderr,
        status: result.status,
        signal: result.signal,
        error: result.error
      });
      
      // execSync - returns string/buffer
      const output = execSync('echo "Hello from sync exec"', {
        encoding: 'utf8',
        cwd: '/tmp'
      });
      
      console.log('execSync output:', output);
      
    } catch (error) {
      console.error('Sync execution error:', error.message);
      console.error('Status:', error.status);
      console.error('Signal:', error.signal);
    }
  }

  // 6. Advanced: Process Pool Manager
  static createProcessPool(config = {}) {
    return new class ProcessPool {
      constructor() {
        this.maxProcesses = config.maxProcesses || 4;
        this.idleTimeout = config.idleTimeout || 30000;
        this.processes = []; // { process, busy, lastUsed, id }
        this.taskQueue = [];
        this.nextId = 1;
        
        // Cleanup idle processes
        setInterval(() => this.cleanupIdleProcesses(), 10000);
      }
      
      async execute(task, args = [], options = {}) {
        // Find or create a process
        let worker = this.getAvailableProcess();
        
        if (!worker) {
          if (this.processes.length < this.maxProcesses) {
            worker = await this.createProcess();
          } else {
            // Wait for a process to become available
            return new Promise((resolve, reject) => {
              this.taskQueue.push({ task, args, options, resolve, reject });
            });
          }
        }
      
        // Mark as busy
        worker.busy = true;
        worker.lastUsed = Date.now();
        
        try {
          // Execute task
          const result = await this.runTaskInProcess(worker.process, task, args, options);
          
          // Mark as available
          worker.busy = false;
          
          // Process queued tasks
          this.processQueue();
          
          return result;
        } catch (error) {
          // Remove failed process
          this.removeProcess(worker.id);
          
          // Retry with new process
          return this.execute(task, args, options);
        }
      }
      
      getAvailableProcess() {
        return this.processes.find(p => !p.busy);
      }
      
      async createProcess() {
        const id = this.nextId++;
        const worker = fork(path.join(__dirname, 'pool-worker.js'), [], {
          silent: true,
          stdio: ['pipe', 'pipe', 'pipe', 'ipc']
        });
        
        const processInfo = {
          id,
          process: worker,
          busy: false,
          created: Date.now(),
          lastUsed: Date.now()
        };
        
        this.processes.push(processInfo);
        
        // Handle process events
        worker.on('exit', (code, signal) => {
          console.log(`Worker ${id} exited with code ${code}`);
          this.removeProcess(id);
        });
        
        worker.on('error', (err) => {
          console.error(`Worker ${id} error:`, err);
          this.removeProcess(id);
        });
        
        // Wait for worker to be ready
        await new Promise((resolve) => {
          worker.on('message', (msg) => {
            if (msg.type === 'ready') {
              resolve();
            }
          });
        });
        
        return processInfo;
      }
      
      async runTaskInProcess(worker, task, args, options) {
        return new Promise((resolve, reject) => {
          const taskId = Math.random().toString(36).substr(2, 9);
          const timeout = options.timeout || 30000;
          
          // Set response timeout
          const timeoutId = setTimeout(() => {
            reject(new Error(`Task timeout after ${timeout}ms`));
            worker.kill('SIGTERM');
          }, timeout);
          
          // Handle response
          const messageHandler = (msg) => {
            if (msg.taskId === taskId) {
              clearTimeout(timeoutId);
              worker.removeListener('message', messageHandler);
              
              if (msg.type === 'success') {
                resolve(msg.result);
              } else {
                reject(new Error(msg.error));
              }
            }
          };
          
          worker.on('message', messageHandler);
          
          // Send task to worker
          worker.send({
            type: 'execute',
            taskId,
            task,
            args,
            options
          });
        });
      }
      
      processQueue() {
        if (this.taskQueue.length === 0) return;
        
        const worker = this.getAvailableProcess();
        if (!worker) return;
        
        const task = this.taskQueue.shift();
        
        this.execute(task.task, task.args, task.options)
          .then(task.resolve)
          .catch(task.reject);
      }
      
      removeProcess(id) {
        const index = this.processes.findIndex(p => p.id === id);
        if (index >= 0) {
          const processInfo = this.processes[index];
          
          if (!processInfo.process.killed) {
            processInfo.process.kill('SIGTERM');
          }
          
          this.processes.splice(index, 1);
          console.log(`Removed worker ${id}`);
        }
      }
      
      cleanupIdleProcesses() {
        const now = Date.now();
        const minProcesses = Math.min(2, this.maxProcesses);
        
        if (this.processes.length <= minProcesses) return;
        
        for (let i = this.processes.length - 1; i >= 0; i--) {
          const processInfo = this.processes[i];
          
          if (!processInfo.busy && 
              now - processInfo.lastUsed > this.idleTimeout &&
              this.processes.length > minProcesses) {
            
            this.removeProcess(processInfo.id);
          }
        }
      }
      
      async shutdown() {
        // Process remaining tasks
        this.taskQueue.forEach(task => {
          task.reject(new Error('Process pool shutting down'));
        });
        this.taskQueue = [];
        
        // Kill all processes
        await Promise.all(this.processes.map(processInfo => {
          return new Promise(resolve => {
            if (processInfo.process.killed) {
              resolve();
            } else {
              processInfo.process.on('exit', resolve);
              processInfo.process.kill('SIGTERM');
            }
          });
        }));
        
        this.processes = [];
        console.log('Process pool shut down');
      }
    };
  }

  // 7. Real-world Example: Video Processing Pipeline
  static createVideoProcessor() {
    return new class VideoProcessor {
      constructor() {
        this.ffmpegPath = 'ffmpeg';
        this.concurrency = 2;
        this.processingQueue = [];
        this.activeProcesses = new Map();
      }
      
      async processVideo(inputPath, outputPath, options = {}) {
        return new Promise((resolve, reject) => {
          this.processingQueue.push({
            inputPath,
            outputPath,
            options,
            resolve,
            reject
          });
          
          this.processNext();
        });
      }
      
      processNext() {
        if (this.processingQueue.length === 0) return;
        if (this.activeProcesses.size >= this.concurrency) return;
        
        const task = this.processingQueue.shift();
        this.executeFfmpeg(task);
      }
      
      executeFfmpeg(task) {
        const { inputPath, outputPath, options, resolve, reject } = task;
        
        // Build ffmpeg command
        const args = [
          '-i', inputPath,
          '-c:v', options.codec || 'libx264',
          '-preset', options.preset || 'medium',
          '-crf', options.crf || '23',
          '-c:a', 'aac',
          '-b:a', '128k',
          outputPath,
          '-y' // Overwrite output
        ];
        
        const ffmpeg = spawn(this.ffmpegPath, args);
        const processId = ffmpeg.pid;
        
        this.activeProcesses.set(processId, { ffmpeg, task });
        
        let stdout = '';
        let stderr = '';
        
        ffmpeg.stdout.on('data', (data) => {
          stdout += data.toString();
        });
        
        ffmpeg.stderr.on('data', (data) => {
          stderr += data.toString();
          
          // Parse progress from ffmpeg output
          const progress = this.parseFfmpegProgress(data.toString());
          if (progress !== null) {
            console.log(`Progress: ${progress}%`);
          }
        });
        
        ffmpeg.on('close', (code) => {
          this.activeProcesses.delete(processId);
          
          if (code === 0) {
            console.log(`Video processing complete: ${outputPath}`);
            resolve({ outputPath, stdout, stderr });
          } else {
            console.error(`FFmpeg failed with code ${code}`);
            reject(new Error(`FFmpeg failed: ${stderr}`));
          }
          
          this.processNext();
        });
        
        ffmpeg.on('error', (err) => {
          this.activeProcesses.delete(processId);
          reject(err);
          this.processNext();
        });
        
        // Optional: Send input to ffmpeg (e.g., for streaming)
        // ffmpeg.stdin.write(someData);
        // ffmpeg.stdin.end();
      }
      
      parseFfmpegProgress(output) {
        // Parse ffmpeg progress from stderr
        const match = output.match(/time=(\d+:\d+:\d+\.\d+)/);
        if (match) {
          // Convert to percentage (simplified)
          return 50; // Example
        }
        return null;
      }
      
      async shutdown() {
        // Kill all active processes
        for (const [pid, { ffmpeg }] of this.activeProcesses) {
          ffmpeg.kill('SIGTERM');
        }
        
        // Reject all queued tasks
        this.processingQueue.forEach(task => {
          task.reject(new Error('Video processor shutting down'));
        });
        
        this.processingQueue = [];
        this.activeProcesses.clear();
      }
    };
  }

  // 8. Security Considerations
  static securityBestPractices() {
    return {
      // 1. Command Injection Prevention
      safeCommandExecution: (userInput) => {
        // UNSAFE - Command injection vulnerability
        // exec(`ls ${userInput}`);
        
        // SAFE - Use spawn with array arguments
        const args = ['-la', userInput].filter(arg => arg !== '');
        const ls = spawn('ls', args, {
          // Additional security options
          stdio: ['ignore', 'pipe', 'pipe'] // Don't pass stdin
        });
        
        // OR use execFile for binaries
        // execFile('ls', args);
      },
      
      // 2. Input Validation
      validateInput: (input) => {
        // Whitelist allowed characters
        const allowedPattern = /^[a-zA-Z0-9_\-\.\/]+$/;
        if (!allowedPattern.test(input)) {
          throw new Error('Invalid input');
        }
        
        // Check for path traversal
        if (input.includes('..') || input.includes('/') || input.includes('\\')) {
          throw new Error('Path traversal attempt');
        }
        
        return input;
      },
      
      // 3. Resource Limits
      setResourceLimits: () => {
        const options = {
          timeout: 10000, // 10 second timeout
          maxBuffer: 1024 * 1024, // 1MB output limit
          killSignal: 'SIGTERM',
          windowsHide: true
        };
        
        // For spawn, use separate resource limiting
        const child = spawn('command', [], {
          detached: false, // Don't allow child to outlive parent
          stdio: 'pipe'
        });
        
        // Set CPU/memory limits (platform dependent)
        // On Linux, use prlimit or cgroups
      },
      
      // 4. Environment Sanitization
      sanitizeEnvironment: () => {
        const safeEnv = {
          ...process.env,
          // Remove sensitive environment variables
          AWS_ACCESS_KEY_ID: undefined,
          AWS_SECRET_ACCESS_KEY: undefined,
          DATABASE_PASSWORD: undefined,
          // Set safe defaults
          PATH: '/usr/local/bin:/usr/bin:/bin',
          LD_LIBRARY_PATH: undefined
        };
        
        return safeEnv;
      },
      
      // 5. Signal Handling
      handleSignals: (child) => {
        // Forward termination signals
        ['SIGTERM', 'SIGINT', 'SIGHUP'].forEach(signal => {
          process.on(signal, () => {
            if (!child.killed) {
              child.kill(signal);
            }
          });
        });
        
        // Handle child signals
        child.on('exit', (code, signal) => {
          console.log(`Child exited with code ${code}, signal ${signal}`);
        });
      }
    };
  }
}

// Example worker script for fork()
const computeWorkerScript = `
process.on('message', (message) => {
  if (message.task === 'calculate') {
    // CPU-intensive calculation
    let sum = 0;
    for (let i = 0; i < 1000000; i++) {
      sum += Math.sqrt(i);
    }
    
    // Send progress updates
    process.send({ type: 'progress', percent: 50 });
    
    // Send result
    process.send({ 
      type: 'result', 
      result: { sum, numbers: message.data.numbers }
    });
  }
});

// Signal readiness
process.send({ type: 'ready' });
`;

// Pool worker script
const poolWorkerScript = `
process.on('message', async (message) => {
  if (message.type === 'execute') {
    try {
      const result = await executeTask(message.task, message.args, message.options);
      
      process.send({
        type: 'success',
        taskId: message.taskId,
        result
      });
    } catch (error) {
      process.send({
        type: 'error',
        taskId: message.taskId,
        error: error.message
      });
    }
  }
});

async function executeTask(task, args, options) {
  // Task execution logic
  if (task === 'fibonacci') {
    return fibonacci(args[0]);
  }
  
  throw new Error(\`Unknown task: \${task}\`);
}

function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

// Signal readiness
process.send({ type: 'ready' });
`;
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Compare `spawn`, `exec`, `execFile`, and `fork`. When would you choose each one?"
2. "How does IPC (Inter-Process Communication) work with `fork()`? What are the limitations?"
3. "What are the security implications of using `exec()` with user input and how would you mitigate them?"

**Scenario-Based Questions:**
1. "You need to process 1000 images using ImageMagick. How would you implement a process pool to handle this efficiently without overwhelming the system?"
2. "A child process hangs indefinitely. How would you implement timeout handling and cleanup?"
3. "You need to stream large amounts of data between parent and child processes. How would you implement this without loading everything into memory?"

**Real-World Challenge:**
> "Design a document conversion service that: 1) Accepts various input formats (PDF, DOCX, etc.), 2) Uses different CLI tools for conversion (libreoffice, imagemagick, etc.), 3) Handles concurrent conversions with resource limits, 4) Provides progress updates during long-running conversions, 5) Implements proper cleanup of temporary files and processes."

---

## 6. Worker Threads <a name="worker-threads"></a>

### Overview
Worker Threads allow Node.js to perform CPU-intensive JavaScript operations on multiple threads, sharing memory through ArrayBuffer and SharedArrayBuffer.

### Comprehensive Implementation Guide

```javascript
const { 
  Worker, 
  isMainThread, 
  parentPort,
  workerData,
  MessagePort,
  MessageChannel,
  threadId,
  SHARE_ENV
} = require('worker_threads');
const { cpus } = require('os');
const path = require('path');

class WorkerThreadsMasterclass {
  // 1. Basic Worker Thread
  static async basicWorker() {
    if (isMainThread) {
      console.log('Main thread ID:', threadId);
      
      // Create a worker
      const worker = new Worker(__filename, {
        workerData: {
          message: 'Hello from main thread!',
          numbers: [1, 2, 3, 4, 5]
        },
        // Resource limits
        resourceLimits: {
          maxOldGenerationSizeMb: 512,
          maxYoungGenerationSizeMb: 256,
          codeRangeSizeMb: 128,
          stackSizeMb: 4
        }
      });
      
      // Handle messages from worker
      worker.on('message', (message) => {
        console.log('Message from worker:', message);
        
        if (message.type === 'result') {
          console.log('Sum:', message.result);
        }
      });
      
      // Handle worker events
      worker.on('error', (error) => {
        console.error('Worker error:', error);
      });
      
      worker.on('exit', (code) => {
        console.log(`Worker exited with code ${code}`);
      });
      
      worker.on('online', () => {
        console.log('Worker is online');
      });
      
      // Send message to worker
      worker.postMessage({ 
        type: 'calculate',
        data: { operation: 'sum' }
      });
      
      // Terminate after 5 seconds
      setTimeout(() => {
        worker.terminate();
        console.log('Worker terminated');
      }, 5000);
      
    } else {
      // Worker thread code
      console.log('Worker thread ID:', threadId);
      console.log('Worker data:', workerData);
      
      // Listen for messages from main thread
      parentPort.on('message', (message) => {
        if (message.type === 'calculate') {
          // CPU-intensive calculation
          const sum = workerData.numbers.reduce((a, b) => a + b, 0);
          
          // Send result back
          parentPort.postMessage({
            type: 'result',
            result: sum,
            threadId: threadId
          });
        }
      });
      
      // Send initialization message
      parentPort.postMessage({
        type: 'ready',
        threadId: threadId
      });
    }
  }

  // 2. Shared Memory with SharedArrayBuffer
  static async sharedMemoryExample() {
    if (isMainThread) {
      // Create shared memory
      const sharedBuffer = new SharedArrayBuffer(1024 * 1024); // 1MB
      const sharedArray = new Uint32Array(sharedBuffer);
      
      // Initialize shared data
      sharedArray[0] = 0; // Counter
      sharedArray[1] = 0; // Flag
      
      // Create workers with shared memory
      const worker1 = new Worker(__filename, {
        workerData: { 
          sharedBuffer,
          workerId: 1,
          maxCount: 1000000
        }
      });
      
      const worker2 = new Worker(__filename, {
        workerData: { 
          sharedBuffer,
          workerId: 2,
          maxCount: 1000000
        }
      });
      
      let completedWorkers = 0;
      
      const handleWorkerExit = () => {
        completedWorkers++;
        if (completedWorkers === 2) {
          console.log('Final counter value:', sharedArray[0]);
          console.log('Expected:', 2000000);
          console.log('Race conditions:', 2000000 - sharedArray[0]);
        }
      };
      
      worker1.on('exit', handleWorkerExit);
      worker2.on('exit', handleWorkerExit);
      
      worker1.on('error', console.error);
      worker2.on('error', console.error);
      
      // Start workers
      worker1.postMessage('start');
      worker2.postMessage('start');
      
    } else {
      // Worker thread - increment counter
      const sharedArray = new Uint32Array(workerData.sharedBuffer);
      const workerId = workerData.workerId;
      const maxCount = workerData.maxCount;
      
      parentPort.on('message', (message) => {
        if (message === 'start') {
          console.log(`Worker ${workerId} starting...`);
          
          for (let i = 0; i < maxCount; i++) {
            // UNSAFE: Race condition
            // sharedArray[0] = sharedArray[0] + 1;
            
            // SAFE: Atomic operation
            Atomics.add(sharedArray, 0, 1);
          }
          
          console.log(`Worker ${workerId} completed`);
          process.exit(0);
        }
      });
    }
  }

  // 3. Thread Pool Implementation
  static createThreadPool(poolSize = cpus().length) {
    return new class ThreadPool {
      constructor() {
        this.poolSize = poolSize;
        this.workers = [];
        this.taskQueue = [];
        this.workerStates = new Map(); // worker -> 'idle' | 'busy'
        this.nextWorkerId = 0;
        
        this.initializeWorkers();
      }
      
      initializeWorkers() {
        for (let i = 0; i < this.poolSize; i++) {
          this.createWorker();
        }
      }
      
      createWorker() {
        const workerId = this.nextWorkerId++;
        const worker = new Worker(path.join(__dirname, 'thread-worker.js'), {
          workerData: { workerId },
          resourceLimits: {
            maxOldGenerationSizeMb: 256,
            maxYoungGenerationSizeMb: 128
          }
        });
        
        this.workers.push(worker);
        this.workerStates.set(worker, 'idle');
        
        worker.on('message', (message) => {
          if (message.type === 'ready') {
            console.log(`Worker ${workerId} ready`);
          } else if (message.type === 'result') {
            // Get task from worker
            const task = worker.currentTask;
            
            if (task) {
              // Resolve promise
              task.resolve(message.result);
              
              // Mark worker as idle
              this.workerStates.set(worker, 'idle');
              worker.currentTask = null;
              
              // Process next task in queue
              this.processQueue();
            }
          } else if (message.type === 'error') {
            const task = worker.currentTask;
            
            if (task) {
              task.reject(new Error(message.error));
              
              // Mark worker as idle (or restart if needed)
              this.workerStates.set(worker, 'idle');
              worker.currentTask = null;
              
              this.processQueue();
            }
          }
        });
        
        worker.on('error', (error) => {
          console.error(`Worker ${workerId} error:`, error);
          
          // Remove and replace failed worker
          this.removeWorker(worker);
          this.createWorker();
        });
        
        worker.on('exit', (code) => {
          console.log(`Worker ${workerId} exited with code ${code}`);
          this.removeWorker(worker);
        });
      }
      
      removeWorker(worker) {
        const index = this.workers.indexOf(worker);
        if (index >= 0) {
          this.workers.splice(index, 1);
          this.workerStates.delete(worker);
          
          // If worker had a task, reject it
          if (worker.currentTask) {
            worker.currentTask.reject(new Error('Worker terminated'));
          }
        }
      }
      
      async execute(task, data) {
        return new Promise((resolve, reject) => {
          this.taskQueue.push({
            task,
            data,
            resolve,
            reject,
            timestamp: Date.now()
          });
          
          this.processQueue();
        });
      }
      
      processQueue() {
        if (this.taskQueue.length === 0) return;
        
        // Find idle worker
        const idleWorker = this.workers.find(w => 
          this.workerStates.get(w) === 'idle'
        );
        
        if (!idleWorker) return;
        
        const nextTask = this.taskQueue.shift();
        
        // Mark worker as busy
        this.workerStates.set(idleWorker, 'busy');
        idleWorker.currentTask = nextTask;
        
        // Send task to worker
        idleWorker.postMessage({
          type: 'execute',
          task: nextTask.task,
          data: nextTask.data,
          taskId: Math.random().toString(36).substr(2, 9)
        });
        
        // Check for timeout
        const timeout = 30000; // 30 seconds
        setTimeout(() => {
          if (idleWorker.currentTask === nextTask) {
            console.log('Task timeout, terminating worker');
            idleWorker.terminate();
            nextTask.reject(new Error('Task timeout'));
          }
        }, timeout);
      }
      
      getStats() {
        const idle = this.workers.filter(w => 
          this.workerStates.get(w) === 'idle'
        ).length;
        
        const busy = this.workers.length - idle;
        
        return {
          totalWorkers: this.workers.length,
          idleWorkers: idle,
          busyWorkers: busy,
          queuedTasks: this.taskQueue.length,
          queueWaitTime: this.taskQueue.length > 0 ? 
            Date.now() - this.taskQueue[0].timestamp : 0
        };
      }
      
      async shutdown() {
        // Reject all queued tasks
        this.taskQueue.forEach(task => {
          task.reject(new Error('Thread pool shutting down'));
        });
        this.taskQueue = [];
        
        // Terminate all workers
        await Promise.all(this.workers.map(worker => {
          return new Promise(resolve => {
            worker.once('exit', resolve);
            worker.terminate();
          });
        }));
        
        this.workers = [];
        this.workerStates.clear();
        
        console.log('Thread pool shut down');
      }
    };
  }

  // 4. Message Channels for Worker Communication
  static async messageChannelExample() {
    if (isMainThread) {
      // Create message channel
      const { port1, port2 } = new MessageChannel();
      
      // Create workers
      const worker1 = new Worker(__filename, {
        workerData: { port: port1 },
        transferList: [port1] // Transfer ownership
      });
      
      const worker2 = new Worker(__filename, {
        workerData: { port: port2 },
        transferList: [port2]
      });
      
      // Listen for messages from worker1
      worker1.on('message', (message) => {
        console.log('Main received from worker1:', message);
      });
      
      // Send message to worker1 to start communication
      worker1.postMessage({ 
        type: 'start', 
        target: 'worker2' 
      });
      
    } else {
      // Worker thread
      const port = workerData.port;
      
      parentPort.on('message', (message) => {
        if (message.type === 'start') {
          console.log(`Worker ${threadId} starting communication`);
          
          // Set up port communication
          port.on('message', (msg) => {
            console.log(`Worker ${threadId} received:`, msg);
            
            // Echo back with modification
            port.postMessage({
              ...msg,
              echoedBy: threadId,
              timestamp: Date.now()
            });
          });
          
          // Start the conversation
          if (message.target === 'worker2') {
            port.postMessage({
              from: threadId,
              message: 'Hello from worker 1!',
              sequence: 1
            });
          }
          
          port.postMessage({ type: 'ready' });
        }
      });
    }
  }

  // 5. CPU-intensive Task: Matrix Multiplication
  static async matrixMultiplication() {
    if (isMainThread) {
      // Generate large matrices
      const size = 500;
      const matrixA = this.generateMatrix(size, size);
      const matrixB = this.generateMatrix(size, size);
      
      console.log(`Multiplying ${size}x${size} matrices...`);
      
      // Single-threaded (for comparison)
      console.time('single-threaded');
      const singleResult = this.multiplyMatricesSingle(matrixA, matrixB);
      console.timeEnd('single-threaded');
      
      // Multi-threaded
      console.time('multi-threaded');
      const multiResult = await this.multiplyMatricesParallel(matrixA, matrixB, 4);
      console.timeEnd('multi-threaded');
      
      // Verify results match
      const match = this.matricesEqual(singleResult, multiResult);
      console.log('Results match:', match);
      
    } else {
      // Worker thread for matrix multiplication
      parentPort.on('message', (message) => {
        if (message.type === 'multiply') {
          const { matrixA, matrixB, startRow, endRow } = message;
          
          const result = this.multiplyMatrixSlice(matrixA, matrixB, startRow, endRow);
          
          parentPort.postMessage({
            type: 'result',
            result,
            startRow,
            endRow
          });
        }
      });
    }
  }
  
  static generateMatrix(rows, cols) {
    const matrix = new Array(rows);
    for (let i = 0; i < rows; i++) {
      matrix[i] = new Array(cols);
      for (let j = 0; j < cols; j++) {
        matrix[i][j] = Math.random();
      }
    }
    return matrix;
  }
  
  static multiplyMatricesSingle(A, B) {
    const rowsA = A.length;
    const colsA = A[0].length;
    const colsB = B[0].length;
    
    const result = new Array(rowsA);
    for (let i = 0; i < rowsA; i++) {
      result[i] = new Array(colsB);
      for (let j = 0; j < colsB; j++) {
        let sum = 0;
        for (let k = 0; k < colsA; k++) {
          sum += A[i][k] * B[k][j];
        }
        result[i][j] = sum;
      }
    }
    
    return result;
  }
  
  static async multiplyMatricesParallel(A, B, threadCount) {
    const rowsA = A.length;
    const rowsPerThread = Math.ceil(rowsA / threadCount);
    
    const workers = [];
    const results = new Array(rowsA);
    
    // Create workers
    for (let i = 0; i < threadCount; i++) {
      const startRow = i * rowsPerThread;
      const endRow = Math.min(startRow + rowsPerThread, rowsA);
      
      if (startRow >= rowsA) break;
      
      const worker = new Worker(__filename, {
        workerData: { workerId: i }
      });
      
      workers.push({
        worker,
        startRow,
        endRow,
        promise: new Promise((resolve) => {
          worker.on('message', (message) => {
            if (message.type === 'result') {
              // Store result slice
              for (let r = message.startRow; r < message.endRow; r++) {
                results[r] = message.result[r - message.startRow];
              }
              resolve();
            }
          });
        })
      });
      
      // Send task to worker
      worker.postMessage({
        type: 'multiply',
        matrixA: A,
        matrixB: B,
        startRow,
        endRow
      });
    }
    
    // Wait for all workers to complete
    await Promise.all(workers.map(w => w.promise));
    
    // Terminate workers
    workers.forEach(w => w.worker.terminate());
    
    return results;
  }
  
  static multiplyMatrixSlice(A, B, startRow, endRow) {
    const colsA = A[0].length;
    const colsB = B[0].length;
    
    const resultSlice = new Array(endRow - startRow);
    
    for (let i = startRow; i < endRow; i++) {
      resultSlice[i - startRow] = new Array(colsB);
      for (let j = 0; j < colsB; j++) {
        let sum = 0;
        for (let k = 0; k < colsA; k++) {
          sum += A[i][k] * B[k][j];
        }
        resultSlice[i - startRow][j] = sum;
      }
    }
    
    return resultSlice;
  }
  
  static matricesEqual(A, B) {
    if (A.length !== B.length) return false;
    
    for (let i = 0; i < A.length; i++) {
      if (A[i].length !== B[i].length) return false;
      
      for (let j = 0; j < A[i].length; j++) {
        if (Math.abs(A[i][j] - B[i][j]) > 0.0001) {
          return false;
        }
      }
    }
    
    return true;
  }

  // 6. Real-world Example: Image Processing
  static createImageProcessor() {
    const { createCanvas, loadImage } = require('canvas');
    
    return new class ImageProcessor {
      constructor(threadCount = 4) {
        this.threadCount = threadCount;
        this.threadPool = this.createThreadPool();
      }
      
      createThreadPool() {
        const workers = [];
        
        for (let i = 0; i < this.threadCount; i++) {
          const worker = new Worker(`
            const { parentPort, workerData } = require('worker_threads');
            const { createCanvas } = require('canvas');
            
            parentPort.on('message', async (message) => {
              if (message.type === 'process') {
                const { imageData, width, height, operations } = message;
                
                // Convert buffer to canvas
                const canvas = createCanvas(width, height);
                const ctx = canvas.getContext('2d');
                const imageDataObj = new ImageData(
                  new Uint8ClampedArray(imageData),
                  width,
                  height
                );
                ctx.putImageData(imageDataObj, 0, 0);
                
                // Apply operations
                const result = await this.applyOperations(canvas, operations);
                
                // Convert back to buffer
                const resultCtx = result.getContext('2d');
                const resultData = resultCtx.getImageData(0, 0, width, height);
                
                parentPort.postMessage({
                  type: 'result',
                  imageData: resultData.data.buffer,
                  taskId: message.taskId
                }, [resultData.data.buffer]); // Transfer buffer
              }
            });
            
            async function applyOperations(canvas, operations) {
              // Apply image processing operations
              const ctx = canvas.getContext('2d');
              
              for (const op of operations) {
                switch (op.type) {
                  case 'grayscale':
                    this.applyGrayscale(ctx, canvas.width, canvas.height);
                    break;
                  case 'blur':
                    this.applyBlur(ctx, canvas.width, canvas.height, op.radius);
                    break;
                  case 'resize':
                    canvas = this.resizeCanvas(canvas, op.width, op.height);
                    break;
                }
              }
              
              return canvas;
            }
            
            function applyGrayscale(ctx, width, height) {
              const imageData = ctx.getImageData(0, 0, width, height);
              const data = imageData.data;
              
              for (let i = 0; i < data.length; i += 4) {
                const avg = (data[i] + data[i + 1] + data[i + 2]) / 3;
                data[i] = avg;     // R
                data[i + 1] = avg; // G
                data[i + 2] = avg; // B
              }
              
              ctx.putImageData(imageData, 0, 0);
            }
            
            // Signal readiness
            parentPort.postMessage({ type: 'ready' });
          `, {
            eval: true,
            workerData: { workerId: i }
          });
          
          workers.push(worker);
        }
        
        return workers;
      }
      
      async processImage(imagePath, operations) {
        // Load image
        const image = await loadImage(imagePath);
        const canvas = createCanvas(image.width, image.height);
        const ctx = canvas.getContext('2d');
        ctx.drawImage(image, 0, 0);
        
        // Get image data
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        
        // Split image into tiles for parallel processing
        const tiles = this.splitIntoTiles(
          imageData.data,
          canvas.width,
          canvas.height,
          this.threadCount
        );
        
        // Process tiles in parallel
        const promises = tiles.map((tile, index) => {
          return new Promise((resolve, reject) => {
            const worker = this.threadPool[index % this.threadPool.length];
            
            worker.once('message', (message) => {
              if (message.type === 'result' && message.taskId === tile.taskId) {
                resolve({
                  data: new Uint8ClampedArray(message.imageData),
                  x: tile.x,
                  y: tile.y,
                  width: tile.width,
                  height: tile.height
                });
              }
            });
            
            worker.postMessage({
              type: 'process',
              imageData: tile.data.buffer,
              width: tile.width,
              height: tile.height,
              operations,
              taskId: tile.taskId
            }, [tile.data.buffer]);
          });
        });
        
        // Wait for all tiles
        const processedTiles = await Promise.all(promises);
        
        // Combine tiles
        const resultCanvas = createCanvas(canvas.width, canvas.height);
        const resultCtx = resultCanvas.getContext('2d');
        
        for (const tile of processedTiles) {
          const tileImageData = new ImageData(tile.data, tile.width, tile.height);
          resultCtx.putImageData(tileImageData, tile.x, tile.y);
        }
        
        return resultCanvas.toBuffer();
      }
      
      splitIntoTiles(imageData, width, height, tileCount) {
        const tiles = [];
        const tileSize = Math.ceil(height / tileCount);
        
        for (let i = 0; i < tileCount; i++) {
          const y = i * tileSize;
          const tileHeight = Math.min(tileSize, height - y);
          
          if (tileHeight <= 0) break;
          
          // Extract tile data from image
          const tileData = new Uint8ClampedArray(width * tileHeight * 4);
          
          for (let row = 0; row < tileHeight; row++) {
            const srcStart = ((y + row) * width) * 4;
            const destStart = row * width * 4;
            
            tileData.set(
              imageData.slice(srcStart, srcStart + width * 4),
              destStart
            );
          }
          
          tiles.push({
            data: tileData.buffer,
            x: 0,
            y,
            width,
            height: tileHeight,
            taskId: Math.random().toString(36).substr(2, 9)
          });
        }
        
        return tiles;
      }
    };
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between Worker Threads and child processes? When would you use each?"
2. "How does SharedArrayBuffer work and what are the security considerations when using it?"
3. "Explain the concept of 'transferable objects' in Worker Threads and how they improve performance."

**Scenario-Based Questions:**
1. "You need to process a large JSON file (10GB) in Node.js. How would you use Worker Threads to parse and process it efficiently?"
2. "Your application performs real-time physics simulations that are CPU-intensive. How would you implement this with Worker Threads while maintaining real-time responsiveness?"
3. "You notice that Worker Threads are causing memory leaks. What are common causes and how would you debug them?"

**Real-World Challenge:**
> "Design a real-time video processing system that: 1) Processes multiple video streams concurrently, 2) Applies different filters (blur, edge detection, color correction) using Worker Threads, 3) Shares intermediate frames between threads efficiently, 4) Handles dynamic addition/removal of video streams, 5) Provides real-time performance metrics for each thread."

---

## 7. Cluster Mode <a name="cluster-mode"></a>

### Overview
Cluster mode enables Node.js to create multiple process instances (workers) that share server ports, allowing better utilization of multi-core systems.

### Comprehensive Implementation Guide

```javascript
const cluster = require('cluster');
const http = require('http');
const os = require('os');
const process = require('process');

class ClusterMasterclass {
  // 1. Basic Cluster Setup
  static basicCluster() {
    if (cluster.isMaster) {
      console.log(`Master ${process.pid} is running`);
      
      // Get number of CPU cores
      const numCPUs = os.cpus().length;
      console.log(`Number of CPUs: ${numCPUs}`);
      
      // Fork workers
      for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
      }
      
      // Handle worker events
      cluster.on('fork', (worker) => {
        console.log(`Worker ${worker.process.pid} forked`);
      });
      
      cluster.on('online', (worker) => {
        console.log(`Worker ${worker.process.pid} is online`);
      });
      
      cluster.on('listening', (worker, address) => {
        console.log(`Worker ${worker.process.pid} is listening on ${address.address}:${address.port}`);
      });
      
      cluster.on('disconnect', (worker) => {
        console.log(`Worker ${worker.process.pid} disconnected`);
      });
      
      cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died with code ${code}, signal ${signal}`);
        
        // Restart worker
        console.log('Starting a new worker...');
        cluster.fork();
      });
      
      cluster.on('message', (worker, message, handle) => {
        console.log(`Message from worker ${worker.process.pid}:`, message);
        
        // Broadcast to all workers
        for (const id in cluster.workers) {
          cluster.workers[id].send(message);
        }
      });
      
      // Graceful shutdown
      process.on('SIGTERM', () => {
        console.log('Master received SIGTERM, shutting down...');
        
        for (const id in cluster.workers) {
          cluster.workers[id].kill('SIGTERM');
        }
        
        setTimeout(() => {
          console.log('Master exiting');
          process.exit(0);
        }, 5000);
      });
      
    } else {
      // Worker process
      console.log(`Worker ${process.pid} started`);
      
      // Create HTTP server
      const server = http.createServer((req, res) => {
        // Simulate CPU work
        let sum = 0;
        for (let i = 0; i < 1000000; i++) {
          sum += Math.sqrt(i);
        }
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          pid: process.pid,
          sum,
          message: 'Hello from worker!'
        }));
      });
      
      // Listen on port 3000
      server.listen(3000, () => {
        console.log(`Worker ${process.pid} listening on port 3000`);
      });
      
      // Handle messages from master
      process.on('message', (message) => {
        console.log(`Worker ${process.pid} received:`, message);
      });
      
      // Send heartbeat to master
      setInterval(() => {
        process.send({
          type: 'heartbeat',
          pid: process.pid,
          memory: process.memoryUsage(),
          uptime: process.uptime()
        });
      }, 10000);
      
      // Graceful shutdown
      process.on('SIGTERM', () => {
        console.log(`Worker ${process.pid} received SIGTERM`);
        
        server.close(() => {
          console.log(`Worker ${process.pid} server closed`);
          process.exit(0);
        });
        
        // Force exit after timeout
        setTimeout(() => {
          console.log(`Worker ${process.pid} forcing exit`);
          process.exit(1);
        }, 10000);
      });
    }
  }

  // 2. Advanced Cluster Manager
  static createAdvancedCluster(options = {}) {
    return new class AdvancedCluster {
      constructor() {
        this.options = {
          workers: options.workers || os.cpus().length,
          respawn: options.respawn !== false,
          respawnDelay: options.respawnDelay || 1000,
          timeout: options.timeout || 5000,
          gracefulShutdown: options.gracefulShutdown !== false,
          ...options
        };
        
        this.workers = new Map(); // pid -> worker info
        this.workerQueue = [];
        this.stats = {
          started: 0,
          exited: 0,
          restarts: 0,
          errors: 0
        };
        
        if (cluster.isMaster) {
          this.setupMaster();
        }
      }
      
      setupMaster() {
        console.log(`Master ${process.pid} starting with ${this.options.workers} workers`);
        
        // Fork initial workers
        for (let i = 0; i < this.options.workers; i++) {
          this.forkWorker();
        }
        
        // Setup event handlers
        this.setupEventHandlers();
        
        // Setup health checks
        this.setupHealthChecks();
        
        // Setup metrics collection
        this.setupMetrics();
      }
      
      forkWorker() {
        const worker = cluster.fork({
          WORKER_ID: this.stats.started + 1,
          NODE_ENV: process.env.NODE_ENV || 'development'
        });
        
        const workerInfo = {
          pid: worker.process.pid,
          id: this.stats.started + 1,
          worker,
          startTime: Date.now(),
          restarts: 0,
          state: 'starting',
          lastHeartbeat: Date.now(),
          requests: 0,
          errors: 0
        };
        
        this.workers.set(worker.process.pid, workerInfo);
        this.stats.started++;
        
        // Setup worker timeout
        workerInfo.timeout = setTimeout(() => {
          if (workerInfo.state === 'starting') {
            console.log(`Worker ${worker.process.pid} failed to start within ${this.options.timeout}ms`);
            worker.kill('SIGKILL');
          }
        }, this.options.timeout);
        
        return workerInfo;
      }
      
      setupEventHandlers() {
        cluster.on('online', (worker) => {
          const workerInfo = this.workers.get(worker.process.pid);
          if (workerInfo) {
            workerInfo.state = 'online';
            clearTimeout(workerInfo.timeout);
            console.log(`Worker ${worker.process.pid} is online`);
          }
        });
        
        cluster.on('listening', (worker, address) => {
          const workerInfo = this.workers.get(worker.process.pid);
          if (workerInfo) {
            workerInfo.state = 'listening';
            workerInfo.address = address;
            console.log(`Worker ${worker.process.pid} listening on ${address.address}:${address.port}`);
          }
        });
        
        cluster.on('disconnect', (worker) => {
          const workerInfo = this.workers.get(worker.process.pid);
          if (workerInfo) {
            workerInfo.state = 'disconnected';
            console.log(`Worker ${worker.process.pid} disconnected`);
          }
        });
        
        cluster.on('exit', (worker, code, signal) => {
          const workerInfo = this.workers.get(worker.process.pid);
          this.stats.exited++;
          
          if (workerInfo) {
            console.log(`Worker ${worker.process.pid} exited with code ${code}, signal ${signal}`);
            
            this.workers.delete(worker.process.pid);
            
            if (this.options.respawn && workerInfo.restarts < 3) {
              console.log(`Restarting worker ${worker.process.pid}...`);
              setTimeout(() => {
                this.forkWorker();
                this.stats.restarts++;
              }, this.options.respawnDelay);
            }
          }
        });
        
        cluster.on('message', (worker, message) => {
          const workerInfo = this.workers.get(worker.process.pid);
          
          if (message.type === 'heartbeat') {
            if (workerInfo) {
              workerInfo.lastHeartbeat = Date.now();
              workerInfo.memory = message.memory;
              workerInfo.uptime = message.uptime;
            }
          } else if (message.type === 'request') {
            if (workerInfo) {
              workerInfo.requests++;
            }
          } else if (message.type === 'error') {
            this.stats.errors++;
            if (workerInfo) {
              workerInfo.errors++;
            }
          }
        });
      }
      
      setupHealthChecks() {
        // Check for unresponsive workers
        setInterval(() => {
          const now = Date.now();
          
          for (const [pid, workerInfo] of this.workers.entries()) {
            if (workerInfo.state === 'online' || workerInfo.state === 'listening') {
              if (now - workerInfo.lastHeartbeat > 30000) { // 30 seconds
                console.log(`Worker ${pid} is unresponsive, killing...`);
                workerInfo.worker.kill('SIGTERM');
              }
            }
          }
        }, 10000);
      }
      
      setupMetrics() {
        // Collect and log metrics
        setInterval(() => {
          const activeWorkers = Array.from(this.workers.values()).filter(w => 
            w.state === 'listening'
          ).length;
          
          const totalRequests = Array.from(this.workers.values()).reduce(
            (sum, w) => sum + w.requests, 0
          );
          
          const totalMemory = Array.from(this.workers.values()).reduce(
            (sum, w) => sum + (w.memory ? w.memory.heapUsed : 0), 0
          );
          
          console.log('\n=== Cluster Metrics ===');
          console.log(`Active workers: ${activeWorkers}/${this.options.workers}`);
          console.log(`Total requests: ${totalRequests}`);
          console.log(`Total memory: ${(totalMemory / 1024 / 1024).toFixed(2)} MB`);
          console.log(`Uptime: ${process.uptime().toFixed(2)}s`);
          console.log(`Restarts: ${this.stats.restarts}`);
          console.log(`Errors: ${this.stats.errors}`);
          console.log('====================\n');
        }, 30000);
      }
      
      broadcast(message) {
        for (const [pid, workerInfo] of this.workers.entries()) {
          if (workerInfo.state === 'listening') {
            workerInfo.worker.send(message);
          }
        }
      }
      
      restartAll() {
        console.log('Restarting all workers...');
        
        for (const [pid, workerInfo] of this.workers.entries()) {
          workerInfo.worker.kill('SIGTERM');
        }
      }
      
      rollingRestart(delay = 1000) {
        console.log('Starting rolling restart...');
        
        const workers = Array.from(this.workers.values());
        let index = 0;
        
        const restartNext = () => {
          if (index >= workers.length) {
            console.log('Rolling restart complete');
            return;
          }
          
          const workerInfo = workers[index];
          console.log(`Restarting worker ${workerInfo.pid}...`);
          workerInfo.worker.kill('SIGTERM');
          
          index++;
          setTimeout(restartNext, delay);
        };
        
        restartNext();
      }
      
      async gracefulShutdown() {
        console.log('Starting graceful shutdown...');
        
        // Stop accepting new connections
        this.broadcast({ type: 'shutdown' });
        
        // Wait for workers to finish
        await new Promise(resolve => {
          setTimeout(resolve, 10000);
        });
        
        // Kill all workers
        for (const [pid, workerInfo] of this.workers.entries()) {
          workerInfo.worker.kill('SIGTERM');
        }
        
        // Wait for workers to exit
        await new Promise(resolve => {
          const check = () => {
            if (this.workers.size === 0) {
              resolve();
            } else {
              setTimeout(check, 1000);
            }
          };
          check();
        });
        
        console.log('All workers shut down');
      }
    };
  }

  // 3. Load Balancing Strategies in Cluster
  static loadBalancingCluster(strategy = 'round-robin') {
    if (cluster.isMaster) {
      const workers = [];
      let currentWorker = 0;
      
      // Create server that master will listen on
      const server = net.createServer((socket) => {
        // Select worker based on strategy
        let worker;
        
        switch (strategy) {
          case 'round-robin':
            worker = workers[currentWorker];
            currentWorker = (currentWorker + 1) % workers.length;
            break;
            
          case 'least-connections':
            worker = workers.reduce((least, w) => {
              return w.connections < least.connections ? w : least;
            });
            break;
            
          case 'ip-hash':
            const clientIP = socket.remoteAddress;
            const hash = clientIP.split('.').reduce((acc, octet) => {
              return ((acc << 5) - acc) + parseInt(octet);
            }, 0);
            worker = workers[Math.abs(hash) % workers.length];
            break;
        }
        
        if (worker) {
          worker.connections++;
          
          // Send socket to worker
          worker.send('sticky-session', socket);
          
          // Decrement on socket close
          socket.on('close', () => {
            worker.connections--;
          });
        }
      });
      
      // Fork workers
      const numWorkers = os.cpus().length;
      
      for (let i = 0; i < numWorkers; i++) {
        const worker = cluster.fork({ WORKER_ID: i + 1 });
        
        workers.push({
          pid: worker.process.pid,
          worker,
          connections: 0,
          id: i + 1
        });
        
        worker.on('message', (msg) => {
          if (msg.type === 'connection-closed') {
            const workerInfo = workers.find(w => w.pid === worker.process.pid);
            if (workerInfo) {
              workerInfo.connections--;
            }
          }
        });
      }
      
      server.listen(3000, () => {
        console.log(`Load balancer listening on port 3000, strategy: ${strategy}`);
      });
      
    } else {
      // Worker process
      const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end(`Hello from worker ${process.pid}`);
      });
      
      // Don't listen on port, master will handle connections
      process.on('message', (message, socket) => {
        if (message === 'sticky-session' && socket) {
          // Handle socket from master
          server.emit('connection', socket);
          socket.resume();
        }
      });
    }
  }

  // 4. Shared State Across Workers
  static sharedStateCluster() {
    if (cluster.isMaster) {
      // Shared state in master
      const sharedState = {
        counter: 0,
        users: new Map(),
        lastUpdated: Date.now()
      };
      
      // Fork workers
      for (let i = 0; i < os.cpus().length; i++) {
        cluster.fork();
      }
      
      // Handle worker messages
      cluster.on('message', (worker, message) => {
        if (message.type === 'increment') {
          // Synchronize counter updates
          sharedState.counter += message.value;
          sharedState.lastUpdated = Date.now();
          
          // Broadcast updated state
          for (const id in cluster.workers) {
            cluster.workers[id].send({
              type: 'state-update',
              counter: sharedState.counter,
              lastUpdated: sharedState.lastUpdated
            });
          }
        }
      });
      
    } else {
      // Worker process
      let localState = {
        counter: 0,
        lastUpdated: Date.now()
      };
      
      const server = http.createServer((req, res) => {
        // Handle different endpoints
        if (req.url === '/increment') {
          // Send increment request to master
          process.send({
            type: 'increment',
            value: 1,
            worker: process.pid
          });
          
          res.writeHead(200);
          res.end(`Increment requested from worker ${process.pid}`);
          
        } else if (req.url === '/counter') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            counter: localState.counter,
            lastUpdated: localState.lastUpdated,
            pid: process.pid
          }));
        }
      });
      
      server.listen(3000);
      
      // Receive state updates from master
      process.on('message', (message) => {
        if (message.type === 'state-update') {
          localState = {
            ...localState,
            counter: message.counter,
            lastUpdated: message.lastUpdated
          };
          console.log(`Worker ${process.pid} updated state:`, localState);
        }
      });
    }
  }

  // 5. Zero-Downtime Deployment
  static zeroDowntimeCluster() {
    if (cluster.isMaster) {
      console.log(`Master ${process.pid} is running`);
      
      const workers = [];
      
      // Fork initial workers
      for (let i = 0; i < os.cpus().length; i++) {
        workers.push(this.forkWorker(i + 1));
      }
      
      // Handle deployment signal
      process.on('SIGUSR2', async () => {
        console.log('Received deployment signal, starting zero-downtime deployment...');
        
        await this.rollingUpdate(workers);
        
        console.log('Deployment complete');
      });
      
      // Handle worker exit
      cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} exited`);
        
        // Remove from workers array
        const index = workers.findIndex(w => w.pid === worker.process.pid);
        if (index >= 0) {
          workers.splice(index, 1);
        }
        
        // Auto-restart (except during deployment)
        if (!this.isDeploying) {
          workers.push(this.forkWorker(workers.length + 1));
        }
      });
      
    } else {
      // Worker process
      const server = http.createServer((req, res) => {
        // Simulate work
        const start = Date.now();
        let sum = 0;
        for (let i = 0; i < 1000000; i++) {
          sum += Math.sqrt(i);
        }
        const duration = Date.now() - start;
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          pid: process.pid,
          duration,
          sum,
          message: 'Hello from worker!'
        }));
      });
      
      server.listen(3000);
      
      // Graceful shutdown handler
      process.on('SIGTERM', () => {
        console.log(`Worker ${process.pid} received SIGTERM, starting graceful shutdown`);
        
        // Stop accepting new connections
        server.close(() => {
          console.log(`Worker ${process.pid} server closed`);
          process.exit(0);
        });
        
        // Close existing connections after timeout
        setTimeout(() => {
          console.log(`Worker ${process.pid} forcing exit`);
          process.exit(1);
        }, 30000);
      });
    }
  }
  
  static forkWorker(id) {
    const worker = cluster.fork({
      WORKER_ID: id,
      START_TIME: Date.now()
    });
    
    return {
      pid: worker.process.pid,
      worker,
      id,
      startTime: Date.now(),
      state: 'running'
    };
  }
  
  static async rollingUpdate(workers) {
    this.isDeploying = true;
    
    for (let i = 0; i < workers.length; i++) {
      const oldWorker = workers[i];
      
      console.log(`Updating worker ${oldWorker.id} (PID: ${oldWorker.pid})`);
      
      // Mark old worker for shutdown
      oldWorker.state = 'draining';
      oldWorker.worker.send({ type: 'drain' });
      
      // Wait for connections to drain
      await new Promise(resolve => setTimeout(resolve, 10000));
      
      // Start new worker
      const newWorker = this.forkWorker(oldWorker.id);
      workers[i] = newWorker;
      
      // Kill old worker
      oldWorker.worker.kill('SIGTERM');
      
      // Wait for new worker to be ready
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      console.log(`Worker ${oldWorker.id} updated (new PID: ${newWorker.pid})`);
    }
    
    this.isDeploying = false;
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does cluster module enable port sharing between multiple Node.js processes?"
2. "What's the difference between cluster.fork() and child_process.fork()?"
3. "How would you implement sticky sessions in a clustered environment?"

**Scenario-Based Questions:**
1. "Your clustered application needs to maintain shared state (like session data) across all workers. How would you implement this?"
2. "During deployment, users are experiencing dropped connections. How would you implement zero-downtime deployment with cluster?"
3. "One worker in your cluster keeps crashing and restarting in a loop. How would you debug and prevent this?"

**Real-World Challenge:**
> "Design a clustered WebSocket server that: 1) Handles 100,000+ concurrent connections, 2) Maintains room/chat state across workers, 3) Implements efficient message broadcasting to all connections, 4) Supports zero-downtime deployment, 5) Provides real-time metrics on each worker's connection count and memory usage."

---

## 8. Event Emitter Custom Usage <a name="event-emitter-custom-usage"></a>

### Overview
Event Emitter is Node.js's implementation of the observer pattern, allowing objects to emit and listen for events.

### Comprehensive Implementation Guide

```javascript
const EventEmitter = require('events');

class EventEmitterMasterclass {
  // 1. Basic EventEmitter Usage
  static basicUsage() {
    console.log('=== Basic EventEmitter Usage ===');
    
    // Create emitter instance
    const emitter = new EventEmitter();
    
    // Set max listeners to avoid memory leak warnings
    emitter.setMaxListeners(20);
    
    // Add event listener
    emitter.on('user.created', (user) => {
      console.log('User created:', user.name);
    });
    
    // Add one-time listener
    emitter.once('system.ready', () => {
      console.log('System is ready (this will only fire once)');
    });
    
    // Add listener with context
    const handler = function(user) {
      console.log('User created in context:', user.name, 'Context:', this.id);
    };
    
    const context = { id: 'app-context' };
    emitter.on('user.created', handler.bind(context));
    
    // Add prepend listener (executes first)
    emitter.prependListener('user.created', (user) => {
      console.log('Prepended listener:', user.name);
    });
    
    // Emit events
    emitter.emit('user.created', { id: 1, name: 'John Doe', email: 'john@example.com' });
    emitter.emit('system.ready');
    emitter.emit('system.ready'); // Won't trigger the once listener
    
    // Remove specific listener
    emitter.removeListener('user.created', handler);
    
    // Remove all listeners for an event
    emitter.removeAllListeners('user.created');
    
    // Get listener count
    const count = emitter.listenerCount('user.created');
    console.log('Remaining listeners for user.created:', count);
    
    // Get event names
    const eventNames = emitter.eventNames();
    console.log('Registered event names:', eventNames);
  }

  // 2. Custom EventEmitter Class
  static createCustomEmitter() {
    console.log('\n=== Custom EventEmitter Class ===');
    
    class UserService extends EventEmitter {
      constructor() {
        super();
        this.users = new Map();
        this.setupInternalEvents();
      }
      
      setupInternalEvents() {
        // Internal error handling
        this.on('error', (error) => {
          console.error('UserService error:', error);
        });
        
        // Performance monitoring
        this.on('operation.complete', (operation, duration) => {
          console.log(`Operation ${operation} took ${duration}ms`);
        });
      }
      
      async createUser(userData) {
        const startTime = Date.now();
        
        try {
          // Validate user data
          if (!userData.name || !userData.email) {
            throw new Error('Invalid user data');
          }
          
          // Simulate async operation
          await new Promise(resolve => setTimeout(resolve, 100));
          
          const user = {
            id: Date.now(),
            ...userData,
            createdAt: new Date(),
            updatedAt: new Date()
          };
          
          this.users.set(user.id, user);
          
          // Emit events
          this.emit('user.beforeCreate', user);
          this.emit('user.created', user);
          this.emit('user.afterCreate', user);
          
          // Emit internal event
          const duration = Date.now() - startTime;
          this.emit('operation.complete', 'createUser', duration);
          
          return user;
          
        } catch (error) {
          this.emit('error', error);
          this.emit('user.createError', error, userData);
          throw error;
        }
      }
      
      async updateUser(id, updates) {
        const startTime = Date.now();
        
        try {
          const user = this.users.get(id);
          if (!user) {
            throw new Error('User not found');
          }
          
          const updatedUser = {
            ...user,
            ...updates,
            updatedAt: new Date()
          };
          
          this.users.set(id, updatedUser);
          
          // Emit update events
          this.emit('user.updated', { old: user, new: updatedUser });
          
          const duration = Date.now() - startTime;
          this.emit('operation.complete', 'updateUser', duration);
          
          return updatedUser;
          
        } catch (error) {
          this.emit('error', error);
          throw error;
        }
      }
      
      async deleteUser(id) {
        const startTime = Date.now();
        
        try {
          const user = this.users.get(id);
          if (!user) {
            throw new Error('User not found');
          }
          
          this.users.delete(id);
          
          // Emit delete events
          this.emit('user.deleted', user);
          
          const duration = Date.now() - startTime;
          this.emit('operation.complete', 'deleteUser', duration);
          
          return true;
          
        } catch (error) {
          this.emit('error', error);
          throw error;
        }
      }
      
      getUserCount() {
        return this.users.size;
      }
      
      // Custom event emitter methods
      emitWithRetry(event, data, maxRetries = 3) {
        return new Promise((resolve, reject) => {
          let retries = 0;
          
          const attempt = () => {
            try {
              const result = this.emit(event, data);
              resolve(result);
            } catch (error) {
              retries++;
              
              if (retries >= maxRetries) {
                reject(new Error(`Failed to emit ${event} after ${maxRetries} retries`));
              } else {
                console.log(`Retry ${retries} for event ${event}`);
                setTimeout(attempt, 1000 * retries);
              }
            }
          };
          
          attempt();
        });
      }
      
      // Event batching
      batchEmit(event, items, batchSize = 10) {
        const batches = [];
        for (let i = 0; i < items.length; i += batchSize) {
          batches.push(items.slice(i, i + batchSize));
        }
        
        batches.forEach((batch, index) => {
          setTimeout(() => {
            this.emit(event, {
              batch,
              index,
              total: batches.length,
              isLast: index === batches.length - 1
            });
          }, index * 100); // Stagger emissions
        });
      }
    }
    
    return UserService;
  }

  // 3. Advanced Event Patterns
  static advancedEventPatterns() {
    console.log('\n=== Advanced Event Patterns ===');
    
    return {
      // 1. Event Debouncing
      createDebouncedEmitter: (delay = 300) => {
        const emitter = new EventEmitter();
        const timers = new Map();
        
        const originalEmit = emitter.emit;
        
        emitter.emit = function(event, ...args) {
          if (timers.has(event)) {
            clearTimeout(timers.get(event));
          }
          
          timers.set(event, setTimeout(() => {
            timers.delete(event);
            originalEmit.call(this, event, ...args);
          }, delay));
          
          return this;
        };
        
        return emitter;
      },
      
      // 2. Event Throttling
      createThrottledEmitter: (interval = 1000) => {
        const emitter = new EventEmitter();
        const lastEmitted = new Map();
        
        const originalEmit = emitter.emit;
        
        emitter.emit = function(event, ...args) {
          const now = Date.now();
          const last = lastEmitted.get(event) || 0;
          
          if (now - last >= interval) {
            lastEmitted.set(event, now);
            return originalEmit.call(this, event, ...args);
          }
          
          return false;
        };
        
        return emitter;
      },
      
      // 3. Event Chaining
      createChainedEmitter: () => {
        const emitter = new EventEmitter();
        
        emitter.chain = function(event, handler) {
          this.on(event, async (data, next) => {
            try {
              await handler(data);
              if (next) next();
            } catch (error) {
              console.error(`Chain error in ${event}:`, error);
              if (next) next(error);
            }
          });
          
          return this;
        };
        
        emitter.emitChain = async function(event, initialData) {
          const listeners = this.listeners(event);
          
          if (listeners.length === 0) {
            return Promise.resolve();
          }
          
          return new Promise((resolve, reject) => {
            let index = 0;
            
            const next = (err) => {
              if (err) {
                reject(err);
                return;
              }
              
              if (index >= listeners.length) {
                resolve();
                return;
              }
              
              const listener = listeners[index++];
              try {
                listener(initialData, next);
              } catch (error) {
                reject(error);
              }
            };
            
            next();
          });
        };
        
        return emitter;
      },
      
      // 4. Event Broadcasting
      createBroadcastEmitter: (channels = new Set()) => {
        const emitter = new EventEmitter();
        
        emitter.subscribe = function(channel) {
          channels.add(channel);
          return this;
        };
        
        emitter.unsubscribe = function(channel) {
          channels.delete(channel);
          return this;
        };
        
        emitter.broadcast = function(event, data) {
          channels.forEach(channel => {
            this.emit(`${channel}:${event}`, data);
          });
          return this;
        };
        
        return emitter;
      },
      
      // 5. Event Validation
      createValidatedEmitter: (schema) => {
        const emitter = new EventEmitter();
        
        emitter.emitWithValidation = function(event, data) {
          const eventSchema = schema[event];
          
          if (eventSchema) {
            const { error, value } = eventSchema.validate(data);
            
            if (error) {
              this.emit('validation.error', { event, error, data });
              throw new Error(`Validation failed for ${event}: ${error.message}`);
            }
            
            return this.emit(event, value);
          }
          
          return this.emit(event, data);
        };
        
        return emitter;
      },
      
      // 6. Event Metrics
      createMonitoredEmitter: () => {
        const emitter = new EventEmitter();
        const metrics = {
          eventsEmitted: new Map(),
          listenersCalled: new Map(),
          errors: new Map(),
          responseTimes: new Map()
        };
        
        // Wrap emit method
        const originalEmit = emitter.emit;
        
        emitter.emit = function(event, ...args) {
          const startTime = Date.now();
          
          // Track event emission
          const eventCount = metrics.eventsEmitted.get(event) || 0;
          metrics.eventsEmitted.set(event, eventCount + 1);
          
          try {
            const result = originalEmit.call(this, event, ...args);
            
            // Track response time
            const duration = Date.now() - startTime;
            const times = metrics.responseTimes.get(event) || [];
            times.push(duration);
            if (times.length > 100) times.shift();
            metrics.responseTimes.set(event, times);
            
            return result;
          } catch (error) {
            // Track errors
            const errorCount = metrics.errors.get(event) || 0;
            metrics.errors.set(event, errorCount + 1);
            throw error;
          }
        };
        
        // Wrap on method to track listeners
        const originalOn = emitter.on;
        
        emitter.on = function(event, listener) {
          const wrappedListener = (...args) => {
            const startTime = Date.now();
            
            try {
              const result = listener(...args);
              
              // Track listener calls
              const listenerKey = `${event}:${listener.name || 'anonymous'}`;
              const callCount = metrics.listenersCalled.get(listenerKey) || 0;
              metrics.listenersCalled.set(listenerKey, callCount + 1);
              
              return result;
            } catch (error) {
              this.emit('listener.error', { event, listener, error });
              throw error;
            }
          };
          
          return originalOn.call(this, event, wrappedListener);
        };
        
        emitter.getMetrics = () => {
          const summary = {};
          
          for (const [event, count] of metrics.eventsEmitted) {
            const times = metrics.responseTimes.get(event) || [];
            const avgTime = times.length > 0 
              ? times.reduce((a, b) => a + b, 0) / times.length 
              : 0;
            
            summary[event] = {
              emitted: count,
              avgResponseTime: avgTime.toFixed(2) + 'ms',
              errors: metrics.errors.get(event) || 0,
              listeners: metrics.listenersCalled.size
            };
          }
          
          return summary;
        };
        
        return emitter;
      }
    };
  }

  // 4. Real-world Example: API Gateway with Event-driven Architecture
  static createAPIGateway() {
    console.log('\n=== API Gateway with Event-driven Architecture ===');
    
    class APIGateway extends EventEmitter {
      constructor() {
        super();
        this.middleware = [];
        this.routes = new Map();
        this.requestCount = 0;
        this.setupCoreEvents();
      }
      
      setupCoreEvents() {
        // Request lifecycle events
        this.on('request.start', (req) => {
          req.startTime = Date.now();
          req.requestId = `req_${Date.now()}_${++this.requestCount}`;
          console.log(`[${req.requestId}] Request started: ${req.method} ${req.url}`);
        });
        
        this.on('request.end', (req, res) => {
          const duration = Date.now() - req.startTime;
          console.log(`[${req.requestId}] Request completed: ${res.statusCode} in ${duration}ms`);
          
          // Emit metrics
          this.emit('metrics.request', {
            requestId: req.requestId,
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration,
            timestamp: new Date().toISOString()
          });
        });
        
        this.on('request.error', (req, error) => {
          console.error(`[${req.requestId}] Request error:`, error.message);
          
          this.emit('metrics.error', {
            requestId: req.requestId,
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
          });
        });
        
        // Middleware events
        this.on('middleware.before', (req, middlewareName) => {
          console.log(`[${req.requestId}] Before middleware: ${middlewareName}`);
        });
        
        this.on('middleware.after', (req, middlewareName, duration) => {
          console.log(`[${req.requestId}] After middleware: ${middlewareName} (${duration}ms)`);
        });
        
        // Route events
        this.on('route.match', (req, route) => {
          console.log(`[${req.requestId}] Route matched: ${route.method} ${route.path}`);
        });
        
        this.on('route.notFound', (req) => {
          console.log(`[${req.requestId}] No route matched: ${req.method} ${req.url}`);
        });
      }
      
      use(middleware) {
        this.middleware.push({
          name: middleware.name || 'anonymous',
          handler: middleware
        });
        return this;
      }
      
      addRoute(method, path, handler) {
        const route = {
          method,
          path,
          handler,
          regex: this.pathToRegex(path)
        };
        
        if (!this.routes.has(method)) {
          this.routes.set(method, []);
        }
        
        this.routes.get(method).push(route);
        return this;
      }
      
      pathToRegex(path) {
        // Convert route path to regex
        const pattern = path
          .replace(/\//g, '\\/')
          .replace(/:(\w+)/g, '(?<$1>[^\\/]+)')
          .replace(/\*/g, '.*');
        
        return new RegExp(`^${pattern}$`);
      }
      
      async handleRequest(req, res) {
        try {
          // Emit request start
          this.emit('request.start', req);
          
          // Execute middleware
          for (const { name, handler } of this.middleware) {
            this.emit('middleware.before', req, name);
            
            const startTime = Date.now();
            await handler(req, res);
            const duration = Date.now() - startTime;
            
            this.emit('middleware.after', req, name, duration);
            
            // Stop if response was sent
            if (res.headersSent) {
              this.emit('request.end', req, res);
              return;
            }
          }
          
          // Find matching route
          const methodRoutes = this.routes.get(req.method) || [];
          let matchedRoute = null;
          let params = {};
          
          for (const route of methodRoutes) {
            const match = req.url.match(route.regex);
            if (match) {
              matchedRoute = route;
              params = match.groups || {};
              break;
            }
          }
          
          if (matchedRoute) {
            this.emit('route.match', req, matchedRoute);
            
            // Add params to request
            req.params = params;
            
            // Execute route handler
            await matchedRoute.handler(req, res);
          } else {
            this.emit('route.notFound', req);
            res.statusCode = 404;
            res.end('Not found');
          }
          
          // Emit request end
          this.emit('request.end', req, res);
          
        } catch (error) {
          this.emit('request.error', req, error);
          
          if (!res.headersSent) {
            res.statusCode = 500;
            res.end('Internal server error');
          }
        }
      }
      
      // Event-driven middleware
      onRequest(event, handler) {
        this.on(`request.${event}`, handler);
        return this;
      }
      
      onMiddleware(event, handler) {
        this.on(`middleware.${event}`, handler);
        return this;
      }
      
      onRoute(event, handler) {
        this.on(`route.${event}`, handler);
        return this;
      }
      
      // Metrics collection
      getMetrics() {
        return {
          totalRequests: this.requestCount,
          activeListeners: this.eventNames().reduce((count, event) => {
            return count + this.listenerCount(event);
          }, 0),
          registeredEvents: this.eventNames().length,
          middlewareCount: this.middleware.length,
          routeCount: Array.from(this.routes.values()).reduce((sum, routes) => sum + routes.length, 0)
        };
      }
    }
    
    return APIGateway;
  }

  // 5. Performance Optimization Techniques
  static performanceOptimizations() {
    console.log('\n=== EventEmitter Performance Optimizations ===');
    
    return {
      // 1. Listener pooling
      createPooledEmitter: (poolSize = 100) => {
        class PooledEmitter extends EventEmitter {
          constructor() {
            super();
            this.listenerPool = new Array(poolSize);
            this.poolIndex = 0;
            
            // Pre-create listeners
            for (let i = 0; i < poolSize; i++) {
              this.listenerPool[i] = this.createListener();
            }
          }
          
          createListener() {
            return (data) => {
              // Generic listener that can be reused
              this.emit('data.processed', data);
            };
          }
          
          getListener() {
            const listener = this.listenerPool[this.poolIndex];
            this.poolIndex = (this.poolIndex + 1) % poolSize;
            return listener;
          }
          
          onWithPool(event, transformer) {
            const listener = this.getListener();
            
            // Wrap with transformer
            const wrappedListener = (data) => {
              const transformed = transformer(data);
              listener(transformed);
            };
            
            return this.on(event, wrappedListener);
          }
        }
        
        return PooledEmitter;
      },
      
      // 2. Batch event processing
      createBatchedEmitter: (batchSize = 10, flushInterval = 1000) => {
        class BatchedEmitter extends EventEmitter {
          constructor() {
            super();
            this.batches = new Map();
            this.flushTimers = new Map();
            
            // Setup periodic flush
            setInterval(() => this.flushAll(), flushInterval);
          }
          
          emitBatched(event, data) {
            if (!this.batches.has(event)) {
              this.batches.set(event, []);
            }
            
            const batch = this.batches.get(event);
            batch.push(data);
            
            // Flush if batch is full
            if (batch.length >= batchSize) {
              this.flush(event);
            } else if (!this.flushTimers.has(event)) {
              // Schedule flush
              const timer = setTimeout(() => this.flush(event), flushInterval);
              this.flushTimers.set(event, timer);
            }
          }
          
          flush(event) {
            if (!this.batches.has(event)) return;
            
            const batch = this.batches.get(event);
            if (batch.length === 0) return;
            
            // Clear timer
            if (this.flushTimers.has(event)) {
              clearTimeout(this.flushTimers.get(event));
              this.flushTimers.delete(event);
            }
            
            // Emit batched event
            this.emit(`${event}.batched`, batch);
            
            // Clear batch
            this.batches.set(event, []);
          }
          
          flushAll() {
            for (const event of this.batches.keys()) {
              this.flush(event);
            }
          }
        }
        
        return BatchedEmitter;
      },
      
      // 3. Lazy listener initialization
      createLazyEmitter: () => {
        class LazyEmitter extends EventEmitter {
          constructor() {
            super();
            this.lazyListeners = new Map();
            this.initialized = false;
          }
          
          onLazy(event, initializer) {
            this.lazyListeners.set(event, initializer);
            return this;
          }
          
          emit(event, ...args) {
            // Initialize lazy listeners on first emit
            if (!this.initialized && this.lazyListeners.has(event)) {
              this.initializeLazyListeners();
            }
            
            return super.emit(event, ...args);
          }
          
          initializeLazyListeners() {
            for (const [event, initializer] of this.lazyListeners) {
              const listeners = initializer();
              
              if (Array.isArray(listeners)) {
                listeners.forEach(listener => {
                  this.on(event, listener);
                });
              } else {
                this.on(event, listeners);
              }
            }
            
            this.initialized = true;
            this.lazyListeners.clear();
          }
        }
        
        return LazyEmitter;
      },
      
      // 4. Memory-efficient emitter
      createMemoryEfficientEmitter: () => {
        class MemoryEfficientEmitter {
          constructor() {
            this.listeners = Object.create(null); // No prototype for faster lookups
            this.maxListeners = 10;
          }
          
          on(event, listener) {
            if (!this.listeners[event]) {
              this.listeners[event] = [];
            }
            
            const listeners = this.listeners[event];
            listeners.push(listener);
            
            // Check max listeners
            if (listeners.length > this.maxListeners && !listeners.warned) {
              console.warn(`Possible memory leak detected for event '${event}'. ${listeners.length} listeners added.`);
              listeners.warned = true;
            }
            
            return this;
          }
          
          once(event, listener) {
            const onceListener = (...args) => {
              this.off(event, onceListener);
              listener(...args);
            };
            
            onceListener.listener = listener;
            return this.on(event, onceListener);
          }
          
          off(event, listener) {
            const listeners = this.listeners[event];
            if (!listeners) return this;
            
            if (listener) {
              const index = listeners.findIndex(l => 
                l === listener || l.listener === listener
              );
              
              if (index >= 0) {
                listeners.splice(index, 1);
              }
            } else {
              listeners.length = 0;
            }
            
            return this;
          }
          
          emit(event, ...args) {
            const listeners = this.listeners[event];
            if (!listeners || listeners.length === 0) return false;
            
            // Copy listeners array to handle mutations during emission
            const listenersCopy = listeners.slice();
            
            for (const listener of listenersCopy) {
              try {
                listener(...args);
              } catch (error) {
                console.error(`Error in event listener for '${event}':`, error);
              }
            }
            
            return true;
          }
          
          listenerCount(event) {
            const listeners = this.listeners[event];
            return listeners ? listeners.length : 0;
          }
        }
        
        return MemoryEfficientEmitter;
      }
    };
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does EventEmitter handle asynchronous vs synchronous listeners? What are the implications?"
2. "Explain the memory leak warning in EventEmitter and how to prevent it."
3. "What's the difference between `emitter.on()` and `emitter.addListener()`? When would you use `emitter.prependListener()`?"

**Scenario-Based Questions:**
1. "You're building a real-time dashboard that needs to update multiple UI components when data changes. How would you design an event system to efficiently handle this?"
2. "Your application emits thousands of events per second, causing performance issues. What optimization strategies would you implement?"
3. "You need to ensure that certain events are processed in a specific order. How would you implement event sequencing?"

**Real-World Challenge:**
> "Design a plugin system for a web framework where: 1) Plugins can register event listeners, 2) Events can be intercepted and modified by multiple plugins, 3) Plugins have dependencies and need to load in correct order, 4) The system supports hot reloading of plugins, 5) Provides comprehensive debugging of event flow between plugins."

---

## 9. Creating Your Own Framework (Mini Express) <a name="creating-your-own-framework"></a>

### Overview
Building a mini Express.js clone helps understand how web frameworks work internally, including routing, middleware, request/response handling.

### Comprehensive Implementation Guide

```javascript
const http = require('http');
const url = require('url');
const querystring = require('querystring');
const EventEmitter = require('events');

class MiniExpress {
  // 1. Core Framework Implementation
  static createMiniExpress() {
    console.log('=== Creating Mini Express Framework ===');
    
    class MiniExpress extends EventEmitter {
      constructor() {
        super();
        this.middleware = [];
        this.routes = {
          GET: new Map(),
          POST: new Map(),
          PUT: new Map(),
          DELETE: new Map(),
          PATCH: new Map()
        };
        this.settings = {};
        this.engines = new Map();
        
        this.setupRequestResponse();
      }
      
      setupRequestResponse() {
        // Extend HTTP request and response prototypes
        this.extendRequest();
        this.extendResponse();
      }
      
      extendRequest() {
        const self = this;
        
        // Store original request prototype
        const originalReq = http.IncomingMessage.prototype;
        
        // Add properties to request prototype
        Object.defineProperties(originalReq, {
          query: {
            get() {
              if (!this._query) {
                const parsedUrl = url.parse(this.url, true);
                this._query = parsedUrl.query;
              }
              return this._query;
            }
          },
          
          params: {
            get() {
              return this._params || {};
            },
            set(value) {
              this._params = value;
            }
          },
          
          body: {
            get() {
              return this._body;
            },
            set(value) {
              this._body = value;
            }
          },
          
          cookies: {
            get() {
              if (!this._cookies) {
                const cookieHeader = this.headers.cookie;
                this._cookies = cookieHeader 
                  ? cookieHeader.split(';').reduce((cookies, cookie) => {
                      const [name, value] = cookie.trim().split('=');
                      cookies[name] = decodeURIComponent(value);
                      return cookies;
                    }, {})
                  : {};
              }
              return this._cookies;
            }
          },
          
          signedCookies: {
            get() {
              // Simplified signed cookies implementation
              return this.cookies;
            }
          },
          
          protocol: {
            get() {
              return this.connection.encrypted ? 'https' : 'http';
            }
          },
          
          secure: {
            get() {
              return this.protocol === 'https';
            }
          },
          
          ip: {
            get() {
              return this.headers['x-forwarded-for'] || 
                     this.connection.remoteAddress;
            }
          },
          
          hostname: {
            get() {
              return this.headers.host.split(':')[0];
            }
          },
          
          path: {
            get() {
              return url.parse(this.url).pathname;
            }
          },
          
          xhr: {
            get() {
              return this.headers['x-requested-with'] === 'XMLHttpRequest';
            }
          }
        });
        
        // Add methods to request prototype
        originalReq.get = function(field) {
          return this.headers[field.toLowerCase()];
        };
        
        originalReq.is = function(type) {
          const contentType = this.headers['content-type'];
          if (!contentType) return false;
          
          return contentType.includes(type);
        };
        
        originalReq.accepts = function(types) {
          const acceptHeader = this.headers.accept || '*/*';
          
          if (typeof types === 'string') {
            types = [types];
          }
          
          for (const type of types) {
            if (acceptHeader.includes(type) || acceptHeader === '*/*') {
              return type;
            }
          }
          
          return false;
        };
      }
      
      extendResponse() {
        const self = this;
        
        // Store original response prototype
        const originalRes = http.ServerResponse.prototype;
        
        // Add properties to response prototype
        Object.defineProperties(originalRes, {
          locals: {
            get() {
              if (!this._locals) {
                this._locals = {};
              }
              return this._locals;
            },
            set(value) {
              this._locals = value;
            }
          }
        });
        
        // Add methods to response prototype
        originalRes.status = function(code) {
          this.statusCode = code;
          return this;
        };
        
        originalRes.send = function(data) {
          let body = data;
          
          // Handle different data types
          if (typeof body === 'object' && body !== null) {
            if (Buffer.isBuffer(body)) {
              if (!this.get('Content-Type')) {
                this.type('application/octet-stream');
              }
            } else {
              // JSON response
              body = JSON.stringify(body);
              if (!this.get('Content-Type')) {
                this.type('application/json');
              }
            }
          } else if (typeof body === 'string') {
            if (!this.get('Content-Type')) {
              this.type('text/html');
            }
          } else if (typeof body === 'number') {
            body = body.toString();
            if (!this.get('Content-Type')) {
              this.type('text/plain');
            }
          }
          
          // Set Content-Length
          this.set('Content-Length', Buffer.byteLength(body));
          
          // Write response
          if (this.statusCode === 204 || this.statusCode === 304) {
            this.removeHeader('Content-Type');
            this.removeHeader('Content-Length');
            this.end();
          } else {
            this.end(body);
          }
          
          return this;
        };
        
        originalRes.json = function(data) {
          this.type('application/json');
          return this.send(data);
        };
        
        originalRes.jsonp = function(data) {
          const callback = this.req.query.callback;
          
          if (callback) {
            this.type('application/javascript');
            return this.send(`${callback}(${JSON.stringify(data)})`);
          }
          
          return this.json(data);
        };
        
        originalRes.sendFile = function(filename, options = {}) {
          const fs = require('fs');
          const path = require('path');
          
          const filePath = path.resolve(filename);
          
          fs.readFile(filePath, (err, data) => {
            if (err) {
              if (err.code === 'ENOENT') {
                this.status(404).send('File not found');
              } else {
                this.status(500).send('Internal server error');
              }
              return;
            }
            
            // Set content type based on file extension
            const ext = path.extname(filename).toLowerCase();
            const mimeTypes = {
              '.html': 'text/html',
              '.css': 'text/css',
              '.js': 'application/javascript',
              '.json': 'application/json',
              '.png': 'image/png',
              '.jpg': 'image/jpeg',
              '.gif': 'image/gif',
              '.svg': 'image/svg+xml'
            };
            
            if (mimeTypes[ext]) {
              this.type(mimeTypes[ext]);
            }
            
            this.send(data);
          });
          
          return this;
        };
        
        originalRes.redirect = function(status, url) {
          // Handle overloaded signature: redirect(url) or redirect(status, url)
          if (typeof status === 'string') {
            url = status;
            status = 302;
          }
          
          this.statusCode = status;
          this.set('Location', url);
          this.set('Content-Length', '0');
          this.end();
          
          return this;
        };
        
        originalRes.type = function(type) {
          this.set('Content-Type', type);
          return this;
        };
        
        originalRes.set = function(field, value) {
          if (typeof field === 'object') {
            for (const key in field) {
              this.setHeader(key, field[key]);
            }
          } else {
            this.setHeader(field, value);
          }
          return this;
        };
        
        originalRes.get = function(field) {
          return this.getHeader(field);
        };
        
        originalRes.cookie = function(name, value, options = {}) {
          let cookie = `${name}=${encodeURIComponent(value)}`;
          
          if (options.maxAge) {
            cookie += `; Max-Age=${options.maxAge}`;
          }
          
          if (options.expires) {
            cookie += `; Expires=${options.expires.toUTCString()}`;
          }
          
          if (options.path) {
            cookie += `; Path=${options.path}`;
          }
          
          if (options.domain) {
            cookie += `; Domain=${options.domain}`;
          }
          
          if (options.secure) {
            cookie += '; Secure';
          }
          
          if (options.httpOnly) {
            cookie += '; HttpOnly';
          }
          
          if (options.sameSite) {
            cookie += `; SameSite=${options.sameSite}`;
          }
          
          this.append('Set-Cookie', cookie);
          return this;
        };
        
        originalRes.clearCookie = function(name, options = {}) {
          const clearOptions = { ...options, expires: new Date(1) };
          return this.cookie(name, '', clearOptions);
        };
        
        originalRes.render = function(view, locals = {}) {
          const self = this;
          const engine = this.app.engines.get('.html') || this.defaultEngine;
          
          if (!engine) {
            throw new Error('No template engine configured');
          }
          
          // Merge locals
          const renderLocals = { ...this.locals, ...locals };
          
          // Render view
          engine(view, renderLocals, (err, html) => {
            if (err) {
              self.next(err);
              return;
            }
            
            self.send(html);
          });
          
          return this;
        };
      }
      
      // 2. Application Methods
      use(path, ...handlers) {
        // Handle overloaded signature: use(handler) or use(path, handler)
        if (typeof path === 'function') {
          handlers = [path, ...handlers];
          path = '/';
        }
        
        for (const handler of handlers) {
          this.middleware.push({
            path,
            handler,
            isRoute: false
          });
        }
        
        return this;
      }
      
      all(path, ...handlers) {
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
        
        for (const method of methods) {
          for (const handler of handlers) {
            this.route(method, path, handler);
          }
        }
        
        return this;
      }
      
      route(method, path, ...handlers) {
        if (!this.routes[method]) {
          this.routes[method] = new Map();
        }
        
        // Convert route path to regex pattern
        const pattern = this.pathToPattern(path);
        
        this.routes[method].set(pattern, {
          path,
          pattern,
          handlers
        });
        
        return this;
      }
      
      get(path, ...handlers) {
        return this.route('GET', path, ...handlers);
      }
      
      post(path, ...handlers) {
        return this.route('POST', path, ...handlers);
      }
      
      put(path, ...handlers) {
        return this.route('PUT', path, ...handlers);
      }
      
      delete(path, ...handlers) {
        return this.route('DELETE', path, ...handlers);
      }
      
      patch(path, ...handlers) {
        return this.route('PATCH', path, ...handlers);
      }
      
      pathToPattern(path) {
        // Convert route path with parameters to regex pattern
        let pattern = path
          .replace(/\//g, '\\/')
          .replace(/:(\w+)/g, '(?<$1>[^\\/]+)')
          .replace(/\*/g, '.*');
        
        return new RegExp(`^${pattern}$`);
      }
      
      // 3. Router Implementation
      Router() {
        const router = new EventEmitter();
        
        router.stack = [];
        router.params = {};
        
        router.use = function(path, ...handlers) {
          if (typeof path === 'function') {
            handlers = [path, ...handlers];
            path = '/';
          }
          
          for (const handler of handlers) {
            this.stack.push({
              path,
              handler,
              isRoute: false
            });
          }
          
          return this;
        };
        
        router.route = function(path) {
          const route = new Route(path);
          
          this.stack.push({
            path,
            route,
            isRoute: true
          });
          
          return route;
        };
        
        // Add HTTP methods to router
        ['get', 'post', 'put', 'delete', 'patch', 'all'].forEach(method => {
          router[method] = function(path, ...handlers) {
            const route = this.route(path);
            route[method](...handlers);
            return this;
          };
        });
        
        router.param = function(name, handler) {
          this.params[name] = handler;
          return this;
        };
        
        return router;
      }
      
      // 4. Route Implementation
      Route(path) {
        const route = {
          path,
          stack: [],
          methods: {}
        };
        
        // Add HTTP methods to route
        ['get', 'post', 'put', 'delete', 'patch', 'all'].forEach(method => {
          route[method] = function(...handlers) {
            for (const handler of handlers) {
              route.stack.push({
                method: method.toUpperCase(),
                handler
              });
            }
            
            route.methods[method.toUpperCase()] = true;
            return route;
          };
        });
        
        return route;
      }
      
      // 5. Request Handling
      async handleRequest(req, res) {
        // Attach app reference to request and response
        req.app = this;
        res.app = this;
        
        // Parse URL
        const parsedUrl = url.parse(req.url, true);
        req.originalUrl = req.url;
        req.url = parsedUrl.pathname;
        req.query = parsedUrl.query;
        
        // Parse body for POST, PUT, PATCH
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
          await this.parseBody(req);
        }
        
        // Execute middleware and routes
        try {
          await this.executeMiddleware(req, res);
        } catch (error) {
          this.handleError(error, req, res);
        }
      }
      
      async parseBody(req) {
        return new Promise((resolve, reject) => {
          let body = '';
          
          req.on('data', chunk => {
            body += chunk.toString();
            
            // Limit body size
            if (body.length > 1e6) { // 1MB
              req.destroy();
              reject(new Error('Request body too large'));
            }
          });
          
          req.on('end', () => {
            try {
              const contentType = req.headers['content-type'];
              
              if (contentType && contentType.includes('application/json')) {
                req.body = body ? JSON.parse(body) : {};
              } else if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
                req.body = querystring.parse(body);
              } else {
                req.body = body;
              }
              
              resolve();
            } catch (error) {
              reject(error);
            }
          });
          
          req.on('error', reject);
        });
      }
      
      async executeMiddleware(req, res) {
        let idx = 0;
        const next = async (err) => {
          if (err) {
            return this.handleError(err, req, res);
          }
          
          if (idx >= this.middleware.length) {
            // Execute route handlers
            return this.executeRoute(req, res);
          }
          
          const layer = this.middleware[idx++];
          
          // Check if middleware path matches
          if (!this.matchPath(layer.path, req.url)) {
            return next();
          }
          
          try {
            await layer.handler(req, res, next);
          } catch (error) {
            next(error);
          }
        };
        
        await next();
      }
      
      matchPath(path, url) {
        if (path === '/') return true;
        
        if (path.endsWith('*')) {
          const prefix = path.slice(0, -1);
          return url.startsWith(prefix);
        }
        
        return url === path;
      }
      
      async executeRoute(req, res) {
        const methodRoutes = this.routes[req.method];
        if (!methodRoutes) {
          res.statusCode = 405;
          res.end('Method not allowed');
          return;
        }
        
        // Find matching route
        for (const [pattern, route] of methodRoutes.entries()) {
          const match = req.url.match(pattern);
          
          if (match) {
            req.params = match.groups || {};
            
            // Execute route handlers
            for (const handler of route.handlers) {
              await handler(req, res);
              if (res.headersSent) break;
            }
            
            return;
          }
        }
        
        // No route matched
        res.statusCode = 404;
        res.end('Not found');
      }
      
      handleError(err, req, res) {
        // Default error handler
        console.error('Error:', err);
        
        if (!res.headersSent) {
          res.statusCode = err.statusCode || 500;
          res.set('Content-Type', 'application/json');
          res.end(JSON.stringify({
            error: err.message || 'Internal server error',
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
          }));
        }
      }
      
      // 6. Server Creation
      listen(port, hostname, callback) {
        const server = http.createServer((req, res) => {
          this.handleRequest(req, res);
        });
        
        server.listen(port, hostname, callback);
        
        return server;
      }
      
      // 7. Template Engine Support
      set(key, value) {
        this.settings[key] = value;
        return this;
      }
      
      get(key) {
        return this.settings[key];
      }
      
      engine(ext, fn) {
        this.engines.set(ext, fn);
        return this;
      }
      
      // 8. Static File Serving
      static(root) {
        const fs = require('fs');
        const path = require('path');
        
        return (req, res, next) => {
          const filePath = path.join(root, req.url);
          
          fs.stat(filePath, (err, stats) => {
            if (err || !stats.isFile()) {
              return next();
            }
            
            const stream = fs.createReadStream(filePath);
            
            // Set content type
            const ext = path.extname(filePath).toLowerCase();
            const mimeTypes = {
              '.html': 'text/html',
              '.css': 'text/css',
              '.js': 'application/javascript',
              '.json': 'application/json',
              '.png': 'image/png',
              '.jpg': 'image/jpeg',
              '.gif': 'image/gif',
              '.svg': 'image/svg+xml',
              '.txt': 'text/plain'
            };
            
            if (mimeTypes[ext]) {
              res.type(mimeTypes[ext]);
            }
            
            stream.pipe(res);
            
            stream.on('error', (err) => {
              next(err);
            });
          });
        };
      }
    }
    
    return MiniExpress;
  }

  // 2. Advanced Features Implementation
  static advancedFeatures() {
    console.log('\n=== Advanced Framework Features ===');
    
    return {
      // 1. Session Management
      createSessionMiddleware: (options = {}) => {
        const sessions = new Map();
        const sessionStore = {
          get(sid) {
            return sessions.get(sid);
          },
          set(sid, session) {
            sessions.set(sid, session);
          },
          destroy(sid) {
            sessions.delete(sid);
          }
        };
        
        return (req, res, next) => {
          // Get session ID from cookie
          const sid = req.cookies.sessionId;
          
          if (sid && sessionStore.get(sid)) {
            req.session = sessionStore.get(sid);
          } else {
            // Create new session
            const newSid = require('crypto').randomBytes(16).toString('hex');
            req.session = { id: newSid };
            sessionStore.set(newSid, req.session);
            
            // Set session cookie
            res.cookie('sessionId', newSid, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });
          }
          
          // Save session at end of request
          const originalEnd = res.end;
          res.end = function(...args) {
            if (req.session) {
              sessionStore.set(req.session.id, req.session);
            }
            originalEnd.apply(this, args);
          };
          
          next();
        };
      },
      
      // 2. Authentication Middleware
      createAuthMiddleware: (options = {}) => {
        return {
          // Basic authentication
          basic: (req, res, next) => {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Basic ')) {
              res.set('WWW-Authenticate', 'Basic realm="Secure Area"');
              res.status(401).send('Authentication required');
              return;
            }
            
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
            const [username, password] = credentials.split(':');
            
            // Validate credentials (in real app, check against database)
            if (username === 'admin' && password === 'password') {
              req.user = { username, role: 'admin' };
              next();
            } else {
              res.status(401).send('Invalid credentials');
            }
          },
          
          // JWT authentication
          jwt: (secret = process.env.JWT_SECRET) => {
            const jwt = require('jsonwebtoken');
            
            return (req, res, next) => {
              const authHeader = req.headers.authorization;
              
              if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'No token provided' });
                return;
              }
              
              const token = authHeader.slice(7);
              
              try {
                const decoded = jwt.verify(token, secret);
                req.user = decoded;
                next();
              } catch (error) {
                res.status(401).json({ error: 'Invalid token' });
              }
            };
          },
          
          // Role-based authorization
          authorize: (...roles) => {
            return (req, res, next) => {
              if (!req.user) {
                res.status(401).json({ error: 'Authentication required' });
                return;
              }
              
              if (!roles.includes(req.user.role)) {
                res.status(403).json({ error: 'Insufficient permissions' });
                return;
              }
              
              next();
            };
          }
        };
      },
      
      // 3. Validation Middleware
      createValidationMiddleware: (schema) => {
        return (req, res, next) => {
          const data = {
            body: req.body,
            query: req.query,
            params: req.params,
            headers: req.headers
          };
          
          const { error, value } = schema.validate(data, {
            abortEarly: false,
            allowUnknown: true
          });
          
          if (error) {
            const errors = error.details.map(detail => ({
              field: detail.path.join('.'),
              message: detail.message
            }));
            
            res.status(400).json({ errors });
            return;
          }
          
          // Replace request data with validated values
          req.body = value.body;
          req.query = value.query;
          req.params = value.params;
          
          next();
        };
      },
      
      // 4. Rate Limiting Middleware
      createRateLimitMiddleware: (options = {}) => {
        const store = new Map();
        
        return (req, res, next) => {
          const key = req.ip;
          const now = Date.now();
          const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
          const max = options.max || 100;
          
          if (!store.has(key)) {
            store.set(key, {
              count: 1,
              resetTime: now + windowMs,
              firstRequest: now
            });
          } else {
            const record = store.get(key);
            
            if (now > record.resetTime) {
              // Reset window
              record.count = 1;
              record.resetTime = now + windowMs;
              record.firstRequest = now;
            } else if (record.count >= max) {
              // Rate limit exceeded
              const retryAfter = Math.ceil((record.resetTime - now) / 1000);
              
              res.set('Retry-After', retryAfter);
              res.status(429).json({
                error: 'Too many requests',
                retryAfter: `${retryAfter} seconds`
              });
              return;
            } else {
              record.count++;
            }
          }
          
          // Set rate limit headers
          const record = store.get(key);
          res.set('X-RateLimit-Limit', max);
          res.set('X-RateLimit-Remaining', max - record.count);
          res.set('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
          
          next();
        };
      },
      
      // 5. Compression Middleware
      createCompressionMiddleware: () => {
        const zlib = require('zlib');
        
        return (req, res, next) => {
          const acceptEncoding = req.headers['accept-encoding'] || '';
          const originalWrite = res.write;
          const originalEnd = res.end;
          let compressor;
          
          if (acceptEncoding.includes('br')) {
            compressor = zlib.createBrotliCompress();
            res.setHeader('Content-Encoding', 'br');
          } else if (acceptEncoding.includes('gzip')) {
            compressor = zlib.createGzip();
            res.setHeader('Content-Encoding', 'gzip');
          } else if (acceptEncoding.includes('deflate')) {
            compressor = zlib.createDeflate();
            res.setHeader('Content-Encoding', 'deflate');
          }
          
          if (compressor) {
            // Compress response
            res.write = function(chunk, encoding, callback) {
              if (chunk) {
                compressor.write(chunk, encoding, callback);
              }
              return true;
            };
            
            res.end = function(chunk, encoding, callback) {
              if (chunk) {
                compressor.write(chunk, encoding);
              }
              
              compressor.end();
              
              // Pipe compressed data to response
              compressor.pipe(res);
              
              compressor.on('end', () => {
                originalEnd.call(res);
              });
            };
          }
          
          next();
        };
      },
      
      // 6. CORS Middleware
      createCorsMiddleware: (options = {}) => {
        const defaults = {
          origin: '*',
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
          allowedHeaders: ['Content-Type', 'Authorization'],
          exposedHeaders: [],
          credentials: false,
          maxAge: 86400
        };
        
        const config = { ...defaults, ...options };
        
        return (req, res, next) => {
          // Handle preflight requests
          if (req.method === 'OPTIONS') {
            res.setHeader('Access-Control-Allow-Origin', config.origin);
            res.setHeader('Access-Control-Allow-Methods', config.methods.join(', '));
            res.setHeader('Access-Control-Allow-Headers', config.allowedHeaders.join(', '));
            res.setHeader('Access-Control-Expose-Headers', config.exposedHeaders.join(', '));
            res.setHeader('Access-Control-Max-Age', config.maxAge);
            
            if (config.credentials) {
              res.setHeader('Access-Control-Allow-Credentials', 'true');
            }
            
            res.status(204).end();
            return;
          }
          
          // Regular requests
          res.setHeader('Access-Control-Allow-Origin', config.origin);
          
          if (config.credentials) {
            res.setHeader('Access-Control-Allow-Credentials', 'true');
          }
          
          if (config.exposedHeaders.length > 0) {
            res.setHeader('Access-Control-Expose-Headers', config.exposedHeaders.join(', '));
          }
          
          next();
        };
      }
    };
  }

  // 3. Complete Example Application
  static createExampleApp() {
    console.log('\n=== Complete Example Application ===');
    
    const MiniExpress = this.createMiniExpress();
    const app = new MiniExpress();
    
    // Settings
    app.set('env', process.env.NODE_ENV || 'development');
    app.set('json spaces', 2);
    
    // Middleware
    app.use((req, res, next) => {
      console.log(`${req.method} ${req.url}`);
      next();
    });
    
    // Static files
    app.use('/public', app.static('public'));
    
    // Routes
    app.get('/', (req, res) => {
      res.send('Hello from MiniExpress!');
    });
    
    app.get('/api/users', (req, res) => {
      const users = [
        { id: 1, name: 'John Doe' },
        { id: 2, name: 'Jane Smith' }
      ];
      res.json(users);
    });
    
    app.get('/api/users/:id', (req, res) => {
      res.json({
        id: req.params.id,
        name: 'User ' + req.params.id
      });
    });
    
    app.post('/api/users', (req, res) => {
      console.log('Creating user:', req.body);
      res.status(201).json({
        id: Date.now(),
        ...req.body
      });
    });
    
    app.put('/api/users/:id', (req, res) => {
      res.json({
        id: req.params.id,
        ...req.body,
        updatedAt: new Date()
      });
    });
    
    app.delete('/api/users/:id', (req, res) => {
      res.status(204).end();
    });
    
    // Error handling middleware
    app.use((err, req, res, next) => {
      console.error('Error:', err);
      
      res.status(err.statusCode || 500).json({
        error: err.message || 'Internal server error',
        stack: app.get('env') === 'development' ? err.stack : undefined
      });
    });
    
    // 404 handler
    app.use((req, res) => {
      res.status(404).send('Not found');
    });
    
    // Start server
    const server = app.listen(3000, () => {
      console.log('MiniExpress server listening on port 3000');
    });
    
    return { app, server };
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does Express.js handle middleware execution order and what happens when a middleware doesn't call next()?"
2. "Explain the difference between app.use() and app.all(). When would you use each?"
3. "How does Express.js handle async errors in middleware and route handlers?"

**Scenario-Based Questions:**
1. "You need to add a custom header to all responses in your framework. How would you implement this as middleware?"
2. "Your framework needs to support template rendering with multiple engines (Handlebars, EJS, Pug). How would you design the engine interface?"
3. "Users report that file uploads are failing with large files. How would you implement streaming file uploads in your framework?"

**Real-World Challenge:**
> "Design a modern web framework that: 1) Supports both REST APIs and GraphQL, 2) Implements middleware chains with dependency injection, 3) Provides built-in WebSocket support, 4) Includes a plugin system for extensibility, 5) Supports server-side rendering with hydration, 6) Has built-in testing utilities."

---

## 10. File Watchers <a name="file-watchers"></a>

### Overview
File watchers monitor files and directories for changes, enabling features like hot reloading, live reloading, and automatic builds.

### Comprehensive Implementation Guide

```javascript
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const chokidar = require('chokidar');

class FileWatcherMasterclass {
  // 1. Native fs.watch Implementation
  static nativeFileWatching() {
    console.log('=== Native fs.watch Implementation ===');
    
    class NativeFileWatcher extends EventEmitter {
      constructor(options = {}) {
        super();
        this.options = {
          persistent: true,
          recursive: false,
          encoding: 'utf8',
          ...options
        };
        
        this.watchers = new Map();
        this.debounceTimers = new Map();
        this.statsCache = new Map();
      }
      
      watch(filePath, options = {}) {
        const fullPath = path.resolve(filePath);
        const watchOptions = { ...this.options, ...options };
        
        // Check if already watching
        if (this.watchers.has(fullPath)) {
          return this.watchers.get(fullPath);
        }
        
        try {
          // Get initial stats
          const stats = fs.statSync(fullPath);
          this.statsCache.set(fullPath, {
            mtime: stats.mtime.getTime(),
            size: stats.size,
            ino: stats.ino
          });
          
          // Create watcher
          const watcher = fs.watch(fullPath, watchOptions, (eventType, filename) => {
            this.handleChange(fullPath, eventType, filename);
          });
          
          // Store watcher
          this.watchers.set(fullPath, watcher);
          
          // Handle watcher errors
          watcher.on('error', (error) => {
            this.emit('error', { path: fullPath, error });
          });
          
          console.log(`Watching: ${fullPath}`);
          this.emit('watching', fullPath);
          
          return watcher;
          
        } catch (error) {
          this.emit('error', { path: fullPath, error });
          throw error;
        }
      }
      
      watchDirectory(dirPath, options = {}) {
        const fullPath = path.resolve(dirPath);
        const watchOptions = {
          ...this.options,
          recursive: options.recursive !== false,
          ...options
        };
        
        try {
          // Get initial directory state
          this.scanDirectory(fullPath, options.recursive);
          
          // Watch directory
          const watcher = fs.watch(fullPath, watchOptions, (eventType, filename) => {
            if (filename) {
              const filePath = path.join(fullPath, filename);
              this.handleChange(filePath, eventType, filename);
            }
          });
          
          this.watchers.set(fullPath, watcher);
          
          watcher.on('error', (error) => {
            this.emit('error', { path: fullPath, error });
          });
          
          console.log(`Watching directory: ${fullPath}`);
          this.emit('watching', fullPath);
          
          return watcher;
          
        } catch (error) {
          this.emit('error', { path: fullPath, error });
          throw error;
        }
      }
      
      scanDirectory(dirPath, recursive = true) {
        const files = fs.readdirSync(dirPath, { withFileTypes: true });
        
        for (const dirent of files) {
          const fullPath = path.join(dirPath, dirent.name);
          
          if (dirent.isDirectory() && recursive) {
            this.scanDirectory(fullPath, recursive);
          } else if (dirent.isFile()) {
            try {
              const stats = fs.statSync(fullPath);
              this.statsCache.set(fullPath, {
                mtime: stats.mtime.getTime(),
                size: stats.size,
                ino: stats.ino
              });
            } catch (error) {
              // Ignore permission errors
            }
          }
        }
      }
      
      handleChange(filePath, eventType, filename) {
        // Debounce rapid changes
        if (this.debounceTimers.has(filePath)) {
          clearTimeout(this.debounceTimers.get(filePath));
        }
        
        const timer = setTimeout(() => {
          this.processChange(filePath, eventType, filename);
          this.debounceTimers.delete(filePath);
        }, 100);
        
        this.debounceTimers.set(filePath, timer);
      }
      
      async processChange(filePath, eventType, filename) {
        try {
          const stats = await fs.promises.stat(filePath).catch(() => null);
          const oldStats = this.statsCache.get(filePath);
          
          // Determine change type
          let changeType = 'unknown';
          
          if (!stats && oldStats) {
            // File deleted
            changeType = 'delete';
            this.statsCache.delete(filePath);
          } else if (stats && !oldStats) {
            // File created
            changeType = 'create';
            this.statsCache.set(filePath, {
              mtime: stats.mtime.getTime(),
              size: stats.size,
              ino: stats.ino
            });
          } else if (stats && oldStats) {
            // File modified
            if (stats.mtime.getTime() !== oldStats.mtime) {
              changeType = 'modify';
              this.statsCache.set(filePath, {
                mtime: stats.mtime.getTime(),
                size: stats.size,
                ino: stats.ino
              });
            } else if (stats.size !== oldStats.size) {
              changeType = 'resize';
              this.statsCache.set(filePath, {
                mtime: stats.mtime.getTime(),
                size: stats.size,
                ino: stats.ino
              });
            } else {
              // No meaningful change
              return;
            }
          }
          
          // Emit event
          this.emit('change', {
            path: filePath,
            type: changeType,
            event: eventType,
            filename,
            stats,
            timestamp: new Date()
          });
          
          // Emit specific events
          if (changeType === 'create') {
            this.emit('create', filePath, stats);
          } else if (changeType === 'modify') {
            this.emit('modify', filePath, stats);
          } else if (changeType === 'delete') {
            this.emit('delete', filePath);
          }
          
        } catch (error) {
          this.emit('error', { path: filePath, error });
        }
      }
      
      unwatch(filePath) {
        const fullPath = path.resolve(filePath);
        
        if (this.watchers.has(fullPath)) {
          const watcher = this.watchers.get(fullPath);
          watcher.close();
          this.watchers.delete(fullPath);
          this.statsCache.delete(fullPath);
          
          console.log(`Stopped watching: ${fullPath}`);
          this.emit('unwatching', fullPath);
        }
      }
      
      close() {
        for (const [path, watcher] of this.watchers) {
          watcher.close();
        }
        
        this.watchers.clear();
        this.statsCache.clear();
        
        for (const timer of this.debounceTimers.values()) {
          clearTimeout(timer);
        }
        
        this.debounceTimers.clear();
        
        console.log('All watchers closed');
        this.emit('close');
      }
      
      getWatchedPaths() {
        return Array.from(this.watchers.keys());
      }
    }
    
    return NativeFileWatcher;
  }

  // 2. Advanced File Watcher with Chokidar
  static advancedChokidarWatcher() {
    console.log('\n=== Advanced Chokidar Implementation ===');
    
    class AdvancedFileWatcher extends EventEmitter {
      constructor(options = {}) {
        super();
        
        this.options = {
          persistent: true,
          ignoreInitial: true,
          followSymlinks: true,
          usePolling: false,
          interval: 100,
          binaryInterval: 300,
          alwaysStat: true,
          depth: 99,
          awaitWriteFinish: {
            stabilityThreshold: 2000,
            pollInterval: 100
          },
          ignorePermissionErrors: true,
          atomic: true,
          ...options
        };
        
        this.watchers = new Map();
        this.debounceTimers = new Map();
        this.renameTimers = new Map();
        this.pendingEvents = new Map();
        
        this.setupEventHandlers();
      }
      
      setupEventHandlers() {
        // Track rename events (common in editors)
        this.on('change', (event) => {
          if (event.type === 'delete') {
            // Might be a rename, wait to see if a create follows
            this.pendingEvents.set(event.path, {
              type: 'delete',
              timestamp: Date.now(),
              event
            });
            
            // Clear after timeout
            setTimeout(() => {
              this.pendingEvents.delete(event.path);
            }, 500);
          } else if (event.type === 'create') {
            // Check if this might be a rename
            const pendingDelete = Array.from(this.pendingEvents.values())
              .find(e => e.type === 'delete' && 
                Date.now() - e.timestamp < 500);
            
            if (pendingDelete) {
              // Likely a rename
              this.emit('rename', {
                from: pendingDelete.event.path,
                to: event.path,
                timestamp: new Date()
              });
              
              this.pendingEvents.delete(pendingDelete.event.path);
            }
          }
        });
      }
      
      watch(paths, options = {}) {
        const watchOptions = { ...this.options, ...options };
        const normalizedPaths = Array.isArray(paths) ? paths : [paths];
        
        // Create chokidar watcher
        const watcher = chokidar.watch(normalizedPaths, watchOptions);
        
        // Setup event handlers
        watcher
          .on('add', (path, stats) => this.handleEvent('add', path, stats))
          .on('change', (path, stats) => this.handleEvent('change', path, stats))
          .on('unlink', (path) => this.handleEvent('unlink', path))
          .on('addDir', (path, stats) => this.handleEvent('addDir', path, stats))
          .on('unlinkDir', (path) => this.handleEvent('unlinkDir', path))
          .on('error', (error) => this.emit('error', error))
          .on('ready', () => this.emit('ready'));
        
        // Store watcher
        const id = Date.now() + Math.random();
        this.watchers.set(id, watcher);
        
        console.log(`Watching ${normalizedPaths.length} path(s)`);
        this.emit('watching', normalizedPaths);
        
        return {
          id,
          close: () => this.unwatch(id),
          getWatched: () => watcher.getWatched()
        };
      }
      
      handleEvent(eventName, path, stats = null) {
        // Debounce rapid events
        const key = `${eventName}:${path}`;
        
        if (this.debounceTimers.has(key)) {
          clearTimeout(this.debounceTimers.get(key));
        }
        
        const timer = setTimeout(() => {
          // Process event
          this.processEvent(eventName, path, stats);
          this.debounceTimers.delete(key);
        }, this.getDebounceTime(eventName));
        
        this.debounceTimers.set(key, timer);
      }
      
      getDebounceTime(eventName) {
        // Different debounce times for different events
        const debounceTimes = {
          add: 100,
          change: 50,
          unlink: 100,
          addDir: 100,
          unlinkDir: 100
        };
        
        return debounceTimes[eventName] || 100;
      }
      
      processEvent(eventName, path, stats) {
        const event = {
          type: eventName,
          path,
          stats,
          timestamp: new Date()
        };
        
        // Emit generic change event
        this.emit('change', event);
        
        // Emit specific event
        this.emit(eventName, path, stats);
        
        // Log for debugging
        if (this.options.verbose) {
          console.log(`[${eventName.toUpperCase()}] ${path}`, 
            stats ? `(${stats.size} bytes)` : '');
        }
        
        // Additional processing based on file type
        if (stats && stats.isFile()) {
          this.processFileEvent(eventName, path, stats);
        }
      }
      
      processFileEvent(eventName, path, stats) {
        const ext = path.extname(path).toLowerCase();
        
        // Handle different file types
        if (['.js', '.ts', '.jsx', '.tsx'].includes(ext)) {
          this.emit('source.change', { path, stats, eventName });
        } else if (['.css', '.scss', '.less'].includes(ext)) {
          this.emit('style.change', { path, stats, eventName });
        } else if (['.html', '.ejs', '.pug'].includes(ext)) {
          this.emit('template.change', { path, stats, eventName });
        } else if (['.json', '.yaml', '.yml'].includes(ext)) {
          this.emit('config.change', { path, stats, eventName });
        }
        
        // Check file size changes
        const oldSize = this.getFileSize(path);
        if (oldSize !== null && oldSize !== stats.size) {
          this.emit('size.change', {
            path,
            oldSize,
            newSize: stats.size,
            difference: stats.size - oldSize
          });
        }
        
        this.updateFileSize(path, stats.size);
      }
      
      getFileSize(path) {
        return this.fileSizes ? this.fileSizes.get(path) : null;
      }
      
      updateFileSize(path, size) {
        if (!this.fileSizes) {
          this.fileSizes = new Map();
        }
        this.fileSizes.set(path, size);
      }
      
      unwatch(id) {
        if (this.watchers.has(id)) {
          const watcher = this.watchers.get(id);
          watcher.close();
          this.watchers.delete(id);
          
          console.log(`Stopped watcher ${id}`);
          this.emit('unwatching', id);
        }
      }
      
      async close() {
        // Close all watchers
        for (const [id, watcher] of this.watchers) {
          await watcher.close();
        }
        
        this.watchers.clear();
        
        // Clear timers
        for (const timer of this.debounceTimers.values()) {
          clearTimeout(timer);
        }
        
        this.debounceTimers.clear();
        
        console.log('All watchers closed');
        this.emit('close');
      }
      
      // Utility methods
      async getFileContent(path, encoding = 'utf8') {
        try {
          return await fs.promises.readFile(path, encoding);
        } catch (error) {
          this.emit('read.error', { path, error });
          return null;
        }
      }
      
      async getFileHash(path) {
        const crypto = require('crypto');
        
        try {
          const content = await this.getFileContent(path, 'binary');
          if (!content) return null;
          
          return crypto.createHash('md5').update(content).digest('hex');
        } catch (error) {
          return null;
        }
      }
    }
    
    return AdvancedFileWatcher;
  }

  // 3. Real-world Example: Development Server with Hot Reload
  static createDevServer() {
    console.log('\n=== Development Server with Hot Reload ===');
    
    class DevServer extends EventEmitter {
      constructor(options = {}) {
        super();
        
        this.options = {
          port: 3000,
          watchPaths: ['.'],
          ignorePaths: ['node_modules', '.git', 'dist', 'build'],
          extensions: ['.js', '.jsx', '.ts', '.tsx', '.json', '.css', '.scss'],
          pollInterval: 100,
          hotReload: true,
          liveReload: true,
          ...options
        };
        
        this.watcher = null;
        this.server = null;
        this.clients = new Set();
        this.fileHashes = new Map();
        this.pendingReloads = new Map();
        
        this.setupWebSocketServer();
        this.setupFileWatcher();
      }
      
      setupWebSocketServer() {
        const WebSocket = require('ws');
        
        this.wss = new WebSocket.Server({ noServer: true });
        
        this.wss.on('connection', (ws) => {
          this.clients.add(ws);
          
          ws.on('close', () => {
            this.clients.delete(ws);
          });
          
          ws.on('error', (error) => {
            console.error('WebSocket error:', error);
          });
          
          // Send initial connection message
          ws.send(JSON.stringify({
            type: 'connected',
            timestamp: new Date().toISOString()
          }));
        });
      }
      
      setupFileWatcher() {
        const watcherClass = this.advancedChokidarWatcher();
        this.watcher = new watcherClass({
          ignored: this.options.ignorePaths,
          ignoreInitial: true,
          persistent: true,
          usePolling: this.options.usePolling,
          interval: this.options.pollInterval,
          awaitWriteFinish: {
            stabilityThreshold: 2000,
            pollInterval: 100
          }
        });
        
        // Watch specified paths
        const watchHandle = this.watcher.watch(this.options.watchPaths);
        
        // Handle file changes
        this.watcher.on('change', async (event) => {
          const { path, type, stats } = event;
          
          // Check file extension
          const ext = path.extname(path).toLowerCase();
          if (!this.options.extensions.includes(ext)) {
            return;
          }
          
          console.log(`File ${type}: ${path}`);
          
          // Handle based on file type
          if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
            await this.handleSourceChange(path, type, stats);
          } else if (['.css', '.scss', '.less'].includes(ext)) {
            await this.handleStyleChange(path, type, stats);
          } else if (['.html'].includes(ext)) {
            await this.handleHtmlChange(path, type, stats);
          } else if (['.json'].includes(ext)) {
            await this.handleConfigChange(path, type, stats);
          }
        });
        
        this.watcher.on('error', (error) => {
          console.error('File watcher error:', error);
        });
      }
      
      async handleSourceChange(path, type, stats) {
        if (this.options.hotReload) {
          // Check if file content actually changed
          const newHash = await this.watcher.getFileHash(path);
          const oldHash = this.fileHashes.get(path);
          
          if (newHash && newHash !== oldHash) {
            this.fileHashes.set(path, newHash);
            
            // Read file content
            const content = await this.watcher.getFileContent(path);
            
            // Notify clients about module change
            this.broadcast({
              type: 'hot-update',
              file: path,
              content: content ? content.slice(0, 1000) : null, // Send partial content
              timestamp: new Date().toISOString()
            });
            
            console.log(`Hot update sent for: ${path}`);
          }
        } else if (this.options.liveReload) {
          this.scheduleLiveReload();
        }
      }
      
      async handleStyleChange(path, type, stats) {
        if (this.options.liveReload) {
          this.scheduleLiveReload();
        }
        
        // Also send CSS update for hot reload
        if (this.options.hotReload) {
          this.broadcast({
            type: 'css-update',
            file: path,
            timestamp: new Date().toISOString()
          });
        }
      }
      
      async handleHtmlChange(path, type, stats) {
        // Always reload for HTML changes
        this.scheduleLiveReload();
      }
      
      async handleConfigChange(path, type, stats) {
        // Restart server on config changes
        if (path.includes('package.json') || path.includes('config.')) {
          console.log('Config file changed, restarting server...');
          this.restartServer();
        }
      }
      
      scheduleLiveReload() {
        // Debounce multiple changes
        if (this.pendingReloads.has('live-reload')) {
          clearTimeout(this.pendingReloads.get('live-reload'));
        }
        
        const timer = setTimeout(() => {
          this.broadcast({
            type: 'live-reload',
            timestamp: new Date().toISOString()
          });
          
          console.log('Live reload triggered');
          this.pendingReloads.delete('live-reload');
        }, 300);
        
        this.pendingReloads.set('live-reload', timer);
      }
      
      broadcast(message) {
        const data = JSON.stringify(message);
        
        for (const client of this.clients) {
          if (client.readyState === 1) { // WebSocket.OPEN
            client.send(data);
          }
        }
      }
      
      async start() {
        const http = require('http');
        const fs = require('fs');
        const path = require('path');
        
        // Create HTTP server
        this.server = http.createServer(async (req, res) => {
          // Handle WebSocket upgrade
          if (req.url === '/_ws' && req.headers.upgrade === 'websocket') {
            this.wss.handleUpgrade(req, req.socket, Buffer.alloc(0), (ws) => {
              this.wss.emit('connection', ws, req);
            });
            return;
          }
          
          // Serve hot reload client script
          if (req.url === '/_hot-reload.js') {
            res.writeHead(200, { 'Content-Type': 'application/javascript' });
            res.end(this.getHotReloadClientScript());
            return;
          }
          
          // Default request handling
          try {
            await this.handleRequest(req, res);
          } catch (error) {
            console.error('Request error:', error);
            res.writeHead(500);
            res.end('Internal server error');
          }
        });
        
        // Upgrade HTTP server to handle WebSockets
        this.server.on('upgrade', (req, socket, head) => {
          if (req.url === '/_ws') {
            this.wss.handleUpgrade(req, socket, head, (ws) => {
              this.wss.emit('connection', ws, req);
            });
          } else {
            socket.destroy();
          }
        });
        
        // Start server
        this.server.listen(this.options.port, () => {
          console.log(`Dev server listening on http://localhost:${this.options.port}`);
          console.log('Hot reload enabled:', this.options.hotReload);
          console.log('Live reload enabled:', this.options.liveReload);
        });
      }
      
      getHotReloadClientScript() {
        return `
          (function() {
            const socket = new WebSocket('ws://' + window.location.host + '/_ws');
            
            socket.onmessage = function(event) {
              const message = JSON.parse(event.data);
              
              switch (message.type) {
                case 'hot-update':
                  console.log('Hot update received for:', message.file);
                  
                  // For CSS files, update the link
                  if (message.file.endsWith('.css')) {
                    const links = document.querySelectorAll('link[rel="stylesheet"]');
                    links.forEach(link => {
                      const url = new URL(link.href);
                      url.searchParams.set('t', Date.now());
                      link.href = url.toString();
                    });
                  }
                  break;
                  
                case 'live-reload':
                  console.log('Live reload triggered');
                  window.location.reload();
                  break;
                  
                case 'css-update':
                  // Update CSS without page reload
                  const links = document.querySelectorAll('link[rel="stylesheet"]');
                  links.forEach(link => {
                    const url = new URL(link.href);
                    url.searchParams.set('t', Date.now());
                    link.href = url.toString();
                  });
                  break;
              }
            };
            
            socket.onclose = function() {
              console.log('Dev server disconnected');
            };
            
            socket.onerror = function(error) {
              console.error('WebSocket error:', error);
            };
          })();
        `;
      }
      
      async handleRequest(req, res) {
        // Simple static file server for development
        const filePath = path.join(process.cwd(), req.url === '/' ? 'index.html' : req.url);
        
        try {
          const stats = await fs.promises.stat(filePath);
          
          if (stats.isDirectory()) {
            // Serve directory listing
            const files = await fs.promises.readdir(filePath);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <head><title>Directory: ${req.url}</title></head>
                <body>
                  <h1>Directory: ${req.url}</h1>
                  <ul>
                    ${files.map(file => `<li><a href="${path.join(req.url, file)}">${file}</a></li>`).join('')}
                  </ul>
                  <script src="/_hot-reload.js"></script>
                </body>
              </html>
            `);
          } else if (stats.isFile()) {
            // Serve file with hot reload script injection for HTML
            const ext = path.extname(filePath).toLowerCase();
            const contentType = this.getContentType(ext);
            
            let content = await fs.promises.readFile(filePath, 'utf8');
            
            // Inject hot reload script for HTML files
            if (ext === '.html' && this.options.hotReload) {
              content = content.replace(
                '</body>',
                '<script src="/_hot-reload.js"></script></body>'
              );
            }
            
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
          }
        } catch (error) {
          if (error.code === 'ENOENT') {
            res.writeHead(404);
            res.end('File not found');
          } else {
            res.writeHead(500);
            res.end('Internal server error');
          }
        }
      }
      
      getContentType(ext) {
        const contentTypes = {
          '.html': 'text/html',
          '.css': 'text/css',
          '.js': 'application/javascript',
          '.json': 'application/json',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.gif': 'image/gif',
          '.svg': 'image/svg+xml',
          '.txt': 'text/plain'
        };
        
        return contentTypes[ext] || 'application/octet-stream';
      }
      
      restartServer() {
        console.log('Restarting server...');
        
        // Close existing server
        if (this.server) {
          this.server.close(() => {
            console.log('Server closed');
            this.start();
          });
        }
      }
      
      async stop() {
        // Close WebSocket server
        if (this.wss) {
          this.wss.close();
        }
        
        // Close file watcher
        if (this.watcher) {
          await this.watcher.close();
        }
        
        // Close HTTP server
        if (this.server) {
          await new Promise(resolve => {
            this.server.close(resolve);
          });
        }
        
        console.log('Dev server stopped');
      }
    }
    
    return DevServer;
  }

  // 4. File System Monitoring with Performance Metrics
  static createPerformanceMonitor() {
    console.log('\n=== File System Performance Monitor ===');
    
    class PerformanceMonitor extends EventEmitter {
      constructor(options = {}) {
        super();
        
        this.options = {
          sampleInterval: 5000,
          historySize: 100,
          thresholds: {
            cpu: 80,
            memory: 80,
            disk: 90,
            inotify: 10000
          },
          ...options
        };
        
        this.metrics = {
          cpu: [],
          memory: [],
          disk: [],
          fileEvents: [],
          watchers: []
        };
        
        this.eventCount = 0;
        this.startTime = Date.now();
        
        this.setupMonitoring();
      }
      
      setupMonitoring() {
        // Monitor system resources
        this.monitorSystemResources();
        
        // Monitor file system events
        this.monitorFileSystem();
        
        // Monitor inotify limits (Linux)
        this.monitorInotify();
      }
      
      monitorSystemResources() {
        setInterval(() => {
          const cpuUsage = process.cpuUsage();
          const memoryUsage = process.memoryUsage();
          const diskUsage = this.getDiskUsage();
          
          const metrics = {
            timestamp: Date.now(),
            cpu: {
              user: cpuUsage.user / 1000000, // Convert to seconds
              system: cpuUsage.system / 1000000
            },
            memory: {
              rss: memoryUsage.rss / 1024 / 1024, // MB
              heapUsed: memoryUsage.heapUsed / 1024 / 1024,
              heapTotal: memoryUsage.heapTotal / 1024 / 1024
            },
            disk: diskUsage
          };
          
          // Store metrics
          this.addMetric('cpu', metrics.cpu);
          this.addMetric('memory', metrics.memory);
          this.addMetric('disk', metrics.disk);
          
          // Check thresholds
          this.checkThresholds(metrics);
          
          // Emit metrics
          this.emit('metrics', metrics);
          
        }, this.options.sampleInterval);
      }
      
      getDiskUsage() {
        try {
          const fs = require('fs');
          const os = require('os');
          
          const stats = fs.statfsSync(os.homedir());
          const total = stats.blocks * stats.bsize;
          const free = stats.bfree * stats.bsize;
          const used = total - free;
          
          return {
            total: total / 1024 / 1024 / 1024, // GB
            used: used / 1024 / 1024 / 1024,
            free: free / 1024 / 1024 / 1024,
            percentage: (used / total) * 100
          };
        } catch (error) {
          return null;
        }
      }
      
      monitorFileSystem() {
        // Track file system events
        this.on('file.event', (event) => {
          this.eventCount++;
          
          const eventMetric = {
            timestamp: Date.now(),
            type: event.type,
            path: event.path,
            size: event.stats ? event.stats.size : 0
          };
          
          this.addMetric('fileEvents', eventMetric);
          
          // Track event rate
          const now = Date.now();
          const windowStart = now - 60000; // 1 minute window
          
          // Remove old events
          this.metrics.fileEvents = this.metrics.fileEvents.filter(
            e => e.timestamp > windowStart
          );
          
          const eventsPerMinute = this.metrics.fileEvents.length;
          
          if (eventsPerMinute > this.options.thresholds.inotify) {
            this.emit('warning', {
              type: 'high_event_rate',
              message: `High file event rate: ${eventsPerMinute} events/minute`,
              value: eventsPerMinute,
              threshold: this.options.thresholds.inotify
            });
          }
        });
      }
      
      monitorInotify() {
        // Linux-specific inotify monitoring
        if (process.platform === 'linux') {
          setInterval(() => {
            try {
              const fs = require('fs');
              const content = fs.readFileSync('/proc/sys/fs/inotify/max_user_watches', 'utf8');
              const maxWatches = parseInt(content.trim());
              
              // Estimate current watches (this is approximate)
              const currentWatches = this.estimateInotifyWatches();
              const usagePercentage = (currentWatches / maxWatches) * 100;
              
              this.emit('inotify', {
                maxWatches,
                currentWatches,
                usagePercentage
              });
              
              if (usagePercentage > 80) {
                this.emit('warning', {
                  type: 'inotify_limit',
                  message: `High inotify usage: ${usagePercentage.toFixed(1)}%`,
                  value: usagePercentage
                });
              }
              
            } catch (error) {
              // /proc file not available
            }
          }, 10000);
        }
      }
      
      estimateInotifyWatches() {
        // This is a rough estimate
        // In production, you'd need more sophisticated tracking
        return this.metrics.watchers.reduce((sum, w) => sum + w.estimate, 0);
      }
      
      addMetric(type, value) {
        if (!this.metrics[type]) {
          this.metrics[type] = [];
        }
        
        this.metrics[type].push({
          timestamp: Date.now(),
          value
        });
        
        // Keep only recent history
        if (this.metrics[type].length > this.options.historySize) {
          this.metrics[type].shift();
        }
      }
      
      checkThresholds(metrics) {
        // Check CPU threshold
        const cpuTotal = metrics.cpu.user + metrics.cpu.system;
        if (cpuTotal > this.options.thresholds.cpu) {
          this.emit('warning', {
            type: 'high_cpu',
            message: `High CPU usage: ${cpuTotal.toFixed(1)}%`,
            value: cpuTotal,
            threshold: this.options.thresholds.cpu
          });
        }
        
        // Check memory threshold
        const memoryPercentage = (metrics.memory.heapUsed / metrics.memory.heapTotal) * 100;
        if (memoryPercentage > this.options.thresholds.memory) {
          this.emit('warning', {
            type: 'high_memory',
            message: `High memory usage: ${memoryPercentage.toFixed(1)}%`,
            value: memoryPercentage,
            threshold: this.options.thresholds.memory
          });
        }
        
        // Check disk threshold
        if (metrics.disk && metrics.disk.percentage > this.options.thresholds.disk) {
          this.emit('warning', {
            type: 'high_disk',
            message: `High disk usage: ${metrics.disk.percentage.toFixed(1)}%`,
            value: metrics.disk.percentage,
            threshold: this.options.thresholds.disk
          });
        }
      }
      
      getPerformanceReport() {
        const now = Date.now();
        const uptime = (now - this.startTime) / 1000;
        
        // Calculate averages
        const cpuAvg = this.calculateAverage('cpu');
        const memoryAvg = this.calculateAverage('memory');
        const diskAvg = this.calculateAverage('disk');
        
        return {
          uptime: `${uptime.toFixed(0)}s`,
          totalEvents: this.eventCount,
          eventRate: `${(this.eventCount / uptime).toFixed(1)} events/second`,
          averages: {
            cpu: cpuAvg,
            memory: memoryAvg,
            disk: diskAvg
          },
          current: {
            cpu: this.metrics.cpu[this.metrics.cpu.length - 1],
            memory: this.metrics.memory[this.metrics.memory.length - 1],
            disk: this.metrics.disk[this.metrics.disk.length - 1]
          }
        };
      }
      
      calculateAverage(type) {
        const metrics = this.metrics[type];
        if (!metrics || metrics.length === 0) return null;
        
        if (type === 'cpu') {
          const total = metrics.reduce((sum, m) => sum + m.value.user + m.value.system, 0);
          return total / metrics.length;
        } else if (type === 'memory') {
          const heapUsed = metrics.reduce((sum, m) => sum + m.value.heapUsed, 0);
          const heapTotal = metrics.reduce((sum, m) => sum + m.value.heapTotal, 0);
          return {
            heapUsed: heapUsed / metrics.length,
            heapTotal: heapTotal / metrics.length,
            percentage: (heapUsed / heapTotal) * 100
          };
        } else if (type === 'disk' && metrics[0].value) {
          const percentage = metrics.reduce((sum, m) => sum + m.value.percentage, 0);
          return percentage / metrics.length;
        }
        
        return null;
      }
      
      registerWatcher(watcher, estimate) {
        this.metrics.watchers.push({
          watcher,
          estimate,
          registered: Date.now()
        });
      }
      
      unregisterWatcher(watcher) {
        this.metrics.watchers = this.metrics.watchers.filter(w => w.watcher !== watcher);
      }
    }
    
    return PerformanceMonitor;
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What are the differences between fs.watch, fs.watchFile, and chokidar? When would you use each?"
2. "How does inotify work on Linux and what are its limitations?"
3. "Explain the challenges of file watching on networked drives or virtual file systems."

**Scenario-Based Questions:**
1. "Your file watcher is missing changes when files are saved rapidly. How would you implement debouncing and change detection?"
2. "Users report that file watching stops working after watching many directories. How would you diagnose and fix inotify limits?"
3. "You need to watch files in a Docker container from the host. What are the challenges and solutions?"

**Real-World Challenge:**
> "Design a production-grade file synchronization service that: 1) Watches for file changes in real-time, 2) Handles conflicts when multiple clients modify the same file, 3) Compresses and encrypts files for transfer, 4) Maintains file version history, 5) Works across different operating systems and file systems, 6) Provides real-time synchronization status and error reporting."

---

## 📊 Performance Comparison Table

| Feature | Native fs.watch | Chokidar | Custom Implementation |
|---------|----------------|----------|---------------------|
| Cross-platform | Good | Excellent | Variable |
| Recursive watching | Limited | Excellent | Customizable |
| Performance | Good | Excellent | Depends on implementation |
| Event accuracy | Variable | Good | Customizable |
| Memory usage | Low | Moderate | Depends on implementation |
| Debouncing | Manual | Built-in | Customizable |
| Rename detection | Manual | Built-in | Customizable |

---

## 🎓 Interview Preparation Tips

1. **Understand the fundamentals**: Know how each concept works at a low level
2. **Practice implementation**: Try building your own versions of these systems
3. **Study trade-offs**: Understand when to use which approach based on requirements
4. **Monitor performance**: Learn to measure and optimize system performance
5. **Stay updated**: Follow Node.js releases and new features in these areas

---
