# System Design for Node.js Developers

## 📖 Table of Contents
1. [Load Balancing](#1-load-balancing)
2. [Horizontal vs Vertical Scaling](#2-horizontal-vs-vertical-scaling)
3. [Cache Layers](#3-cache-layers)
4. [CDN Usage](#4-cdn-usage)
5. [Database Sharding](#5-database-sharding)
6. [Indexing & Query Optimization](#6-indexing--query-optimization)
7. [Rate Limiting Strategies](#7-rate-limiting-strategies)
8. [Queues & Async Processing](#8-queues--async-processing)
9. [API Gateway Design](#9-api-gateway-design)
10. [High Availability Architecture](#10-high-availability-architecture)
11. [Interview Questions](#11-interview-questions)

---

## 1. Load Balancing

### In-Depth Explanation
Load balancing distributes incoming network traffic across multiple servers to ensure no single server bears too much demand. This improves responsiveness, increases availability, and prevents server overload.

### Types of Load Balancing Algorithms

**1. Round Robin (Default)**
```javascript
class RoundRobinBalancer {
  constructor(servers) {
    this.servers = servers;
    this.index = 0;
  }

  getNextServer() {
    const server = this.servers[this.index];
    this.index = (this.index + 1) % this.servers.length;
    return server;
  }
}
```

**2. Least Connections**
```javascript
class LeastConnectionsBalancer {
  constructor(servers) {
    this.servers = servers.map(s => ({
      ...s,
      connections: 0
    }));
  }

  getNextServer() {
    return this.servers.reduce((prev, curr) => 
      prev.connections < curr.connections ? prev : curr
    );
  }

  releaseConnection(server) {
    server.connections = Math.max(0, server.connections - 1);
  }
}
```

**3. Weighted Round Robin**
```javascript
class WeightedRoundRobinBalancer {
  constructor(servers) {
    this.servers = servers;
    this.currentWeight = 0;
    this.gcd = this.calculateGCD();
    this.maxWeight = Math.max(...servers.map(s => s.weight));
  }

  calculateGCD() {
    const weights = this.servers.map(s => s.weight);
    let result = weights[0];
    for (let i = 1; i < weights.length; i++) {
      result = this.gcdTwoNumbers(result, weights[i]);
    }
    return result;
  }

  gcdTwoNumbers(a, b) {
    while (b) {
      const t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  getNextServer() {
    while (true) {
      this.currentWeight = (this.currentWeight + this.gcd) % this.maxWeight;
      
      for (const server of this.servers) {
        if (server.weight >= this.currentWeight) {
          return server;
        }
      }
    }
  }
}
```

**4. IP Hash (Sticky Sessions)**
```javascript
class IPHashBalancer {
  constructor(servers) {
    this.servers = servers;
  }

  hashIP(ip) {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      hash = ((hash << 5) - hash) + ip.charCodeAt(i);
      hash |= 0; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  getNextServer(ip) {
    const hash = this.hashIP(ip);
    const index = hash % this.servers.length;
    return this.servers[index];
  }
}
```

### Implementation with Health Checks

```javascript
const axios = require('axios');

class LoadBalancerWithHealthChecks {
  constructor(servers) {
    this.servers = servers.map(server => ({
      ...server,
      healthy: true,
      failures: 0,
      lastChecked: null,
      responseTime: null
    }));
    this.healthCheckInterval = 10000; // 10 seconds
    this.failureThreshold = 3;
    this.startHealthChecks();
  }

  async performHealthCheck(server) {
    const startTime = Date.now();
    try {
      const response = await axios.get(`${server.url}/health`, {
        timeout: 5000
      });
      
      server.responseTime = Date.now() - startTime;
      
      if (response.status === 200) {
        server.healthy = true;
        server.failures = 0;
        console.log(`✅ Server ${server.url} is healthy (${server.responseTime}ms)`);
      } else {
        this.handleFailure(server);
      }
    } catch (error) {
      this.handleFailure(server);
    }
    
    server.lastChecked = new Date();
  }

  handleFailure(server) {
    server.failures++;
    if (server.failures >= this.failureThreshold) {
      server.healthy = false;
      console.log(`❌ Server ${server.url} marked as unhealthy`);
    }
  }

  startHealthChecks() {
    setInterval(() => {
      this.servers.forEach(server => {
        this.performHealthCheck(server);
      });
    }, this.healthCheckInterval);
  }

  getHealthyServers() {
    return this.servers.filter(server => server.healthy);
  }

  getNextServerLeastResponseTime() {
    const healthyServers = this.getHealthyServers();
    if (healthyServers.length === 0) {
      throw new Error('No healthy servers available');
    }
    
    return healthyServers.reduce((prev, curr) => 
      (prev.responseTime || Infinity) < (curr.responseTime || Infinity) ? prev : curr
    );
  }
}

// Usage
const lb = new LoadBalancerWithHealthChecks([
  { url: 'http://server1:3000', weight: 3 },
  { url: 'http://server2:3000', weight: 2 },
  { url: 'http://server3:3000', weight: 1 }
]);

// Express middleware for load balancing
const loadBalancerMiddleware = (req, res, next) => {
  try {
    const targetServer = lb.getNextServerLeastResponseTime();
    req.targetServer = targetServer;
    next();
  } catch (error) {
    res.status(503).json({ error: 'Service unavailable' });
  }
};

// Proxy request to target server
const proxyMiddleware = async (req, res) => {
  const { targetServer } = req;
  
  try {
    const response = await axios({
      method: req.method,
      url: `${targetServer.url}${req.originalUrl}`,
      data: req.body,
      headers: req.headers,
      timeout: 30000
    });
    
    res.status(response.status).json(response.data);
  } catch (error) {
    console.error(`Proxy error for ${targetServer.url}:`, error.message);
    res.status(502).json({ error: 'Bad gateway' });
  }
};
```

### Layer 4 vs Layer 7 Load Balancing

```javascript
// Layer 4 (Transport Layer) - TCP/UDP
// Pros: Faster, simpler
// Cons: No application awareness

// Layer 7 (Application Layer) - HTTP/HTTPS
// Pros: Smart routing, SSL termination, caching
// Cons: More overhead, slower

class Layer7LoadBalancer {
  constructor() {
    this.routes = new Map();
    this.setupRoutingRules();
  }

  setupRoutingRules() {
    // Path-based routing
    this.routes.set('/api/v1/users', ['server1', 'server2']);
    this.routes.set('/api/v1/orders', ['server3', 'server4']);
    
    // Header-based routing
    this.routes.set('mobile-client', ['server5', 'server6']);
    
    // Content-based routing
    this.routes.set('json-content', ['server7']);
    this.routes.set('xml-content', ['server8']);
  }

  routeRequest(req) {
    const path = req.path;
    const userAgent = req.headers['user-agent'];
    const contentType = req.headers['content-type'];
    
    // Path-based routing
    for (const [routePath, servers] of this.routes) {
      if (path.startsWith(routePath)) {
        return this.selectServer(servers);
      }
    }
    
    // Header-based routing
    if (userAgent?.includes('Mobile')) {
      return this.selectServer(this.routes.get('mobile-client'));
    }
    
    // Content-based routing
    if (contentType?.includes('application/json')) {
      return this.selectServer(this.routes.get('json-content'));
    }
    
    // Default routing
    return this.selectServer(['default-server1', 'default-server2']);
  }

  selectServer(servers) {
    // Implement selection algorithm
    return servers[0];
  }
}
```

---

## 2. Horizontal vs Vertical Scaling

### In-Depth Explanation

**Vertical Scaling (Scale Up)**
- Add more resources to existing server (CPU, RAM, Storage)
- **Pros**: Simpler, no code changes needed
- **Cons**: Single point of failure, hardware limits, costly

**Horizontal Scaling (Scale Out)**
- Add more servers to distribute load
- **Pros**: Fault tolerance, cost-effective, no downtime
- **Cons**: Complex architecture, requires load balancing

### Comparison Table

| Aspect | Vertical Scaling | Horizontal Scaling |
|--------|-----------------|-------------------|
| Cost | Expensive hardware | Commodity hardware |
| Limits | Hardware limits | Virtually unlimited |
| Downtime | Required for upgrades | Zero-downtime possible |
| Complexity | Low | High |
| Resilience | Single point of failure | High availability |
| Performance | Limited by single machine | Distributed workload |

### Implementation Patterns

**1. Vertical Scaling with PM2**
```javascript
// PM2 configuration for vertical scaling
module.exports = {
  apps: [{
    name: 'app',
    script: 'server.js',
    instances: 1, // Single instance
    exec_mode: 'fork',
    max_memory_restart: '4G', // Restart if memory exceeds 4GB
    node_args: '--max-old-space-size=4096', // 4GB heap
    env: {
      NODE_OPTIONS: '--max-old-space-size=4096'
    }
  }]
};
```

**2. Horizontal Scaling with Cluster Module**
```javascript
const cluster = require('cluster');
const os = require('os');
const express = require('express');

if (cluster.isMaster) {
  console.log(`Master ${process.pid} is running`);
  
  // Fork workers based on CPU cores
  const numCPUs = os.cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  // Handle worker events
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    console.log('Forking a new worker');
    cluster.fork();
  });
  
  // Load monitoring
  cluster.on('online', (worker) => {
    console.log(`Worker ${worker.process.pid} is online`);
  });
  
} else {
  // Worker process - create server
  const app = express();
  const PORT = process.env.PORT || 3000;
  
  // Shared state using Redis
  const redis = require('redis');
  const session = require('express-session');
  const RedisStore = require('connect-redis')(session);
  
  const redisClient = redis.createCluster({
    rootNodes: [
      { url: 'redis://redis1:6379' },
      { url: 'redis://redis2:6379' },
      { url: 'redis://redis3:6379' }
    ],
    useReplicas: true
  });
  
  app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: 'your-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true }
  }));
  
  // Stateless API endpoints
  app.get('/api/data', async (req, res) => {
    // All business logic here
    res.json({ worker: process.pid, data: 'response' });
  });
  
  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log(`Worker ${process.pid} shutting down`);
    server.close(() => {
      process.exit(0);
    });
  });
  
  const server = app.listen(PORT, () => {
    console.log(`Worker ${process.pid} listening on port ${PORT}`);
  });
}
```

**3. Auto-scaling Implementation**
```javascript
const AWS = require('aws-sdk');

class AutoScaler {
  constructor() {
    this.ec2 = new AWS.EC2();
    this.cloudWatch = new AWS.CloudWatch();
    this.asg = new AWS.AutoScaling();
    
    this.scalingConfig = {
      minInstances: 2,
      maxInstances: 10,
      targetCPU: 70,
      scaleOutThreshold: 80,
      scaleInThreshold: 30,
      cooldownPeriod: 300000 // 5 minutes
    };
    
    this.lastScalingTime = 0;
    this.monitoringInterval = 60000; // 1 minute
  }

  async startMonitoring() {
    setInterval(async () => {
      try {
        await this.evaluateScaling();
      } catch (error) {
        console.error('Scaling evaluation failed:', error);
      }
    }, this.monitoringInterval);
  }

  async evaluateScaling() {
    const now = Date.now();
    
    // Check cooldown period
    if (now - this.lastScalingTime < this.scalingConfig.cooldownPeriod) {
      console.log('In cooldown period, skipping evaluation');
      return;
    }

    // Get metrics
    const metrics = await this.getMetrics();
    const cpuUtilization = metrics.cpuUtilization;
    const requestRate = metrics.requestRate;
    const errorRate = metrics.errorRate;

    console.log(`Metrics - CPU: ${cpuUtilization}%, Requests: ${requestRate}/s, Errors: ${errorRate}%`);

    // Scale out conditions
    if (cpuUtilization > this.scalingConfig.scaleOutThreshold ||
        requestRate > 1000 || // 1000 requests per second
        errorRate > 5) { // 5% error rate
      await this.scaleOut();
      return;
    }

    // Scale in conditions
    if (cpuUtilization < this.scalingConfig.scaleInThreshold &&
        requestRate < 100 &&
        errorRate < 1) {
      await this.scaleIn();
    }
  }

  async getMetrics() {
    // Get CPU utilization
    const cpuParams = {
      Namespace: 'AWS/EC2',
      MetricName: 'CPUUtilization',
      Dimensions: [{ Name: 'AutoScalingGroupName', Value: 'my-asg' }],
      Statistics: ['Average'],
      Period: 300, // 5 minutes
      StartTime: new Date(Date.now() - 600000), // 10 minutes ago
      EndTime: new Date()
    };

    const cpuData = await this.cloudWatch.getMetricStatistics(cpuParams).promise();
    const cpuUtilization = cpuData.Datapoints[0]?.Average || 0;

    // Get application metrics from custom CloudWatch
    const requestParams = {
      Namespace: 'Custom/Application',
      MetricName: 'RequestRate',
      // ... similar parameters
    };

    return {
      cpuUtilization,
      requestRate: 500, // Mock data
      errorRate: 1.2 // Mock data
    };
  }

  async scaleOut() {
    console.log('Scaling out...');
    
    const currentCapacity = await this.getCurrentCapacity();
    
    if (currentCapacity >= this.scalingConfig.maxInstances) {
      console.log('Already at maximum capacity');
      return;
    }

    const newDesiredCapacity = Math.min(
      currentCapacity + 2,
      this.scalingConfig.maxInstances
    );

    await this.asg.setDesiredCapacity({
      AutoScalingGroupName: 'my-asg',
      DesiredCapacity: newDesiredCapacity,
      HonorCooldown: false
    }).promise();

    this.lastScalingTime = Date.now();
    console.log(`Scaled out to ${newDesiredCapacity} instances`);
  }

  async scaleIn() {
    console.log('Scaling in...');
    
    const currentCapacity = await this.getCurrentCapacity();
    
    if (currentCapacity <= this.scalingConfig.minInstances) {
      console.log('Already at minimum capacity');
      return;
    }

    const newDesiredCapacity = Math.max(
      currentCapacity - 1,
      this.scalingConfig.minInstances
    );

    await this.asg.setDesiredCapacity({
      AutoScalingGroupName: 'my-asg',
      DesiredCapacity: newDesiredCapacity,
      HonorCooldown: false
    }).promise();

    this.lastScalingTime = Date.now();
    console.log(`Scaled in to ${newDesiredCapacity} instances`);
  }

  async getCurrentCapacity() {
    const result = await this.asg.describeAutoScalingGroups({
      AutoScalingGroupNames: ['my-asg']
    }).promise();
    
    return result.AutoScalingGroups[0]?.DesiredCapacity || 0;
  }
}

// Usage
const autoScaler = new AutoScaler();
autoScaler.startMonitoring();
```

### Hybrid Scaling Approach

```javascript
// Hybrid scaling - combine vertical and horizontal
class HybridScaler {
  constructor() {
    this.verticalThreshold = 80; // CPU%
    this.horizontalThreshold = 70; // CPU%
    this.instanceTypes = {
      small: { cpu: 2, memory: 4 },
      medium: { cpu: 4, memory: 8 },
      large: { cpu: 8, memory: 16 },
      xlarge: { cpu: 16, memory: 32 }
    };
    this.currentInstanceType = 'medium';
  }

  async evaluateScaling(metrics) {
    const { cpu, memory, connections } = metrics;
    
    // Vertical scaling first
    if (cpu > this.verticalThreshold || memory > 90) {
      await this.scaleVertical('up');
      return;
    }
    
    // Then horizontal if needed
    if (cpu > this.horizontalThreshold && connections > 1000) {
      await this.scaleHorizontal('out');
    }
    
    // Scale down when utilization is low
    if (cpu < 30 && connections < 100) {
      await this.scaleHorizontal('in');
    }
    
    if (cpu < 20 && memory < 50) {
      await this.scaleVertical('down');
    }
  }

  async scaleVertical(direction) {
    const types = Object.keys(this.instanceTypes);
    const currentIndex = types.indexOf(this.currentInstanceType);
    
    if (direction === 'up' && currentIndex < types.length - 1) {
      this.currentInstanceType = types[currentIndex + 1];
      console.log(`Vertical scaling UP to ${this.currentInstanceType}`);
      // Implement instance type change logic
    } else if (direction === 'down' && currentIndex > 0) {
      this.currentInstanceType = types[currentIndex - 1];
      console.log(`Vertical scaling DOWN to ${this.currentInstanceType}`);
      // Implement instance type change logic
    }
  }

  async scaleHorizontal(direction) {
    // Implement horizontal scaling logic
    console.log(`Horizontal scaling ${direction}`);
  }
}
```

---

## 3. Cache Layers

### In-Depth Explanation
Multi-level caching strategy to reduce latency and database load. Each layer serves a different purpose in the caching hierarchy.

### Cache Hierarchy

```javascript
class MultiLayerCache {
  constructor() {
    // L1: In-memory cache (fastest, smallest)
    this.l1Cache = new Map();
    this.l1Size = 1000;
    this.l1TTL = 1000; // 1 second
    
    // L2: Redis cache (distributed, larger)
    this.redisClient = require('ioredis').createClient({
      host: 'redis-cluster',
      port: 6379
    });
    
    // L3: Application-level cache (shared between instances)
    this.l3Cache = new SharedMemoryCache();
    
    // L4: CDN cache (edge locations)
    this.cdnEnabled = true;
    
    // Cache statistics
    this.stats = {
      l1Hits: 0,
      l1Misses: 0,
      l2Hits: 0,
      l2Misses: 0,
      totalRequests: 0
    };
  }

  async get(key, fetchFn, options = {}) {
    this.stats.totalRequests++;
    
    const {
      ttl = 300, // 5 minutes default
      refresh = false,
      staleWhileRevalidate = false
    } = options;

    // 1. Check L1 cache
    if (!refresh) {
      const l1Value = this.l1Cache.get(key);
      if (l1Value && !this.isExpired(l1Value)) {
        this.stats.l1Hits++;
        
        // Background refresh if stale but not expired
        if (staleWhileRevalidate && this.isStale(l1Value)) {
          this.refreshInBackground(key, fetchFn, ttl);
        }
        
        return l1Value.data;
      }
    }

    // 2. Check L2 cache (Redis)
    try {
      const l2Value = await this.redisClient.get(key);
      if (l2Value && !refresh) {
        this.stats.l2Hits++;
        const parsedValue = JSON.parse(l2Value);
        
        // Update L1 cache
        this.setL1(key, parsedValue, ttl);
        
        return parsedValue;
      }
    } catch (error) {
      console.error('L2 cache error:', error);
    }

    // 3. Fetch from source (cache miss)
    this.stats.l2Misses++;
    const freshData = await fetchFn();
    
    // 4. Update all cache layers
    await this.set(key, freshData, ttl);
    
    return freshData;
  }

  async set(key, value, ttl) {
    const cacheEntry = {
      data: value,
      timestamp: Date.now(),
      ttl: ttl * 1000
    };
    
    // Set L1 cache with LRU eviction
    this.setL1(key, cacheEntry, ttl);
    
    // Set L2 cache
    try {
      await this.redisClient.setex(
        key,
        ttl,
        JSON.stringify(value)
      );
    } catch (error) {
      console.error('L2 cache set error:', error);
    }
    
    // Invalidate CDN cache if needed
    if (this.cdnEnabled) {
      await this.invalidateCDN(key);
    }
  }

  setL1(key, value, ttl) {
    // Implement LRU eviction
    if (this.l1Cache.size >= this.l1Size) {
      const firstKey = this.l1Cache.keys().next().value;
      this.l1Cache.delete(firstKey);
    }
    
    this.l1Cache.set(key, {
      data: value,
      timestamp: Date.now(),
      ttl: ttl * 1000
    });
  }

  isExpired(cacheEntry) {
    return Date.now() - cacheEntry.timestamp > cacheEntry.ttl;
  }

  isStale(cacheEntry) {
    // Consider stale after 80% of TTL
    return Date.now() - cacheEntry.timestamp > (cacheEntry.ttl * 0.8);
  }

  async refreshInBackground(key, fetchFn, ttl) {
    // Non-blocking refresh
    setTimeout(async () => {
      try {
        const freshData = await fetchFn();
        await this.set(key, freshData, ttl);
        console.log(`Background refresh completed for key: ${key}`);
      } catch (error) {
        console.error(`Background refresh failed for key: ${key}:`, error);
      }
    }, 0);
  }

  async invalidateCDN(key) {
    // Implement CDN cache invalidation
    const cdnUrl = `https://cdn.example.com/${key}`;
    // Send purge request to CDN
    console.log(`Invalidating CDN cache for: ${cdnUrl}`);
  }

  getHitRate() {
    const l1HitRate = (this.stats.l1Hits / this.stats.totalRequests) * 100;
    const l2HitRate = (this.stats.l2Hits / this.stats.totalRequests) * 100;
    const overallHitRate = ((this.stats.l1Hits + this.stats.l2Hits) / this.stats.totalRequests) * 100;
    
    return {
      l1HitRate: l1HitRate.toFixed(2),
      l2HitRate: l2HitRate.toFixed(2),
      overallHitRate: overallHitRate.toFixed(2),
      totalRequests: this.stats.totalRequests
    };
  }
}

// Cache patterns implementation
class CachePatterns {
  constructor() {
    this.cache = new MultiLayerCache();
  }

  // 1. Cache Aside (Lazy Loading)
  async cacheAside(key, fetchFn, ttl = 300) {
    try {
      return await this.cache.get(key, fetchFn, { ttl });
    } catch (error) {
      // Fallback to direct fetch on cache failure
      console.error('Cache aside failed, fetching directly:', error);
      return fetchFn();
    }
  }

  // 2. Write Through
  async writeThrough(key, data, writeFn, ttl = 300) {
    // Write to cache and database simultaneously
    await Promise.all([
      this.cache.set(key, data, ttl),
      writeFn(data)
    ]);
    return data;
  }

  // 3. Write Behind (Write Back)
  async writeBehind(key, data, writeFn, ttl = 300) {
    // Write to cache immediately
    await this.cache.set(key, data, ttl);
    
    // Queue database write for later
    this.queueWrite({
      key,
      data,
      writeFn,
      timestamp: Date.now()
    });
    
    return data;
  }

  // 4. Read Through
  async readThrough(key, fetchFn, ttl = 300) {
    // Cache handles the fetch if missing
    return this.cache.get(key, fetchFn, { ttl });
  }

  // 5. Cache Stampede Prevention
  async cacheWithLock(key, fetchFn, ttl = 300, lockTimeout = 5000) {
    const lockKey = `lock:${key}`;
    
    try {
      // Try to acquire lock
      const lockAcquired = await this.acquireLock(lockKey, lockTimeout);
      
      if (lockAcquired) {
        // We have the lock, fetch data
        const data = await fetchFn();
        await this.cache.set(key, data, ttl);
        await this.releaseLock(lockKey);
        return data;
      } else {
        // Wait for other process to populate cache
        await this.waitForCache(key, 100, 10); // Wait 100ms, retry 10 times
        return this.cache.get(key, fetchFn, { ttl });
      }
    } catch (error) {
      console.error('Cache with lock failed:', error);
      return fetchFn();
    }
  }

  async acquireLock(lockKey, timeout) {
    // Implement distributed lock (Redis, ZooKeeper, etc.)
    return true; // Simplified
  }

  async waitForCache(key, delay, maxRetries) {
    for (let i = 0; i < maxRetries; i++) {
      await new Promise(resolve => setTimeout(resolve, delay));
      const value = await this.cache.get(key, () => null);
      if (value) return value;
    }
    throw new Error('Cache wait timeout');
  }

  queueWrite(writeOperation) {
    // Implement write queue with batch processing
    this.writeQueue.push(writeOperation);
    
    if (this.writeQueue.length >= 100) {
      this.processWriteQueue();
    }
  }

  async processWriteQueue() {
    const batch = this.writeQueue.splice(0, 100);
    
    // Group by write function for batch operations
    const grouped = batch.reduce((groups, op) => {
      const fnName = op.writeFn.name || 'default';
      if (!groups[fnName]) groups[fnName] = [];
      groups[fnName].push(op);
      return groups;
    }, {});
    
    // Process each group
    for (const [fnName, operations] of Object.entries(grouped)) {
      try {
        await this.batchWrite(operations);
      } catch (error) {
        console.error(`Batch write failed for ${fnName}:`, error);
        // Retry logic here
      }
    }
  }
}

// Database query caching
class QueryCache {
  constructor() {
    this.cache = new MultiLayerCache();
  }

  generateCacheKey(query, params) {
    // Normalize query for caching
    const normalizedQuery = query
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase();
    
    const paramsString = JSON.stringify(params || {});
    
    // Create hash for cache key
    const crypto = require('crypto');
    return crypto
      .createHash('md5')
      .update(`${normalizedQuery}:${paramsString}`)
      .digest('hex');
  }

  async cachedQuery(query, params, fetchFn, ttl = 300) {
    const cacheKey = this.generateCacheKey(query, params);
    
    return this.cache.cacheAside(cacheKey, fetchFn, ttl);
  }

  async cachedQueryWithInvalidation(query, params, fetchFn, ttl = 300) {
    const cacheKey = this.generateCacheKey(query, params);
    
    // Check for cached result
    const cachedResult = await this.cache.get(cacheKey, () => null);
    
    if (cachedResult) {
      // Check if data is still valid
      if (!this.isDataStale(cachedResult)) {
        return cachedResult;
      }
      
      // Data is stale, refresh in background
      this.refreshInBackground(cacheKey, fetchFn, ttl);
      return cachedResult;
    }
    
    // No cache, fetch fresh data
    const freshData = await fetchFn();
    await this.cache.set(cacheKey, freshData, ttl);
    return freshData;
  }

  isDataStale(cachedData) {
    // Implement staleness check based on business rules
    return false;
  }

  async invalidateQueries(tableName) {
    // Invalidate all cached queries for a table
    const pattern = `*${tableName}*`;
    await this.cache.invalidatePattern(pattern);
  }
}
```

### Cache Invalidation Strategies

```javascript
class CacheInvalidator {
  constructor() {
    this.invalidationStrategies = {
      TTL: this.invalidateByTTL,
      EVENT: this.invalidateByEvent,
      VERSION: this.invalidateByVersion,
      MANUAL: this.invalidateManual
    };
  }

  // 1. Time-based invalidation (TTL)
  invalidateByTTL(key, ttl) {
    setTimeout(() => {
      this.deleteFromAllLayers(key);
    }, ttl * 1000);
  }

  // 2. Event-based invalidation
  async invalidateByEvent(event) {
    switch (event.type) {
      case 'USER_UPDATED':
        await this.invalidateUserCache(event.userId);
        break;
      case 'ORDER_CREATED':
        await this.invalidateOrderCaches(event.orderId);
        break;
      case 'PRODUCT_PRICE_CHANGED':
        await this.invalidateProductCaches(event.productId);
        break;
    }
  }

  async invalidateUserCache(userId) {
    const patterns = [
      `user:${userId}:*`,
      `profile:${userId}:*`,
      `orders:user:${userId}:*`
    ];
    
    for (const pattern of patterns) {
      await this.invalidatePattern(pattern);
    }
  }

  // 3. Version-based invalidation
  invalidateByVersion(key, currentVersion) {
    const cachedVersion = this.getCachedVersion(key);
    
    if (cachedVersion !== currentVersion) {
      this.deleteFromAllLayers(key);
      this.setVersion(key, currentVersion);
    }
  }

  // 4. Manual invalidation
  invalidateManual(keys) {
    keys.forEach(key => this.deleteFromAllLayers(key));
  }

  // Pattern-based invalidation
  async invalidatePattern(pattern) {
    // Redis SCAN for keys matching pattern
    const keys = await this.scanKeys(pattern);
    
    if (keys.length > 0) {
      await this.deleteMultiple(keys);
      console.log(`Invalidated ${keys.length} keys matching ${pattern}`);
    }
  }

  async scanKeys(pattern, cursor = '0', keys = []) {
    const [newCursor, foundKeys] = await this.redisClient.scan(
      cursor,
      'MATCH',
      pattern,
      'COUNT',
      100
    );
    
    keys.push(...foundKeys);
    
    if (newCursor === '0') {
      return keys;
    }
    
    return this.scanKeys(pattern, newCursor, keys);
  }
}
```

---

## 4. CDN Usage

### In-Depth Explanation
Content Delivery Networks distribute content geographically to reduce latency. Ideal for static assets, media files, and API responses.

### Implementation Strategies

```javascript
const AWS = require('aws-sdk');
const crypto = require('crypto');

class CDNManager {
  constructor() {
    this.cloudFront = new AWS.CloudFront();
    this.s3 = new AWS.S3();
    this.cdnDomain = 'd123456789.cloudfront.net';
    
    // Cache behaviors configuration
    this.cacheBehaviors = {
      static: {
        minTTL: 86400, // 24 hours
        defaultTTL: 31536000, // 1 year
        maxTTL: 31536000,
        compress: true,
        forwardedHeaders: ['Origin'],
        cookies: 'none',
        queryString: false
      },
      dynamic: {
        minTTL: 0,
        defaultTTL: 300, // 5 minutes
        maxTTL: 3600, // 1 hour
        compress: true,
        forwardedHeaders: ['*'],
        cookies: 'all',
        queryString: true,
        enableAcceptEncodingBrotli: true,
        enableAcceptEncodingGzip: true
      },
      api: {
        minTTL: 0,
        defaultTTL: 60, // 1 minute
        maxTTL: 300,
        compress: true,
        forwardedHeaders: ['Authorization', 'X-API-Key'],
        cookies: 'none',
        queryString: true
      }
    };
  }

  // 1. Static Asset Distribution
  async uploadStaticAsset(filePath, contentType) {
    const fileBuffer = require('fs').readFileSync(filePath);
    const fileHash = crypto.createHash('md5').update(fileBuffer).digest('hex');
    const fileName = `static/${fileHash}/${require('path').basename(filePath)}`;
    
    const params = {
      Bucket: 'my-cdn-bucket',
      Key: fileName,
      Body: fileBuffer,
      ContentType: contentType,
      CacheControl: 'public, max-age=31536000, immutable',
      ACL: 'public-read'
    };
    
    await this.s3.upload(params).promise();
    
    return `https://${this.cdnDomain}/${fileName}`;
  }

  // 2. Dynamic Content Caching
  async cacheDynamicContent(path, content, options = {}) {
    const {
      ttl = 300,
      varyByHeaders = ['Accept-Encoding', 'User-Agent'],
      varyByCookies = [],
      varyByQueryStrings = []
    } = options;
    
    const cacheKey = this.generateCacheKey(path, {
      headers: varyByHeaders,
      cookies: varyByCookies,
      query: varyByQueryStrings
    });
    
    // Store in S3 with metadata for CDN
    const params = {
      Bucket: 'my-cdn-bucket',
      Key: `dynamic/${cacheKey}`,
      Body: JSON.stringify(content),
      ContentType: 'application/json',
      CacheControl: `public, max-age=${ttl}, s-maxage=${ttl}`,
      Metadata: {
        'x-cache-ttl': ttl.toString(),
        'x-cache-key': cacheKey
      }
    };
    
    await this.s3.putObject(params).promise();
    
    return `https://${this.cdnDomain}/dynamic/${cacheKey}`;
  }

  generateCacheKey(path, varyOptions) {
    const keyParts = [path];
    
    if (varyOptions.headers) {
      keyParts.push(`headers:${varyOptions.headers.sort().join(',')}`);
    }
    
    if (varyOptions.cookies) {
      keyParts.push(`cookies:${varyOptions.cookies.sort().join(',')}`);
    }
    
    if (varyOptions.query) {
      keyParts.push(`query:${varyOptions.query.sort().join(',')}`);
    }
    
    return crypto
      .createHash('sha256')
      .update(keyParts.join('|'))
      .digest('hex');
  }

  // 3. Cache Invalidation
  async invalidateCache(paths) {
    const params = {
      DistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
      InvalidationBatch: {
        CallerReference: `invalidation-${Date.now()}`,
        Paths: {
          Quantity: paths.length,
          Items: paths.map(path => path.startsWith('/') ? path : `/${path}`)
        }
      }
    };
    
    const result = await this.cloudFront.createInvalidation(params).promise();
    
    console.log(`Invalidation created: ${result.Invalidation.Id}`);
    console.log(`Paths invalidated: ${paths.join(', ')}`);
    
    return result;
  }

  async invalidatePattern(pattern) {
    // Get all objects matching pattern from S3
    const objects = await this.listObjectsWithPattern(pattern);
    const paths = objects.map(obj => `/${obj.Key}`);
    
    if (paths.length > 0) {
      // CloudFront allows max 3000 paths per invalidation
      const batchSize = 3000;
      for (let i = 0; i < paths.length; i += batchSize) {
        const batch = paths.slice(i, i + batchSize);
        await this.invalidateCache(batch);
      }
    }
  }

  // 4. Edge Lambda@Edge Functions
  async deployEdgeFunction(code, eventType) {
    const lambda = new AWS.Lambda();
    
    // Event types: viewer-request, origin-request, origin-response, viewer-response
    
    const params = {
      FunctionName: `cdn-edge-${eventType}`,
      Runtime: 'nodejs18.x',
      Role: process.env.LAMBDA_EDGE_ROLE_ARN,
      Handler: 'index.handler',
      Code: { ZipFile: code },
      Description: `Edge function for ${eventType} events`,
      MemorySize: 128,
      Timeout: 5,
      Publish: true
    };
    
    const result = await lambda.createFunction(params).promise();
    
    // Associate with CloudFront
    await this.associateLambdaWithCloudFront(result.FunctionArn, eventType);
    
    return result;
  }

  // 5. Security - Signed URLs & Cookies
  generateSignedURL(path, expiresIn = 3600) {
    const cloudfrontSigner = new AWS.CloudFront.Signer(
      process.env.CLOUDFRONT_KEY_PAIR_ID,
      process.env.CLOUDFRONT_PRIVATE_KEY
    );
    
    const policy = {
      Statement: [{
        Resource: `https://${this.cdnDomain}${path}`,
        Condition: {
          DateLessThan: {
            'AWS:EpochTime': Math.floor(Date.now() / 1000) + expiresIn
          }
        }
      }]
    };
    
    const signedUrl = cloudfrontSigner.getSignedUrl({
      url: `https://${this.cdnDomain}${path}`,
      expires: Math.floor(Date.now() / 1000) + expiresIn
    });
    
    return signedUrl;
  }

  generateSignedCookies(path, expiresIn = 3600) {
    const cloudfrontSigner = new AWS.CloudFront.Signer(
      process.env.CLOUDFRONT_KEY_PAIR_ID,
      process.env.CLOUDFRONT_PRIVATE_KEY
    );
    
    const policy = JSON.stringify({
      Statement: [{
        Resource: `https://${this.cdnDomain}${path}`,
        Condition: {
          DateLessThan: {
            'AWS:EpochTime': Math.floor(Date.now() / 1000) + expiresIn
          }
        }
      }]
    });
    
    const cookies = cloudfrontSigner.getSignedCookie({
      url: `https://${this.cdnDomain}${path}`,
      expires: Math.floor(Date.now() / 1000) + expiresIn,
      policy: policy
    });
    
    return cookies;
  }

  // 6. Real-time Logging & Analytics
  async enableRealtimeLogging(configName, samplingRate = 100) {
    const params = {
      DistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
      RealtimeLogConfigArn: process.env.REALTIME_LOG_CONFIG_ARN
    };
    
    await this.cloudFront.updateDistribution(params).promise();
    
    console.log(`Enabled real-time logging with ${samplingRate}% sampling`);
  }

  // 7. Geo-restriction & Country Blocking
  async restrictByCountry(allowedCountries) {
    const params = {
      Id: process.env.CLOUDFRONT_DISTRIBUTION_ID,
      DistributionConfig: {
        Restrictions: {
          GeoRestriction: {
            RestrictionType: 'whitelist',
            Quantity: allowedCountries.length,
            Items: allowedCountries
          }
        }
      }
    };
    
    await this.cloudFront.updateDistribution(params).promise();
  }

  // 8. Custom Error Pages
  async setupCustomErrorPages() {
    const customErrorResponses = [
      {
        ErrorCode: 404,
        ResponsePagePath: '/error/404.html',
        ResponseCode: '404',
        ErrorCachingMinTTL: 300
      },
      {
        ErrorCode: 403,
        ResponsePagePath: '/error/403.html',
        ResponseCode: '403',
        ErrorCachingMinTTL: 300
      },
      {
        ErrorCode: 500,
        ResponsePagePath: '/error/500.html',
        ResponseCode: '500',
        ErrorCachingMinTTL: 60
      }
    ];
    
    // Update distribution with custom error responses
    // Implementation depends on your infrastructure
  }
}

// Express middleware for CDN optimization
const cdnMiddleware = (req, res, next) => {
  // Set cache headers for CDN
  const setCacheHeaders = (ttl, options = {}) => {
    const { public = true, immutable = false, staleWhileRevalidate = 0 } = options;
    
    let cacheControl = public ? 'public' : 'private';
    cacheControl += `, max-age=${ttl}`;
    
    if (immutable) {
      cacheControl += ', immutable';
    }
    
    if (staleWhileRevalidate > 0) {
      cacheControl += `, stale-while-revalidate=${staleWhileRevalidate}`;
    }
    
    res.set('Cache-Control', cacheControl);
    
    // Set surrogate control for CDN
    res.set('Surrogate-Control', `max-age=${ttl}`);
    
    // Set Vary headers for proper caching
    res.set('Vary', 'Accept-Encoding, User-Agent');
  };
  
  // Helper to set CDN headers based on content type
  const setCDNHeadersByType = (contentType) => {
    switch (contentType) {
      case 'application/javascript':
      case 'text/css':
      case 'image/':
        setCacheHeaders(31536000, { immutable: true }); // 1 year
        break;
      case 'application/json':
        setCacheHeaders(300, { staleWhileRevalidate: 3600 }); // 5 minutes
        break;
      case 'text/html':
        setCacheHeaders(60, { staleWhileRevalidate: 300 }); // 1 minute
        break;
      default:
        setCacheHeaders(3600); // 1 hour
    }
  };
  
  // Override res.send to intercept and set headers
  const originalSend = res.send;
  res.send = function(body) {
    const contentType = this.get('Content-Type');
    if (contentType) {
      setCDNHeadersByType(contentType);
    }
    
    originalSend.call(this, body);
  };
  
  next();
};

// Lambda@Edge example for request transformation
const edgeRequestHandler = {
  async handler(event, context) {
    const request = event.Records[0].cf.request;
    const headers = request.headers;
    
    // 1. Add security headers
    headers['x-frame-options'] = [{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }];
    headers['x-content-type-options'] = [{ key: 'X-Content-Type-Options', value: 'nosniff' }];
    headers['x-xss-protection'] = [{ key: 'X-XSS-Protection', value: '1; mode=block' }];
    
    // 2. Modify request for A/B testing
    const userAgent = headers['user-agent']?.[0]?.value || '';
    const isMobile = /Mobile|Android|iPhone/i.test(userAgent);
    
    if (isMobile) {
      // Route to mobile-optimized version
      request.uri = `/mobile${request.uri}`;
    }
    
    // 3. Geo-based routing
    const country = headers['cloudfront-viewer-country']?.[0]?.value;
    if (country === 'CN') {
      // Route to China-optimized origin
      request.origin = {
        custom: {
          domainName: 'cn-origin.example.com',
          port: 443,
          protocol: 'https',
          path: '',
          sslProtocols: ['TLSv1.2'],
          readTimeout: 30,
          keepaliveTimeout: 5,
          customHeaders: {}
        }
      };
    }
    
    // 4. Cache key normalization
    // Remove tracking parameters from cache key
    const queryParams = request.querystring;
    if (queryParams) {
      const params = new URLSearchParams(queryParams);
      
      // Remove tracking parameters
      ['utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid'].forEach(param => {
        params.delete(param);
      });
      
      request.querystring = params.toString();
    }
    
    return request;
  }
};

// Edge response handler for optimization
const edgeResponseHandler = {
  async handler(event, context) {
    const response = event.Records[0].cf.response;
    const headers = response.headers;
    
    // 1. Add security headers
    headers['strict-transport-security'] = [{
      key: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains; preload'
    }];
    
    headers['content-security-policy'] = [{
      key: 'Content-Security-Policy',
      value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    }];
    
    // 2. Image optimization
    const contentType = headers['content-type']?.[0]?.value || '';
    
    if (contentType.startsWith('image/')) {
      const acceptHeader = event.Records[0].cf.request.headers['accept']?.[0]?.value || '';
      
      // Convert to WebP if supported
      if (acceptHeader.includes('image/webp')) {
        headers['content-type'] = [{ key: 'Content-Type', value: 'image/webp' }];
        // Note: Actual image conversion would happen at origin
      }
    }
    
    // 3. Gzip/Brotli compression
    const acceptEncoding = event.Records[0].cf.request.headers['accept-encoding']?.[0]?.value || '';
    
    if (acceptEncoding.includes('br')) {
      headers['content-encoding'] = [{ key: 'Content-Encoding', value: 'br' }];
    } else if (acceptEncoding.includes('gzip')) {
      headers['content-encoding'] = [{ key: 'Content-Encoding', value: 'gzip' }];
    }
    
    return response;
  }
};
```

---

## 5. Database Sharding

### In-Depth Explanation
Sharding horizontally partitions data across multiple databases to improve scalability and performance.

### Sharding Strategies

```javascript
class DatabaseSharder {
  constructor() {
    this.shards = new Map();
    this.shardingStrategy = 'range'; // range, hash, directory, geographic
    this.shardCount = 4;
    this.initializeShards();
  }

  initializeShards() {
    for (let i = 0; i < this.shardCount; i++) {
      this.shards.set(i, {
        id: i,
        connection: this.createShardConnection(i),
        range: this.calculateRange(i),
        load: 0,
        status: 'healthy'
      });
    }
  }

  createShardConnection(shardId) {
    // Create database connection for shard
    return {
      host: `shard-${shardId}.example.com`,
      port: 5432,
      database: `app_shard_${shardId}`,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD
    };
  }

  // 1. Range-based Sharding
  calculateRange(shardId) {
    const totalShards = this.shardCount;
    const rangeSize = 1000000; // 1 million IDs per shard
    
    return {
      start: shardId * rangeSize,
      end: (shardId + 1) * rangeSize - 1
    };
  }

  getShardByRange(key) {
    for (const [shardId, shard] of this.shards) {
      if (key >= shard.range.start && key <= shard.range.end) {
        return shard;
      }
    }
    
    // If key exceeds range, use modulo
    return this.getShardByHash(key);
  }

  // 2. Hash-based Sharding
  getShardByHash(key) {
    const hash = this.hashFunction(key.toString());
    const shardId = hash % this.shardCount;
    return this.shards.get(shardId);
  }

  hashFunction(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  // 3. Directory-based Sharding
  async getShardByDirectory(key) {
    // Lookup shard mapping from directory service
    const directory = await this.getShardDirectory();
    const shardId = directory.get(key);
    
    if (shardId !== undefined) {
      return this.shards.get(shardId);
    }
    
    // If not found, assign new shard
    return this.assignNewShard(key);
  }

  async getShardDirectory() {
    // Retrieve from Redis or consistent storage
    // This is a simplified example
    return new Map([
      ['user:1001', 0],
      ['user:1002', 1],
      ['order:5001', 2]
    ]);
  }

  // 4. Geographic Sharding
  getShardByGeography(region) {
    const geoMapping = {
      'us-east': 0,
      'us-west': 1,
      'europe': 2,
      'asia': 3
    };
    
    const shardId = geoMapping[region] || 0;
    return this.shards.get(shardId);
  }

  // Query routing
  async routeQuery(query, params) {
    const shardKey = this.extractShardKey(query, params);
    const shard = this.selectShard(shardKey);
    
    return this.executeOnShard(shard, query, params);
  }

  extractShardKey(query, params) {
    // Extract shard key from query or params
    // This is a simplified example
    if (params.userId) {
      return `user:${params.userId}`;
    } else if (params.orderId) {
      return `order:${params.orderId}`;
    }
    
    return null;
  }

  selectShard(shardKey) {
    if (!shardKey) {
      // Broadcast query to all shards
      return Array.from(this.shards.values());
    }
    
    switch (this.shardingStrategy) {
      case 'range':
        return this.getShardByRange(this.extractNumericKey(shardKey));
      case 'hash':
        return this.getShardByHash(shardKey);
      case 'directory':
        return this.getShardByDirectory(shardKey);
      case 'geographic':
        return this.getShardByGeography(shardKey);
      default:
        return this.getShardByHash(shardKey);
    }
  }

  async executeOnShard(shard, query, params) {
    if (Array.isArray(shard)) {
      // Execute on multiple shards
      const results = await Promise.all(
        shard.map(s => this.executeSingleShard(s, query, params))
      );
      return this.mergeResults(results);
    }
    
    return this.executeSingleShard(shard, query, params);
  }

  async executeSingleShard(shard, query, params) {
    // Execute query on specific shard
    const connection = shard.connection;
    
    // Update shard load
    shard.load++;
    
    try {
      const result = await this.performQuery(connection, query, params);
      shard.load--;
      return result;
    } catch (error) {
      shard.load--;
      throw error;
    }
  }

  mergeResults(results) {
    // Merge results from multiple shards
    return results.flat();
  }

  // Shard management
  async addShard() {
    const newShardId = this.shardCount;
    const newShard = {
      id: newShardId,
      connection: this.createShardConnection(newShardId),
      range: this.calculateRange(newShardId),
      load: 0,
      status: 'healthy'
    };
    
    this.shards.set(newShardId, newShard);
    this.shardCount++;
    
    // Rebalance data
    await this.rebalanceShards();
    
    return newShard;
  }

  async rebalanceShards() {
    console.log('Rebalancing shards...');
    
    // Calculate target data distribution
    const targetPerShard = await this.getTotalDataCount() / this.shardCount;
    
    // Identify shards that need rebalancing
    const shardsToRebalance = [];
    
    for (const shard of this.shards.values()) {
      const dataCount = await this.getShardDataCount(shard);
      const deviation = Math.abs(dataCount - targetPerShard) / targetPerShard;
      
      if (deviation > 0.2) { // More than 20% deviation
        shardsToRebalance.push({ shard, dataCount, target: targetPerShard });
      }
    }
    
    // Rebalance data
    for (const { shard, dataCount, target } of shardsToRebalance) {
      if (dataCount > target) {
        await this.moveDataFromShard(shard, dataCount - target);
      }
    }
    
    console.log('Shard rebalancing complete');
  }

  async moveDataFromShard(sourceShard, amountToMove) {
    // Move data from overloaded shard to underloaded shards
    const dataToMove = await this.extractDataFromShard(sourceShard, amountToMove);
    
    // Distribute to other shards
    const targetShards = Array.from(this.shards.values())
      .filter(s => s.id !== sourceShard.id && s.load < sourceShard.load)
      .sort((a, b) => a.load - b.load);
    
    let remainingData = dataToMove;
    
    for (const targetShard of targetShards) {
      if (remainingData.length === 0) break;
      
      const batchSize = Math.min(
        remainingData.length,
        Math.ceil(dataToMove.length / targetShards.length)
      );
      
      const batch = remainingData.splice(0, batchSize);
      await this.insertDataIntoShard(targetShard, batch);
    }
  }

  // Shard health monitoring
  async monitorShardHealth() {
    setInterval(async () => {
      for (const shard of this.shards.values()) {
        try {
          await this.checkShardHealth(shard);
          shard.status = 'healthy';
        } catch (error) {
          console.error(`Shard ${shard.id} is unhealthy:`, error);
          shard.status = 'unhealthy';
          
          // Trigger failover
          await this.handleShardFailure(shard);
        }
      }
    }, 30000); // Check every 30 seconds
  }

  async handleShardFailure(failedShard) {
    console.log(`Handling failure of shard ${failedShard.id}`);
    
    // 1. Mark shard as failed
    failedShard.status = 'failed';
    
    // 2. Redirect traffic to replica if available
    if (failedShard.replica) {
      console.log(`Redirecting to replica for shard ${failedShard.id}`);
      failedShard.connection = failedShard.replica;
      failedShard.status = 'degraded';
      return;
    }
    
    // 3. Rebalance data to other shards
    await this.rebalanceAfterFailure(failedShard);
    
    // 4. Update routing tables
    await this.updateRoutingTables(failedShard);
  }

  // Cross-shard transactions
  async performCrossShardTransaction(operations) {
    // Two-phase commit protocol
    const transactionId = this.generateTransactionId();
    const participants = [];
    
    try {
      // Phase 1: Prepare
      for (const operation of operations) {
        const shard = this.selectShard(operation.key);
        const prepared = await this.prepareTransaction(shard, transactionId, operation);
        
        if (!prepared) {
          throw new Error(`Prepare failed for operation: ${operation}`);
        }
        
        participants.push(shard);
      }
      
      // Phase 2: Commit
      for (const shard of participants) {
        await this.commitTransaction(shard, transactionId);
      }
      
      return { success: true, transactionId };
      
    } catch (error) {
      // Rollback on failure
      for (const shard of participants) {
        await this.rollbackTransaction(shard, transactionId);
      }
      
      throw error;
    }
  }

  async prepareTransaction(shard, transactionId, operation) {
    // Store transaction state
    const prepared = await this.executeSingleShard(
      shard,
      'INSERT INTO transaction_log (id, operation, status) VALUES ($1, $2, $3)',
      [transactionId, JSON.stringify(operation), 'prepared']
    );
    
    return prepared.rowCount > 0;
  }

  async commitTransaction(shard, transactionId) {
    // Execute the actual operation
    await this.executeSingleShard(
      shard,
      'UPDATE transaction_log SET status = $1 WHERE id = $2',
      ['committed', transactionId]
    );
  }

  async rollbackTransaction(shard, transactionId) {
    await this.executeSingleShard(
      shard,
      'UPDATE transaction_log SET status = $1 WHERE id = $2',
      ['rolled_back', transactionId]
    );
  }

  generateTransactionId() {
    return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Shard-aware data access layer
  async findUserById(userId) {
    const shard = this.getShardByHash(`user:${userId}`);
    
    return this.executeOnShard(
      shard,
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
  }

  async findOrdersByUserId(userId) {
    // This requires cross-shard query if users and orders are on different shards
    const userShard = this.getShardByHash(`user:${userId}`);
    const user = await this.executeOnShard(
      userShard,
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    
    if (!user) return [];
    
    // Assuming orders are sharded by orderId, not userId
    // We need to query all shards or maintain an index
    const allOrders = await this.broadcastQuery(
      'SELECT * FROM orders WHERE user_id = $1',
      [userId]
    );
    
    return allOrders.flat();
  }

  async broadcastQuery(query, params) {
    const results = [];
    
    for (const shard of this.shards.values()) {
      try {
        const shardResult = await this.executeOnShard(shard, query, params);
        results.push(shardResult);
      } catch (error) {
        console.error(`Query failed on shard ${shard.id}:`, error);
      }
    }
    
    return results;
  }

  // Data migration between shards
  async migrateData(sourceShardId, targetShardId, dataRange) {
    console.log(`Migrating data from shard ${sourceShardId} to ${targetShardId}`);
    
    const sourceShard = this.shards.get(sourceShardId);
    const targetShard = this.shards.get(targetShardId);
    
    if (!sourceShard || !targetShard) {
      throw new Error('Invalid shard IDs');
    }
    
    // 1. Start migration
    await this.startMigration(sourceShard, targetShard, dataRange);
    
    // 2. Copy data
    const data = await this.extractDataFromShard(sourceShard, dataRange);
    await this.insertDataIntoShard(targetShard, data);
    
    // 3. Update routing
    await this.updateRoutingForMigration(sourceShardId, targetShardId, dataRange);
    
    // 4. Cleanup old data
    await this.cleanupMigratedData(sourceShard, dataRange);
    
    console.log('Data migration complete');
  }

  async startMigration(sourceShard, targetShard, dataRange) {
    // Mark data as being migrated
    await this.executeSingleShard(
      sourceShard,
      'UPDATE migrating_data SET status = $1 WHERE range_start = $2 AND range_end = $3',
      ['migrating', dataRange.start, dataRange.end]
    );
  }
}

// Shard proxy for transparent sharding
class ShardProxy {
  constructor() {
    this.sharder = new DatabaseSharder();
    this.queryCache = new Map();
    this.connectionPool = new Map();
  }

  async query(sql, params = []) {
    const cacheKey = `${sql}:${JSON.stringify(params)}`;
    
    // Check cache
    if (this.queryCache.has(cacheKey)) {
      return this.queryCache.get(cacheKey);
    }
    
    // Route to appropriate shard
    const result = await this.sharder.routeQuery(sql, params);
    
    // Cache result
    this.queryCache.set(cacheKey, result);
    
    return result;
  }

  async transactional(operations) {
    return this.sharder.performCrossShardTransaction(operations);
  }

  // Connection pooling per shard
  async getConnection(shard) {
    const poolKey = shard.id;
    
    if (!this.connectionPool.has(poolKey)) {
      this.connectionPool.set(poolKey, this.createConnectionPool(shard));
    }
    
    const pool = this.connectionPool.get(poolKey);
    return pool.acquire();
  }

  createConnectionPool(shard) {
    // Create connection pool for shard
    return {
      connections: [],
      maxConnections: 10,
      acquire() {
        // Simplified connection acquisition
        return Promise.resolve({
          query: async (sql, params) => {
            // Execute query on shard
            return this.sharder.executeSingleShard(shard, sql, params);
          },
          release: () => {
            // Release connection back to pool
          }
        });
      }
    };
  }
}

// Shard key generation strategies
class ShardKeyGenerator {
  static generateSnowflakeId(shardId) {
    // Twitter Snowflake-like ID
    const timestamp = Date.now() - 1609459200000; // Custom epoch
    const sequence = Math.floor(Math.random() * 4096);
    
    // 41 bits timestamp, 10 bits shard ID, 12 bits sequence
    return (timestamp << 22) | (shardId << 12) | sequence;
  }

  static generateULID(shardId) {
    // ULID with shard prefix
    const { ulid } = require('ulid');
    return `${shardId.toString().padStart(3, '0')}_${ulid()}`;
  }

  static generateCompositeKey(entityType, entityId, shardHint) {
    // Composite key with shard hint
    return `${entityType}:${entityId}:${shardHint}`;
  }
}

// Shard-aware ORM
class ShardAwareModel {
  constructor(shardProxy, tableName, shardKeyField = 'id') {
    this.shardProxy = shardProxy;
    this.tableName = tableName;
    this.shardKeyField = shardKeyField;
  }

  async findById(id) {
    const shardKey = `${this.tableName}:${id}`;
    const sql = `SELECT * FROM ${this.tableName} WHERE ${this.shardKeyField} = $1`;
    
    return this.shardProxy.query(sql, [id]);
  }

  async create(data) {
    // Generate shard-aware ID
    const id = ShardKeyGenerator.generateSnowflakeId(
      this.determineShardId(data)
    );
    
    data[this.shardKeyField] = id;
    
    const fields = Object.keys(data);
    const values = Object.values(data);
    const placeholders = fields.map((_, i) => `$${i + 1}`);
    
    const sql = `
      INSERT INTO ${this.tableName} (${fields.join(', ')})
      VALUES (${placeholders.join(', ')})
      RETURNING *
    `;
    
    return this.shardProxy.query(sql, values);
  }

  determineShardId(data) {
    // Determine shard based on data
    if (data.user_id) {
      return this.shardProxy.sharder.getShardByHash(`user:${data.user_id}`).id;
    }
    
    // Default to hash of ID
    return this.shardProxy.sharder.hashFunction(
      data[this.shardKeyField]?.toString() || 'default'
    ) % this.shardProxy.sharder.shardCount;
  }

  async update(id, data) {
    const fields = Object.keys(data).map((field, i) => 
      `${field} = $${i + 1}`
    );
    
    const values = Object.values(data);
    values.push(id); // For WHERE clause
    
    const sql = `
      UPDATE ${this.tableName}
      SET ${fields.join(', ')}
      WHERE ${this.shardKeyField} = $${values.length}
      RETURNING *
    `;
    
    return this.shardProxy.query(sql, values);
  }

  async delete(id) {
    const sql = `DELETE FROM ${this.tableName} WHERE ${this.shardKeyField} = $1`;
    return this.shardProxy.query(sql, [id]);
  }

  async findByIndex(indexField, value) {
    // This may require cross-shard query
    // Better to have secondary index or materialized view
    const sql = `SELECT * FROM ${this.tableName} WHERE ${indexField} = $1`;
    
    // Broadcast to all shards
    const results = await this.shardProxy.sharder.broadcastQuery(sql, [value]);
    return results.flat();
  }
}
```

---

## 6. Indexing & Query Optimization

### In-Depth Explanation
Proper indexing and query optimization are critical for database performance. This section covers indexing strategies, query analysis, and optimization techniques.

### Index Types and Strategies

```javascript
const { Pool } = require('pg');
const SQL = require('sql-template-strings');

class DatabaseOptimizer {
  constructor(pool) {
    this.pool = pool;
    this.queryStats = new Map();
    this.indexAdvisor = new IndexAdvisor();
  }

  // 1. Analyze Query Performance
  async analyzeQuery(query, params = []) {
    const startTime = Date.now();
    
    try {
      // Use EXPLAIN ANALYZE to get execution plan
      const explainQuery = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${query}`;
      const result = await this.pool.query(explainQuery, params);
      
      const executionTime = Date.now() - startTime;
      const plan = result.rows[0]['QUERY PLAN'];
      
      const analysis = {
        executionTime,
        plan: JSON.parse(plan)[0],
        query,
        params,
        timestamp: new Date().toISOString()
      };
      
      // Store for historical analysis
      this.storeQueryStats(analysis);
      
      // Analyze for optimization opportunities
      const recommendations = await this.analyzePlan(analysis.plan);
      
      return {
        ...analysis,
        recommendations,
        cost: analysis.plan['Plan']['Total Cost']
      };
      
    } catch (error) {
      console.error('Query analysis failed:', error);
      throw error;
    }
  }

  // 2. Index Recommendation Engine
  async recommendIndexes(query, params, frequency = 1) {
    const analysis = await this.analyzeQuery(query, params);
    const plan = analysis.plan;
    
    const recommendations = [];
    
    // Check for sequential scans
    if (plan['Plan']['Node Type'] === 'Seq Scan') {
      const table = plan['Plan']['Relation Name'];
      const filter = plan['Plan']['Filter'];
      
      if (filter) {
        // Extract filter conditions for index
        const conditions = this.extractFilterConditions(filter);
        
        recommendations.push({
          type: 'CREATE_INDEX',
          priority: 'HIGH',
          table,
          columns: this.extractColumnsFromConditions(conditions),
          reason: `Sequential scan detected on table ${table} with filter: ${filter}`,
          estimatedImprovement: '90-95%'
        });
      }
    }
    
    // Check for sort operations
    if (plan['Plan']['Node Type'] === 'Sort') {
      const sortKey = plan['Plan']['Sort Key'];
      
      if (sortKey && sortKey.length > 0) {
        const childPlan = plan['Plan']['Plans'][0];
        const table = childPlan['Relation Name'];
        
        recommendations.push({
          type: 'CREATE_INDEX',
          priority: 'MEDIUM',
          table,
          columns: sortKey,
          reason: `Sort operation detected without covering index`,
          estimatedImprovement: '70-80%'
        });
      }
    }
    
    // Check for join performance
    if (plan['Plan']['Node Type'] === 'Hash Join' || 
        plan['Plan']['Node Type'] === 'Nested Loop') {
      
      const joinConditions = this.extractJoinConditions(plan['Plan']);
      
      joinConditions.forEach(condition => {
        recommendations.push({
          type: 'CREATE_INDEX',
          priority: 'HIGH',
          table: condition.table,
          columns: [condition.column],
          reason: `Join condition without index: ${condition.condition}`,
          estimatedImprovement: '80-90%'
        });
      });
    }
    
    return {
      query,
      frequency,
      currentCost: plan['Plan']['Total Cost'],
      recommendations: this.prioritizeRecommendations(recommendations, frequency)
    };
  }

  // 3. Automatic Index Creation
  async createRecommendedIndexes(recommendations, dryRun = true) {
    const createdIndexes = [];
    
    for (const rec of recommendations) {
      if (rec.type === 'CREATE_INDEX') {
        const indexName = this.generateIndexName(rec.table, rec.columns);
        const indexSQL = this.generateIndexSQL(
          indexName,
          rec.table,
          rec.columns
        );
        
        if (dryRun) {
          console.log(`Would create index: ${indexSQL}`);
        } else {
          try {
            await this.pool.query(indexSQL);
            createdIndexes.push(indexName);
            console.log(`Created index: ${indexName}`);
          } catch (error) {
            console.error(`Failed to create index ${indexName}:`, error);
          }
        }
      }
    }
    
    return createdIndexes;
  }

  generateIndexName(table, columns) {
    const columnStr = columns.join('_');
    return `idx_${table}_${columnStr}_${Date.now()}`;
  }

  generateIndexSQL(indexName, table, columns, options = {}) {
    const columnList = columns.map(col => `"${col}"`).join(', ');
    const unique = options.unique ? 'UNIQUE ' : '';
    const concurrently = options.concurrently ? 'CONCURRENTLY ' : '';
    
    return `
      CREATE ${unique}INDEX ${concurrently}"${indexName}"
      ON "${table}" (${columnList})
      ${options.where ? `WHERE ${options.where}` : ''}
    `.trim();
  }

  // 4. Query Rewriting Optimization
  async optimizeQuery(query, params) {
    const originalAnalysis = await this.analyzeQuery(query, params);
    
    const optimizations = [
      this.rewriteSelectStar,
      this.rewriteImplicitJoins,
      this.rewriteSubqueriesToJoins,
      this.rewriteOrToUnion,
      this.addMissingJoins
    ];
    
    let bestQuery = query;
    let bestAnalysis = originalAnalysis;
    
    for (const optimizeFn of optimizations) {
      try {
        const optimizedQuery = optimizeFn(query);
        
        if (optimizedQuery !== query) {
          const optimizedAnalysis = await this.analyzeQuery(optimizedQuery, params);
          
          if (optimizedAnalysis.cost < bestAnalysis.cost) {
            bestQuery = optimizedQuery;
            bestAnalysis = optimizedAnalysis;
            console.log(`Found better query: ${optimizedAnalysis.cost} < ${bestAnalysis.cost}`);
          }
        }
      } catch (error) {
        // Skip optimization if it fails
        continue;
      }
    }
    
    return {
      originalQuery: query,
      optimizedQuery: bestQuery,
      improvement: ((originalAnalysis.cost - bestAnalysis.cost) / originalAnalysis.cost * 100).toFixed(2),
      originalCost: originalAnalysis.cost,
      optimizedCost: bestAnalysis.cost
    };
  }

  rewriteSelectStar(query) {
    // Replace SELECT * with explicit columns
    const tableRegex = /FROM\s+(\w+)/i;
    const match = query.match(tableRegex);
    
    if (match && query.includes('SELECT *')) {
      const table = match[1];
      // In real implementation, you would fetch columns from information_schema
      const columns = ['id', 'created_at', 'updated_at']; // Example columns
      
      return query.replace('SELECT *', `SELECT ${columns.join(', ')}`);
    }
    
    return query;
  }

  rewriteImplicitJoins(query) {
    // Convert implicit joins to explicit JOIN syntax
    return query.replace(
      /FROM\s+(\w+)\s*,\s*(\w+)\s+WHERE/i,
      'FROM $1 INNER JOIN $2 ON'
    );
  }

  // 5. Database Statistics Management
  async updateStatistics(tables = []) {
    if (tables.length === 0) {
      // Update all tables
      const allTables = await this.getAllTables();
      tables = allTables;
    }
    
    console.log(`Updating statistics for ${tables.length} tables`);
    
    for (const table of tables) {
      try {
        await this.pool.query(`ANALYZE "${table}"`);
        console.log(`Updated statistics for table: ${table}`);
      } catch (error) {
        console.error(`Failed to analyze table ${table}:`, error);
      }
    }
  }

  async getAllTables() {
    const result = await this.pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    return result.rows.map(row => row.table_name);
  }

  // 6. Connection Pool Optimization
  optimizeConnectionPool(config) {
    const { maxClients, avgQueryTime, targetConcurrency } = config;
    
    // Formula: poolSize = (core_count * 2) + effective_spindle_count
    const coreCount = require('os').cpus().length;
    const recommendedPoolSize = (coreCount * 2) + 1;
    
    // Adjust based on query characteristics
    let adjustedSize = recommendedPoolSize;
    
    if (avgQueryTime > 100) { // Slow queries
      adjustedSize = Math.min(recommendedPoolSize, 20);
    }
    
    if (targetConcurrency > 1000) { // High concurrency
      adjustedSize = Math.max(recommendedPoolSize, 50);
    }
    
    return {
      max: adjustedSize,
      min: Math.floor(adjustedSize * 0.1),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000
    };
  }

  // 7. Query Cache Implementation
  class QueryCache {
    constructor() {
      this.cache = new Map();
      this.hits = 0;
      this.misses = 0;
      this.maxSize = 1000;
    }

    async getOrExecute(query, params, executor) {
      const cacheKey = this.generateCacheKey(query, params);
      
      if (this.cache.has(cacheKey)) {
        this.hits++;
        const cached = this.cache.get(cacheKey);
        
        // Check if cache is still valid
        if (!this.isExpired(cached)) {
          return cached.data;
        }
        
        // Cache is expired, remove it
        this.cache.delete(cacheKey);
      }
      
      this.misses++;
      
      // Execute query
      const startTime = Date.now();
      const result = await executor(query, params);
      const executionTime = Date.now() - startTime;
      
      // Determine TTL based on query characteristics
      const ttl = this.calculateTTL(query, executionTime);
      
      // Cache the result
      this.set(cacheKey, result, ttl);
      
      // Evict if cache is too large
      if (this.cache.size > this.maxSize) {
        this.evictLRU();
      }
      
      return result;
    }

    calculateTTL(query, executionTime) {
      // Longer TTL for expensive queries
      if (executionTime > 1000) {
        return 300; // 5 minutes
      } else if (executionTime > 100) {
        return 60; // 1 minute
      } else {
        return 10; // 10 seconds
      }
    }

    evictLRU() {
      // Simple LRU eviction
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    getHitRate() {
      const total = this.hits + this.misses;
      return total > 0 ? (this.hits / total * 100).toFixed(2) : 0;
    }
  }

  // 8. Materialized Views for Complex Queries
  async createMaterializedView(name, query, refreshInterval = '1 hour') {
    const createSQL = `
      CREATE MATERIALIZED VIEW IF NOT EXISTS "${name}" AS
      ${query}
    `;
    
    await this.pool.query(createSQL);
    
    // Create index on materialized view
    await this.createMaterializedViewIndexes(name);
    
    // Schedule refresh
    this.scheduleViewRefresh(name, refreshInterval);
    
    console.log(`Created materialized view: ${name}`);
  }

  async createMaterializedViewIndexes(viewName) {
    // Analyze query to determine optimal indexes
    const analysis = await this.analyzeQuery(`SELECT * FROM "${viewName}" LIMIT 1`);
    
    // Create indexes based on analysis
    // Implementation depends on specific requirements
  }

  scheduleViewRefresh(viewName, interval) {
    setInterval(async () => {
      try {
        await this.refreshMaterializedView(viewName);
        console.log(`Refreshed materialized view: ${viewName}`);
      } catch (error) {
        console.error(`Failed to refresh materialized view ${viewName}:`, error);
      }
    }, this.parseInterval(interval));
  }

  async refreshMaterializedView(viewName, concurrently = true) {
    const concurrentlyStr = concurrently ? 'CONCURRENTLY' : '';
    await this.pool.query(`REFRESH MATERIALIZED VIEW ${concurrentlyStr} "${viewName}"`);
  }

  parseInterval(interval) {
    // Parse interval string to milliseconds
    const match = interval.match(/^(\d+)\s*(hour|minute|second)s?$/i);
    
    if (match) {
      const value = parseInt(match[1]);
      const unit = match[2].toLowerCase();
      
      switch (unit) {
        case 'hour': return value * 60 * 60 * 1000;
        case 'minute': return value * 60 * 1000;
        case 'second': return value * 1000;
      }
    }
    
    return 3600000; // Default 1 hour
  }

  // 9. Partitioning Large Tables
  async partitionTable(tableName, partitionKey, strategy = 'range') {
    const partitionDate = new Date().toISOString().split('T')[0];
    const partitionName = `${tableName}_${partitionDate.replace(/-/g, '')}`;
    
    let partitionSQL;
    
    if (strategy === 'range') {
      partitionSQL = `
        CREATE TABLE "${partitionName}" PARTITION OF "${tableName}"
        FOR VALUES FROM ('${partitionDate}') TO ('${this.getNextPartitionDate(partitionDate)}')
      `;
    } else if (strategy === 'list') {
      partitionSQL = `
        CREATE TABLE "${partitionName}" PARTITION OF "${tableName}"
        FOR VALUES IN ('${partitionDate}')
      `;
    }
    
    await this.pool.query(partitionSQL);
    
    // Create indexes on partition
    await this.createPartitionIndexes(partitionName);
    
    console.log(`Created partition: ${partitionName}`);
    
    return partitionName;
  }

  async createPartitionIndexes(partitionName) {
    // Copy indexes from parent table
    const indexSQL = `
      SELECT indexdef 
      FROM pg_indexes 
      WHERE tablename = '${partitionName.replace(/_\d+$/, '')}'
    `;
    
    const result = await this.pool.query(indexSQL);
    
    for (const row of result.rows) {
      const createIndexSQL = row.indexdef.replace(
        /ON\s+\w+/,
        `ON "${partitionName}"`
      );
      
      await this.pool.query(createIndexSQL);
    }
  }

  // 10. Query Performance Dashboard
  async generatePerformanceReport(timeRange = '24 hours') {
    const slowQueries = await this.getSlowQueries(timeRange);
    const indexUsage = await this.getIndexUsage();
    const tableStats = await this.getTableStatistics();
    const lockAnalysis = await this.analyzeLocks();
    
    return {
      timestamp: new Date().toISOString(),
      timeRange,
      slowQueries: this.analyzeSlowQueries(slowQueries),
      indexRecommendations: this.analyzeIndexUsage(indexUsage),
      tableHealth: this.analyzeTableHealth(tableStats),
      lockIssues: lockAnalysis,
      summary: this.generateSummary(slowQueries, indexUsage)
    };
  }

  async getSlowQueries(timeRange) {
    const result = await this.pool.query(`
      SELECT 
        query,
        calls,
        total_time,
        mean_time,
        rows,
        shared_blks_hit,
        shared_blks_read
      FROM pg_stat_statements
      WHERE mean_time > 100 -- milliseconds
        AND query_start >= NOW() - INTERVAL '${timeRange}'
      ORDER BY mean_time DESC
      LIMIT 20
    `);
    
    return result.rows;
  }

  async getIndexUsage() {
    const result = await this.pool.query(`
      SELECT 
        schemaname,
        tablename,
        indexname,
        idx_scan as index_scans,
        idx_tup_read as tuples_read,
        idx_tup_fetch as tuples_fetched
      FROM pg_stat_user_indexes
      ORDER BY idx_scan DESC
    `);
    
    return result.rows;
  }

  analyzeSlowQueries(queries) {
    return queries.map(q => ({
      query: q.query.substring(0, 100) + '...',
      calls: q.calls,
      avgTime: q.mean_time,
      totalTime: q.total_time,
      efficiency: (q.shared_blks_hit / (q.shared_blks_hit + q.shared_blks_read || 1)) * 100
    }));
  }

  analyzeIndexUsage(indexes) {
    const unusedIndexes = indexes.filter(idx => idx.index_scans === 0);
    const heavilyUsedIndexes = indexes.filter(idx => idx.index_scans > 10000);
    
    return {
      totalIndexes: indexes.length,
      unusedIndexes: unusedIndexes.length,
      heavilyUsedIndexes: heavilyUsedIndexes.length,
      recommendations: unusedIndexes.map(idx => ({
        action: 'DROP_INDEX',
        index: idx.indexname,
        table: `${idx.schemaname}.${idx.tablename}`,
        reason: 'Index has never been used'
      }))
    };
  }
}

// Query Builder with Optimization
class OptimizedQueryBuilder {
  constructor() {
    this.query = {
      select: [],
      from: null,
      joins: [],
      where: [],
      groupBy: [],
      having: [],
      orderBy: [],
      limit: null,
      offset: null
    };
  }

  select(fields) {
    this.query.select = Array.isArray(fields) ? fields : [fields];
    return this;
  }

  from(table, alias = null) {
    this.query.from = alias ? `${table} AS ${alias}` : table;
    return this;
  }

  join(table, condition, type = 'INNER') {
    this.query.joins.push({
      table,
      condition,
      type: type.toUpperCase()
    });
    return this;
  }

  where(condition, params = []) {
    this.query.where.push({ condition, params });
    return this;
  }

  orderBy(field, direction = 'ASC') {
    this.query.orderBy.push({ field, direction });
    return this;
  }

  limit(value) {
    this.query.limit = value;
    return this;
  }

  offset(value) {
    this.query.offset = value;
    return this;
  }

  build() {
    const parts = [];
    const params = [];
    
    // SELECT
    parts.push(`SELECT ${this.query.select.join(', ')}`);
    
    // FROM
    parts.push(`FROM ${this.query.from}`);
    
    // JOINS
    this.query.joins.forEach(join => {
      parts.push(`${join.type} JOIN ${join.table} ON ${join.condition}`);
    });
    
    // WHERE
    if (this.query.where.length > 0) {
      const whereConditions = this.query.where.map(w => w.condition);
      parts.push(`WHERE ${whereConditions.join(' AND ')}`);
      
      this.query.where.forEach(w => {
        params.push(...w.params);
      });
    }
    
    // ORDER BY
    if (this.query.orderBy.length > 0) {
      const orderClauses = this.query.orderBy.map(o => 
        `${o.field} ${o.direction}`
      );
      parts.push(`ORDER BY ${orderClauses.join(', ')}`);
    }
    
    // LIMIT & OFFSET
    if (this.query.limit !== null) {
      parts.push(`LIMIT $${params.length + 1}`);
      params.push(this.query.limit);
    }
    
    if (this.query.offset !== null) {
      parts.push(`OFFSET $${params.length + 1}`);
      params.push(this.query.offset);
    }
    
    const sql = parts.join(' ');
    
    return {
      sql,
      params,
      explain: async () => {
        const optimizer = new DatabaseOptimizer();
        return optimizer.analyzeQuery(sql, params);
      }
    };
  }

  // Optimization methods
  optimizeForPagination(page, pageSize) {
    // Use keyset pagination instead of OFFSET for large datasets
    if (page > 10) { // Threshold for switching to keyset pagination
      this.query.where.push({
        condition: 'id > $' + (this.query.where.length + 1),
        params: [this.lastId]
      });
      
      this.query.limit = pageSize;
      this.query.offset = null; // Remove offset
    }
    
    return this;
  }

  useCoveringIndex() {
    // Ensure SELECT includes columns needed for covering index
    if (this.query.select.includes('*')) {
      // Replace with explicit columns for better index usage
      console.warn('Consider using explicit columns instead of * for covering index');
    }
    
    return this;
  }
}

// Usage example
const queryBuilder = new OptimizedQueryBuilder();

const query = queryBuilder
  .select(['id', 'name', 'email', 'created_at'])
  .from('users', 'u')
  .join('orders', 'u.id = orders.user_id', 'LEFT')
  .where('u.active = $1', [true])
  .where('orders.created_at > $2', ['2024-01-01'])
  .orderBy('u.created_at', 'DESC')
  .limit(100)
  .build();

console.log(query.sql);
console.log(query.params);

// Analyze the query
query.explain().then(analysis => {
  console.log('Query analysis:', analysis);
});
```

### Indexing Patterns

```javascript
class IndexPatterns {
  // 1. Single Column Index
  static createSingleColumnIndex(table, column) {
    return `CREATE INDEX idx_${table}_${column} ON ${table}(${column})`;
  }

  // 2. Composite Index
  static createCompositeIndex(table, columns, options = {}) {
    const columnList = columns.join(', ');
    const include = options.include ? ` INCLUDE (${options.include.join(', ')})` : '';
    const where = options.where ? ` WHERE ${options.where}` : '';
    
    return `CREATE INDEX idx_${table}_${columns.join('_')} 
            ON ${table}(${columnList})${include}${where}`;
  }

  // 3. Partial Index
  static createPartialIndex(table, columns, condition) {
    return `CREATE INDEX idx_${table}_partial 
            ON ${table}(${columns.join(', ')}) 
            WHERE ${condition}`;
  }

  // 4. Expression Index
  static createExpressionIndex(table, expression, name) {
    return `CREATE INDEX idx_${name} 
            ON ${table}((${expression}))`;
  }

  // 5. Full-text Search Index
  static createFullTextIndex(table, column, language = 'english') {
    return `
      CREATE INDEX idx_${table}_${column}_fts 
      ON ${table} USING gin(to_tsvector('${language}', ${column}));
    `;
  }

  // 6. Spatial Index (PostGIS)
  static createSpatialIndex(table, geometryColumn) {
    return `CREATE INDEX idx_${table}_${geometryColumn}_spatial 
            ON ${table} USING gist(${geometryColumn})`;
  }

  // 7. Unique Index
  static createUniqueIndex(table, columns) {
    return `CREATE UNIQUE INDEX idx_${table}_unique 
            ON ${table}(${columns.join(', ')})`;
  }

  // 8. Concurrent Index (no locking)
  static createConcurrentIndex(table, columns) {
    return `CREATE INDEX CONCURRENTLY idx_${table}_${columns.join('_')} 
            ON ${table}(${columns.join(', ')})`;
  }

  // 9. Index on JSONB fields
  static createJSONBIndex(table, jsonbColumn, path) {
    return `CREATE INDEX idx_${table}_${jsonbColumn}_${path.replace('.', '_')} 
            ON ${table}((${jsonbColumn}->>'${path}'))`;
  }

  // 10. BRIN Index for large sorted tables
  static createBRINIndex(table, column) {
    return `CREATE INDEX idx_${table}_${column}_brin 
            ON ${table} USING brin(${column})`;
  }

  // Index selection helper
  static recommendIndexType(tableSize, queryPattern) {
    const recommendations = [];
    
    if (tableSize > 1000000) { // Large table
      if (queryPattern.includes('range')) {
        recommendations.push('BRIN for large range scans');
      }
      
      if (queryPattern.includes('equality')) {
        recommendations.push('B-tree for equality searches');
      }
    }
    
    if (queryPattern.includes('text search')) {
      recommendations.push('GIN for full-text search');
    }
    
    if (queryPattern.includes('spatial')) {
      recommendations.push('GiST for spatial data');
    }
    
    if (queryPattern.includes('partial')) {
      recommendations.push('Partial index for filtered queries');
    }
    
    return recommendations;
  }
}

// Index monitoring and maintenance
class IndexMaintenance {
  constructor(pool) {
    this.pool = pool;
  }

  async findUnusedIndexes() {
    const query = `
      SELECT 
        schemaname,
        tablename,
        indexname,
        idx_scan as index_scans
      FROM pg_stat_user_indexes
      WHERE idx_scan = 0
      ORDER BY schemaname, tablename;
    `;
    
    const result = await this.pool.query(query);
    return result.rows;
  }

  async findDuplicateIndexes() {
    const query = `
      SELECT 
        indrelid::regclass as table_name,
        array_agg(indexrelid::regclass) as duplicate_indexes
      FROM pg_index
      GROUP BY indrelid, indkey
      HAVING COUNT(*) > 1;
    `;
    
    const result = await this.pool.query(query);
    return result.rows;
  }

  async findBloatedIndexes(threshold = 20) {
    const query = `
      SELECT 
        schemaname,
        tablename,
        indexname,
        pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
        idx_scan as index_scans
      FROM pg_stat_user_indexes
      WHERE pg_relation_size(indexrelid) > 100000000 -- 100MB
        AND idx_scan < 1000
      ORDER BY pg_relation_size(indexrelid) DESC;
    `;
    
    const result = await this.pool.query(query);
    return result.rows;
  }

  async rebuildIndex(indexName, concurrently = true) {
    const concurrentlyStr = concurrently ? 'CONCURRENTLY' : '';
    const query = `REINDEX INDEX ${concurrentlyStr} "${indexName}"`;
    
    await this.pool.query(query);
    console.log(`Rebuilt index: ${indexName}`);
  }

  async vacuumIndexes(tableName) {
    const query = `VACUUM (ANALYZE, VERBOSE) "${tableName}"`;
    await this.pool.query(query);
    console.log(`Vacuumed table: ${tableName}`);
  }

  async optimizeIndexes() {
    console.log('Starting index optimization...');
    
    // 1. Find and remove unused indexes
    const unusedIndexes = await this.findUnusedIndexes();
    for (const idx of unusedIndexes) {
      console.log(`Consider dropping unused index: ${idx.indexname}`);
      // await this.pool.query(`DROP INDEX CONCURRENTLY "${idx.indexname}"`);
    }
    
    // 2. Find and remove duplicate indexes
    const duplicateIndexes = await this.findDuplicateIndexes();
    for (const dup of duplicateIndexes) {
      console.log(`Found duplicate indexes on ${dup.table_name}: ${dup.duplicate_indexes}`);
    }
    
    // 3. Rebuild bloated indexes
    const bloatedIndexes = await this.findBloatedIndexes();
    for (const idx of bloatedIndexes) {
      console.log(`Rebuilding bloated index: ${idx.indexname} (${idx.index_size})`);
      // await this.rebuildIndex(idx.indexname);
    }
    
    // 4. Update statistics
    await this.pool.query('ANALYZE');
    
    console.log('Index optimization complete');
  }

  async generateIndexReport() {
    const report = {
      generated: new Date().toISOString(),
      unusedIndexes: await this.findUnusedIndexes(),
      duplicateIndexes: await this.findDuplicateIndexes(),
      bloatedIndexes: await this.findBloatedIndexes(),
      indexUsage: await this.getIndexUsageStats(),
      recommendations: []
    };
    
    // Generate recommendations
    if (report.unusedIndexes.length > 0) {
      report.recommendations.push({
        type: 'DROP_UNUSED',
        count: report.unusedIndexes.length,
        estimatedSpace: await this.calculateSpaceSavings(report.unusedIndexes)
      });
    }
    
    if (report.bloatedIndexes.length > 0) {
      report.recommendations.push({
        type: 'REBUILD_BLOATED',
        count: report.bloatedIndexes.length
      });
    }
    
    return report;
  }

  async getIndexUsageStats() {
    const query = `
      SELECT 
        SUM(idx_scan) as total_scans,
        SUM(idx_tup_read) as total_reads,
        SUM(idx_tup_fetch) as total_fetches,
        COUNT(*) as total_indexes
      FROM pg_stat_user_indexes;
    `;
    
    const result = await this.pool.query(query);
    return result.rows[0];
  }

  async calculateSpaceSavings(indexes) {
    let totalSize = 0;
    
    for (const idx of indexes) {
      const sizeQuery = `
        SELECT pg_relation_size('${idx.indexname}'::regclass) as size
      `;
      
      const result = await this.pool.query(sizeQuery);
      totalSize += parseInt(result.rows[0].size) || 0;
    }
    
    return this.formatBytes(totalSize);
  }

  formatBytes(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    if (bytes === 0) return '0 Bytes';
    
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
  }
}
```

---

## 7. Rate Limiting Strategies

### In-Depth Explanation
Rate limiting protects APIs from abuse and ensures fair usage. Multiple strategies can be combined for comprehensive protection.

### Multi-Layer Rate Limiting Implementation

```javascript
const Redis = require('ioredis');
const { RateLimiterRedis, RateLimiterMemory } = require('rate-limiter-flexible');
const LRU = require('lru-cache');

class MultiLayerRateLimiter {
  constructor() {
    this.redisClient = new Redis.Cluster([
      { host: process.env.REDIS_HOST, port: process.env.REDIS_PORT }
    ]);
    
    // Layer 1: In-memory cache (fastest)
    this.memoryLimiter = new LRU({
      max: 10000,
      ttl: 1000 // 1 second
    });
    
    // Layer 2: Redis-based distributed limiter
    this.redisLimiters = {
      // IP-based limiting
      ip: new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: 'rl:ip',
        points: 100, // 100 requests
        duration: 60, // per minute
        blockDuration: 300 // block for 5 minutes if exceeded
      }),
      
      // User-based limiting
      user: new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: 'rl:user',
        points: 1000, // 1000 requests
        duration: 3600, // per hour
        blockDuration: 3600
      }),
      
      // API key-based limiting
      apiKey: new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: 'rl:apikey',
        points: 10000, // 10000 requests
        duration: 86400, // per day
        blockDuration: 0
      }),
      
      // Global limiting
      global: new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: 'rl:global',
        points: 100000, // 100K requests
        duration: 3600, // per hour
        blockDuration: 0
      })
    };
    
    // Layer 3: Adaptive rate limiting
    this.adaptiveLimiter = new AdaptiveRateLimiter();
    
    // Layer 4: Geo-based limiting
    this.geoLimiter = new GeoRateLimiter();
  }

  // 1. Fixed Window Algorithm
  async fixedWindow(key, limit, windowSeconds) {
    const now = Math.floor(Date.now() / 1000);
    const window = Math.floor(now / windowSeconds);
    const redisKey = `fw:${key}:${window}`;
    
    const current = await this.redisClient.incr(redisKey);
    
    if (current === 1) {
      await this.redisClient.expire(redisKey, windowSeconds);
    }
    
    return current <= limit;
  }

  // 2. Sliding Window Algorithm
  async slidingWindow(key, limit, windowSeconds) {
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);
    
    const redisKey = `sw:${key}`;
    
    // Remove old timestamps
    await this.redisClient.zremrangebyscore(redisKey, 0, windowStart);
    
    // Add current timestamp
    await this.redisClient.zadd(redisKey, now, now.toString());
    
    // Count requests in window
    const count = await this.redisClient.zcount(redisKey, windowStart, now);
    
    // Set TTL
    await this.redisClient.expire(redisKey, windowSeconds);
    
    return count <= limit;
  }

  // 3. Token Bucket Algorithm
  async tokenBucket(key, capacity, refillRate) {
    const redisKey = `tb:${key}`;
    
    const script = `
      local key = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local refillRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      
      local bucket = redis.call('hmget', key, 'tokens', 'lastRefill')
      
      local tokens = 0
      local lastRefill = now
      
      if bucket[1] then
        tokens = tonumber(bucket[1])
        lastRefill = tonumber(bucket[2])
      end
      
      -- Calculate refill
      local timePassed = now - lastRefill
      local refillAmount = math.floor(timePassed * refillRate / 1000)
      
      if refillAmount > 0 then
        tokens = math.min(capacity, tokens + refillAmount)
        lastRefill = now
      end
      
      -- Check if request can be processed
      if tokens >= 1 then
        tokens = tokens - 1
        redis.call('hmset', key, 'tokens', tokens, 'lastRefill', lastRefill)
        redis.call('expire', key, math.ceil(capacity / refillRate) * 2)
        return 1
      else
        return 0
      end
    `;
    
    const result = await this.redisClient.eval(
      script,
      1,
      redisKey,
      capacity,
      refillRate,
      Date.now()
    );
    
    return result === 1;
  }

  // 4. Leaky Bucket Algorithm
  async leakyBucket(key, capacity, leakRate) {
    const redisKey = `lb:${key}`;
    const now = Date.now();
    
    const script = `
      local key = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local leakRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      
      local bucket = redis.call('hmget', key, 'volume', 'lastLeak')
      
      local volume = 0
      local lastLeak = now
      
      if bucket[1] then
        volume = tonumber(bucket[1])
        lastLeak = tonumber(bucket[2])
      end
      
      -- Calculate leak
      local timePassed = now - lastLeak
      local leakAmount = math.floor(timePassed * leakRate / 1000)
      
      if leakAmount > 0 then
        volume = math.max(0, volume - leakAmount)
        lastLeak = now
      end
      
      -- Check if request can be added
      if volume < capacity then
        volume = volume + 1
        redis.call('hmset', key, 'volume', volume, 'lastLeak', lastLeak)
        redis.call('expire', key, math.ceil(capacity / leakRate) * 2)
        return 1
      else
        return 0
      end
    `;
    
    const result = await this.redisClient.eval(
      script,
      1,
      redisKey,
      capacity,
      leakRate,
      now
    );
    
    return result === 1;
  }

  // 5. Multi-dimensional rate limiting
  async multiDimensionalLimit(req, res, next) {
    const ip = req.ip;
    const userId = req.user?.id;
    const apiKey = req.headers['x-api-key'];
    const endpoint = req.path;
    const userAgent = req.headers['user-agent'];
    
    const limiters = [];
    
    // IP-based limiting (strict)
    limiters.push({
      key: `ip:${ip}`,
      limiter: this.redisLimiters.ip,
      weight: 1
    });
    
    // User-based limiting (if authenticated)
    if (userId) {
      limiters.push({
        key: `user:${userId}`,
        limiter: this.redisLimiters.user,
        weight: 1
      });
    }
    
    // API key-based limiting
    if (apiKey) {
      limiters.push({
        key: `apikey:${apiKey}`,
        limiter: this.redisLimiters.apiKey,
        weight: 1
      });
    }
    
    // Endpoint-specific limiting
    limiters.push({
      key: `endpoint:${endpoint}:${ip}`,
      limiter: new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: 'rl:endpoint',
        points: 10, // 10 requests
        duration: 60 // per minute
      }),
      weight: 1
    });
    
    // Global limiting
    limiters.push({
      key: 'global',
      limiter: this.redisLimiters.global,
      weight: 0.1 // Lower weight for global limit
    });
    
    // Check all limiters
    try {
      for (const { key, limiter, weight } of limiters) {
        await limiter.consume(key, weight);
      }
      
      next();
    } catch (error) {
      // Determine which limiter failed
      const retryAfter = Math.ceil(error.msBeforeNext / 1000) || 1;
      
      res.set('Retry-After', retryAfter);
      res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter,
        message: 'Too many requests, please try again later.'
      });
    }
  }

  // 6. Adaptive rate limiting based on system load
  async adaptiveLimit(req, res, next) {
    const systemLoad = await this.getSystemLoad();
    const currentLimit = this.adaptiveLimiter.calculateLimit(systemLoad);
    
    const key = `adaptive:${req.ip}`;
    const limiter = new RateLimiterRedis({
      storeClient: this.redisClient,
      keyPrefix: 'rl:adaptive',
      points: currentLimit,
      duration: 60
    });
    
    try {
      await limiter.consume(key);
      next();
    } catch (error) {
      res.status(429).json({
        error: 'Rate limit exceeded',
        currentLimit,
        message: 'System under heavy load, rate limits reduced.'
      });
    }
  }

  async getSystemLoad() {
    // Get CPU load, memory usage, etc.
    const cpuLoad = require('os').loadavg()[0];
    const freeMemory = require('os').freemem() / require('os').totalmem();
    
    return {
      cpuLoad,
      memoryUsage: 1 - freeMemory,
      timestamp: Date.now()
    };
  }

  // 7. Rate limiting with burst allowance
  async burstLimit(key, sustainedLimit, burstLimit, windowSeconds) {
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);
    
    const redisKey = `burst:${key}`;
    
    // Get all timestamps in window
    const timestamps = await this.redisClient.zrangebyscore(
      redisKey,
      windowStart,
      now
    );
    
    const burstWindow = 1000; // 1 second for burst
    const burstStart = now - burstWindow;
    
    // Count burst requests
    const burstCount = timestamps.filter(ts => 
      parseInt(ts) >= burstStart
    ).length;
    
    // Count sustained requests
    const sustainedCount = timestamps.length;
    
    // Check limits
    if (burstCount >= burstLimit) {
      return false; // Burst limit exceeded
    }
    
    if (sustainedCount >= sustainedLimit) {
      return false; // Sustained limit exceeded
    }
    
    // Add current request
    await this.redisClient.zadd(redisKey, now, now.toString());
    await this.redisClient.zremrangebyscore(redisKey, 0, windowStart);
    await this.redisClient.expire(redisKey, windowSeconds);
    
    return true;
  }

  // 8. Rate limiting with cost-based weights
  async costBasedLimit(key, cost, limit, windowSeconds) {
    const redisKey = `cost:${key}`;
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);
    
    const script = `
      local key = KEYS[1]
      local cost = tonumber(ARGV[1])
      local limit = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      local windowStart = tonumber(ARGV[4])
      
      -- Remove old entries
      redis.call('zremrangebyscore', key, 0, windowStart)
      
      -- Get current total cost
      local entries = redis.call('zrange', key, 0, -1, 'WITHSCORES')
      local totalCost = 0
      
      for i = 1, #entries, 2 do
        totalCost = totalCost + tonumber(entries[i])
      end
      
      -- Check if request can be processed
      if totalCost + cost <= limit then
        -- Add request with cost as score
        redis.call('zadd', key, now, cost)
        redis.call('expire', key, ${windowSeconds})
        return 1
      else
        return 0
      end
    `;
    
    const result = await this.redisClient.eval(
      script,
      1,
      redisKey,
      cost,
      limit,
      now,
      windowStart
    );
    
    return result === 1;
  }

  // 9. Whitelist/Blacklist management
  async manageAccessList(type, identifier, action) {
    const listKey = type === 'whitelist' ? 'whitelist' : 'blacklist';
    
    switch (action) {
      case 'add':
        await this.redisClient.sadd(listKey, identifier);
        break;
      case 'remove':
        await this.redisClient.srem(listKey, identifier);
        break;
      case 'check':
        const isMember = await this.redisClient.sismember(listKey, identifier);
        return isMember === 1;
    }
    
    await this.redisClient.expire(listKey, 86400 * 30); // 30 days
  }

  // 10. Rate limit headers in response
  addRateLimitHeaders(req, res, limits) {
    res.set('X-RateLimit-Limit', limits.limit);
    res.set('X-RateLimit-Remaining', limits.remaining);
    res.set('X-RateLimit-Reset', limits.reset);
    
    if (limits.retryAfter) {
      res.set('Retry-After', limits.retryAfter);
    }
  }
}

class AdaptiveRateLimiter {
  constructor() {
    this.baseLimit = 100;
    this.minLimit = 10;
    this.maxLimit = 1000;
    this.metrics = [];
    this.metricWindow = 60000; // 1 minute
  }

  addMetric(responseTime, errorRate) {
    this.metrics.push({
      timestamp: Date.now(),
      responseTime,
      errorRate
    });
    
    // Remove old metrics
    const cutoff = Date.now() - this.metricWindow;
    this.metrics = this.metrics.filter(m => m.timestamp > cutoff);
  }

  calculateLimit(systemLoad) {
    const avgResponseTime = this.getAverageResponseTime();
    const avgErrorRate = this.getAverageErrorRate();
    
    let limit = this.baseLimit;
    
    // Adjust based on response time
    if (avgResponseTime > 1000) { // Slow response
      limit = Math.max(this.minLimit, limit * 0.5);
    } else if (avgResponseTime < 100) { // Fast response
      limit = Math.min(this.maxLimit, limit * 1.5);
    }
    
    // Adjust based on error rate
    if (avgErrorRate > 5) { // High error rate
      limit = Math.max(this.minLimit, limit * 0.7);
    }
    
    // Adjust based on system load
    if (systemLoad.cpuLoad > 2) { // High CPU load
      limit = Math.max(this.minLimit, limit * 0.6);
    }
    
    return Math.round(limit);
  }

  getAverageResponseTime() {
    if (this.metrics.length === 0) return 0;
    
    const sum = this.metrics.reduce((acc, m) => acc + m.responseTime, 0);
    return sum / this.metrics.length;
  }

  getAverageErrorRate() {
    if (this.metrics.length === 0) return 0;
    
    const sum = this.metrics.reduce((acc, m) => acc + m.errorRate, 0);
    return sum / this.metrics.length;
  }
}

class GeoRateLimiter {
  constructor() {
    this.countryLimits = new Map([
      ['US', 1000], // United States
      ['GB', 800],  // United Kingdom
      ['DE', 800],  // Germany
      ['IN', 500],  // India
      ['CN', 300],  // China
      ['RU', 200],  // Russia
      // Default
      ['DEFAULT', 100]
    ]);
    
    this.suspiciousCountries = new Set(['CN', 'RU', 'KP']);
  }

  async getCountryFromIP(ip) {
    // Use geoip service or local database
    // This is a simplified example
    const geoResponse = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await geoResponse.json();
    
    return data.countryCode || 'DEFAULT';
  }

  async checkGeoLimit(ip) {
    const country = await this.getCountryFromIP(ip);
    const limit = this.countryLimits.get(country) || this.countryLimits.get('DEFAULT');
    
    // Stricter limits for suspicious countries
    if (this.suspiciousCountries.has(country)) {
      return {
        allowed: false,
        reason: 'Country restricted',
        limit: 0
      };
    }
    
    return {
      allowed: true,
      country,
      limit
    };
  }
}

// Express middleware for comprehensive rate limiting
const rateLimitMiddleware = (options = {}) => {
  const {
    windowMs = 60000, // 1 minute
    max = 100,
    skipSuccessfulRequests = false,
    keyGenerator = (req) => req.ip,
    skip = () => false,
    handler = (req, res) => {
      res.status(429).json({
        error: 'Too many requests',
        message: 'Please try again later.'
      });
    }
  } = options;
  
  const limiter = new MultiLayerRateLimiter();
  
  return async (req, res, next) => {
    // Skip rate limiting for certain conditions
    if (skip(req)) {
      return next();
    }
    
    // Skip if request was successful (optional)
    if (skipSuccessfulRequests) {
      const originalSend = res.send;
      res.send = function(body) {
        if (res.statusCode < 400) {
          // Request was successful, don't count it
          return originalSend.call(this, body);
        }
        originalSend.call(this, body);
      };
    }
    
    const key = keyGenerator(req);
    
    try {
      // Check multiple rate limiting strategies
      const allowed = await Promise.all([
        limiter.fixedWindow(key, max, windowMs / 1000),
        limiter.slidingWindow(key, max, windowMs / 1000),
        limiter.burstLimit(key, max, max * 2, windowMs / 1000)
      ]);
      
      if (allowed.every(a => a)) {
        next();
      } else {
        handler(req, res);
      }
    } catch (error) {
      console.error('Rate limiting error:', error);
      next(); // Allow request on error
    }
  };
};

// Usage examples
const app = require('express')();

// Basic rate limiting
app.use('/api/', rateLimitMiddleware({
  windowMs: 60000,
  max: 100,
  message: 'Too many requests from this IP'
}));

// Stricter rate limiting for auth endpoints
app.use('/api/auth/', rateLimitMiddleware({
  windowMs: 3600000, // 1 hour
  max: 5,
  message: 'Too many login attempts'
}));

// API key based rate limiting
app.use('/api/v1/', async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (apiKey) {
    const limiter = new MultiLayerRateLimiter();
    const allowed = await limiter.costBasedLimit(
      `apikey:${apiKey}`,
      1, // cost per request
      10000, // limit
      86400 // per day
    );
    
    if (!allowed) {
      return res.status(429).json({ error: 'API quota exceeded' });
    }
  }
  
  next();
});

// Dynamic rate limiting based on endpoint
app.use('/api/:endpoint', (req, res, next) => {
  const endpoint = req.params.endpoint;
  const limits = {
    'users': { windowMs: 60000, max: 100 },
    'orders': { windowMs: 60000, max: 200 },
    'reports': { windowMs: 3600000, max: 10 }
  };
  
  const endpointLimit = limits[endpoint] || limits.users;
  
  rateLimitMiddleware(endpointLimit)(req, res, next);
});
```

---

## 8. Queues & Async Processing

### In-Depth Explanation
Message queues enable asynchronous processing, decouple services, and handle workload spikes efficiently.

### Comprehensive Queue System Implementation

```javascript
const Bull = require('bull');
const Redis = require('ioredis');
const amqp = require('amqplib');
const EventEmitter = require('events');

class QueueSystem {
  constructor() {
    this.queues = new Map();
    this.redisClient = new Redis.Cluster([
      { host: process.env.REDIS_HOST, port: process.env.REDIS_PORT }
    ]);
    
    this.eventEmitter = new EventEmitter();
    this.workerPool = new WorkerPool();
    this.dlqManager = new DeadLetterQueueManager();
    
    this.setupQueues();
    this.setupMonitoring();
  }

  setupQueues() {
    // Priority queues
    this.createQueue('high-priority', {
      defaultJobOptions: {
        priority: 1,
        attempts: 5,
        backoff: {
          type: 'exponential',
          delay: 1000
        }
      },
      limiter: {
        max: 100,
        duration: 1000
      }
    });
    
    this.createQueue('normal-priority', {
      defaultJobOptions: {
        priority: 5,
        attempts: 3
      }
    });
    
    this.createQueue('low-priority', {
      defaultJobOptions: {
        priority: 10,
        attempts: 1
      }
    });
    
    // Delayed queue for scheduled tasks
    this.createQueue('delayed', {
      defaultJobOptions: {
        delay: 0,
        attempts: 3
      }
    });
    
    // Batch processing queue
    this.createQueue('batch', {
      defaultJobOptions: {
        attempts: 3
      }
    });
  }

  createQueue(name, options = {}) {
    const queue = new Bull(name, {
      redis: {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT
      },
      ...options
    });
    
    // Set up event listeners
    this.setupQueueEvents(queue);
    
    this.queues.set(name, queue);
    return queue;
  }

  setupQueueEvents(queue) {
    queue.on('completed', (job, result) => {
      console.log(`Job ${job.id} completed`);
      this.eventEmitter.emit('job:completed', { job, result });
    });
    
    queue.on('failed', (job, error) => {
      console.error(`Job ${job.id} failed:`, error);
      this.eventEmitter.emit('job:failed', { job, error });
      
      // Move to DLQ after retries exhausted
      if (job.attemptsMade >= job.opts.attempts) {
        this.dlqManager.addToDLQ(job, error);
      }
    });
    
    queue.on('stalled', (job) => {
      console.warn(`Job ${job.id} stalled`);
      this.eventEmitter.emit('job:stalled', { job });
    });
    
    queue.on('progress', (job, progress) => {
      this.eventEmitter.emit('job:progress', { job, progress });
    });
  }

  // 1. Job Submission Patterns
  async submitJob(queueName, jobData, options = {}) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const jobOptions = {
      jobId: options.jobId || this.generateJobId(),
      delay: options.delay || 0,
      priority: options.priority || Bull.DEFAULT_PRIORITY,
      attempts: options.attempts || 3,
      backoff: options.backoff || {
        type: 'exponential',
        delay: 1000
      },
      removeOnComplete: options.removeOnComplete || true,
      removeOnFail: options.removeOnFail || false,
      timeout: options.timeout || 30000,
      lifo: options.lifo || false
    };
    
    const job = await queue.add(jobData, jobOptions);
    
    console.log(`Submitted job ${job.id} to queue ${queueName}`);
    
    return {
      jobId: job.id,
      queue: queueName,
      timestamp: new Date().toISOString()
    };
  }

  // 2. Batch Processing
  async submitBatchJobs(queueName, jobsData, batchSize = 100) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const batches = [];
    
    for (let i = 0; i < jobsData.length; i += batchSize) {
      const batch = jobsData.slice(i, i + batchSize);
      const batchJobs = batch.map((jobData, index) => ({
        name: 'batch-job',
        data: jobData,
        opts: {
          jobId: `${Date.now()}_${i + index}`,
          priority: Bull.DEFAULT_PRIORITY
        }
      }));
      
      const jobs = await queue.addBulk(batchJobs);
      batches.push({
        batchId: i / batchSize,
        jobs: jobs.map(j => j.id),
        count: jobs.length
      });
    }
    
    return {
      totalJobs: jobsData.length,
      batches,
      batchSize
    };
  }

  // 3. Delayed Jobs
  async scheduleJob(queueName, jobData, delayMs, options = {}) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const job = await queue.add(jobData, {
      delay: delayMs,
      ...options
    });
    
    console.log(`Scheduled job ${job.id} to run in ${delayMs}ms`);
    
    return job;
  }

  // 4. Recurring Jobs (Cron-like)
  async createRecurringJob(queueName, jobData, pattern, options = {}) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const job = await queue.add(jobData, {
      repeat: { cron: pattern },
      jobId: options.jobId || `recurring_${Date.now()}`,
      ...options
    });
    
    console.log(`Created recurring job ${job.id} with pattern ${pattern}`);
    
    return job;
  }

  // 5. Job Dependency Management
  async submitJobWithDependencies(queueName, jobData, dependencies, options = {}) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    // Wait for dependencies to complete
    await this.waitForDependencies(dependencies);
    
    const job = await queue.add(jobData, options);
    
    console.log(`Submitted job ${job.id} with ${dependencies.length} dependencies`);
    
    return job;
  }

  async waitForDependencies(jobIds) {
    const promises = jobIds.map(jobId => 
      this.waitForJobCompletion(jobId)
    );
    
    await Promise.all(promises);
  }

  async waitForJobCompletion(jobId, timeout = 300000) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Timeout waiting for job ${jobId}`));
      }, timeout);
      
      const listener = ({ job }) => {
        if (job.id === jobId) {
          clearTimeout(timeoutId);
          this.eventEmitter.removeListener('job:completed', listener);
          this.eventEmitter.removeListener('job:failed', listener);
          resolve(job);
        }
      };
      
      this.eventEmitter.on('job:completed', listener);
      this.eventEmitter.on('job:failed', listener);
    });
  }

  // 6. Job Priority Management
  async prioritizeJob(queueName, jobId, newPriority) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const job = await queue.getJob(jobId);
    
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }
    
    await job.updatePriority(newPriority);
    
    console.log(`Updated priority of job ${jobId} to ${newPriority}`);
    
    return job;
  }

  // 7. Job Pausing/Resuming
  async pauseQueue(queueName) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    await queue.pause();
    console.log(`Paused queue ${queueName}`);
  }

  async resumeQueue(queueName) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    await queue.resume();
    console.log(`Resumed queue ${queueName}`);
  }

  // 8. Queue Monitoring and Metrics
  async getQueueMetrics(queueName) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const [
      waiting,
      active,
      completed,
      failed,
      delayed
    ] = await Promise.all([
      queue.getWaitingCount(),
      queue.getActiveCount(),
      queue.getCompletedCount(),
      queue.getFailedCount(),
      queue.getDelayedCount()
    ]);
    
    return {
      queue: queueName,
      waiting,
      active,
      completed,
      failed,
      delayed,
      total: waiting + active + completed + failed + delayed,
      timestamp: new Date().toISOString()
    };
  }

  // 9. Worker Pool Management
  async processQueue(queueName, processor, concurrency = 1) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    queue.process(concurrency, async (job) => {
      const worker = await this.workerPool.acquireWorker();
      
      try {
        console.log(`Processing job ${job.id} on worker ${worker.id}`);
        
        const result = await worker.execute(processor, job.data);
        
        await this.workerPool.releaseWorker(worker);
        
        return result;
      } catch (error) {
        await this.workerPool.releaseWorker(worker);
        throw error;
      }
    });
    
    console.log(`Started processing queue ${queueName} with concurrency ${concurrency}`);
  }

  // 10. Dead Letter Queue Management
  async retryFailedJobs(queueName, count = 100) {
    const queue = this.queues.get(queueName);
    
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }
    
    const failedJobs = await queue.getFailed(0, count);
    
    console.log(`Retrying ${failedJobs.length} failed jobs from ${queueName}`);
    
    const results = await Promise.allSettled(
      failedJobs.map(job => job.retry())
    );
    
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    return {
      attempted: failedJobs.length,
      successful,
      failed
    };
  }

  setupMonitoring() {
    setInterval(async () => {
      for (const [queueName, queue] of this.queues) {
        const metrics = await this.getQueueMetrics(queueName);
        
        // Check for queue health
        if (metrics.waiting > 10000) {
          console.warn(`Queue ${queueName} has ${metrics.waiting} waiting jobs`);
          this.eventEmitter.emit('queue:congested', { queueName, metrics });
        }
        
        if (metrics.failed > 100) {
          console.warn(`Queue ${queueName} has ${metrics.failed} failed jobs`);
          this.eventEmitter.emit('queue:failed-jobs', { queueName, metrics });
        }
      }
    }, 60000); // Check every minute
  }

  generateJobId() {
    return `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

class WorkerPool {
  constructor() {
    this.workers = [];
    this.maxWorkers = 10;
    this.idleWorkers = [];
    this.activeWorkers = new Set();
    
    this.initializeWorkers();
  }

  initializeWorkers() {
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = {
        id: i,
        status: 'idle',
        lastUsed: null,
        execute: async (processor, data) => {
          this.setWorkerStatus(worker, 'active');
          worker.lastUsed = Date.now();
          
          try {
            const result = await processor(data);
            this.setWorkerStatus(worker, 'idle');
            return result;
          } catch (error) {
            this.setWorkerStatus(worker, 'idle');
            throw error;
          }
        }
      };
      
      this.workers.push(worker);
      this.idleWorkers.push(worker);
    }
  }

  async acquireWorker() {
    if (this.idleWorkers.length === 0) {
      // No idle workers, wait for one to become available
      return new Promise((resolve) => {
        const checkInterval = setInterval(() => {
          if (this.idleWorkers.length > 0) {
            clearInterval(checkInterval);
            resolve(this.acquireWorker());
          }
        }, 100);
      });
    }
    
    const worker = this.idleWorkers.shift();
    this.activeWorkers.add(worker);
    
    return worker;
  }

  releaseWorker(worker) {
    this.activeWorkers.delete(worker);
    this.idleWorkers.push(worker);
    this.setWorkerStatus(worker, 'idle');
  }

  setWorkerStatus(worker, status) {
    worker.status = status;
    
    if (status === 'idle') {
      worker.lastUsed = Date.now();
    }
  }

  getStats() {
    return {
      totalWorkers: this.workers.length,
      idleWorkers: this.idleWorkers.length,
      activeWorkers: this.activeWorkers.size,
      utilization: (this.activeWorkers.size / this.workers.length * 100).toFixed(2)
    };
  }
}

class DeadLetterQueueManager {
  constructor() {
    this.dlq = new Bull('dead-letter-queue', {
      redis: {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT
      }
    });
    
    this.setupDLQProcessing();
  }

  async addToDLQ(job, error) {
    const dlqEntry = {
      originalJobId: job.id,
      originalQueue: job.queue.name,
      jobData: job.data,
      error: {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      },
      attemptsMade: job.attemptsMade,
      failedAt: job.finishedOn,
      metadata: job.opts
    };
    
    await this.dlq.add(dlqEntry, {
      jobId: `dlq_${job.id}_${Date.now()}`
    });
    
    console.log(`Added job ${job.id} to DLQ`);
  }

  setupDLQProcessing() {
    this.dlq.process(async (job) => {
      console.log(`Processing DLQ entry for job ${job.data.originalJobId}`);
      
      // Try to reprocess or notify administrators
      await this.handleDLQEntry(job.data);
      
      return { processed: true, timestamp: new Date().toISOString() };
    });
  }

  async handleDLQEntry(entry) {
    // Send alert
    await this.sendAlert(entry);
    
    // Log for manual intervention
    console.error('DLQ Entry:', {
      jobId: entry.originalJobId,
      queue: entry.originalQueue,
      error: entry.error.message,
      attempts: entry.attemptsMade
    });
    
    // Optionally try to reprocess
    if (this.shouldRetry(entry)) {
      await this.retryJob(entry);
    }
  }

  async sendAlert(entry) {
    // Send alert via email, Slack, etc.
    const alertMessage = `
      🚨 DEAD LETTER QUEUE ALERT
      
      Job ID: ${entry.originalJobId}
      Queue: ${entry.originalQueue}
      Error: ${entry.error.message}
      Attempts: ${entry.attemptsMade}
      Timestamp: ${new Date(entry.failedAt).toISOString()}
      
      Job Data: ${JSON.stringify(entry.jobData, null, 2)}
    `;
    
    console.log('ALERT:', alertMessage);
    
    // Implement actual alert sending
  }

  shouldRetry(entry) {
    // Don't retry if too many attempts already
    if (entry.attemptsMade >= 5) return false;
    
    // Don't retry certain types of errors
    const nonRetryableErrors = [
      'ValidationError',
      'AuthorizationError',
      'InvalidInput'
    ];
    
    return !nonRetryableErrors.some(errorType => 
      entry.error.message.includes(errorType)
    );
  }

  async retryJob(entry) {
    console.log(`Retrying job ${entry.originalJobId} from DLQ`);
    
    // Implement retry logic
    // This would involve re-queueing the job with modified options
  }
}

// AMQP/RabbitMQ Integration
class RabbitMQManager {
  constructor() {
    this.connection = null;
    this.channel = null;
    this.queues = new Map();
    this.exchanges = new Map();
  }

  async connect() {
    this.connection = await amqp.connect(process.env.RABBITMQ_URL);
    this.channel = await this.connection.createChannel();
    
    console.log('Connected to RabbitMQ');
    
    // Setup connection error handling
    this.connection.on('error', (error) => {
      console.error('RabbitMQ connection error:', error);
      this.reconnect();
    });
    
    this.connection.on('close', () => {
      console.log('RabbitMQ connection closed');
      this.reconnect();
    });
  }

  async reconnect() {
    console.log('Attempting to reconnect to RabbitMQ...');
    
    setTimeout(async () => {
      try {
        await this.connect();
      } catch (error) {
        console.error('Reconnection failed:', error);
        this.reconnect();
      }
    }, 5000);
  }

  // 1. Work Queue Pattern
  async createWorkQueue(queueName, options = {}) {
    await this.channel.assertQueue(queueName, {
      durable: true,
      ...options
    });
    
    this.queues.set(queueName, {
      name: queueName,
      options,
      consumerCount: 0
    });
    
    return queueName;
  }

  // 2. Publish/Subscribe Pattern
  async createExchange(exchangeName, type = 'fanout') {
    await this.channel.assertExchange(exchangeName, type, {
      durable: true
    });
    
    this.exchanges.set(exchangeName, {
      name: exchangeName,
      type,
      queues: []
    });
    
    return exchangeName;
  }

  async bindQueueToExchange(queueName, exchangeName, routingKey = '') {
    await this.channel.bindQueue(queueName, exchangeName, routingKey);
    
    const exchange = this.exchanges.get(exchangeName);
    if (exchange) {
      exchange.queues.push({ queueName, routingKey });
    }
  }

  // 3. Routing Pattern
  async createRoutingExchange(exchangeName) {
    return this.createExchange(exchangeName, 'direct');
  }

  // 4. Topics Pattern
  async createTopicsExchange(exchangeName) {
    return this.createExchange(exchangeName, 'topic');
  }

  // 5. RPC Pattern
  async createRPCQueue(queueName) {
    const { queue } = await this.channel.assertQueue('', {
      exclusive: true
    });
    
    this.queues.set(queueName, {
      name: queue,
      isRPC: true
    });
    
    return queue;
  }

  async publishRPCRequest(queueName, message, timeout = 30000) {
    const correlationId = this.generateCorrelationId();
    const replyTo = await this.createRPCQueue(`rpc_reply_${correlationId}`);
    
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.channel.deleteQueue(replyTo);
        reject(new Error('RPC timeout'));
      }, timeout);
      
      // Set up consumer for response
      this.channel.consume(replyTo, (msg) => {
        if (msg.properties.correlationId === correlationId) {
          clearTimeout(timeoutId);
          this.channel.ack(msg);
          this.channel.deleteQueue(replyTo);
          
          resolve(JSON.parse(msg.content.toString()));
        }
      }, { noAck: false });
      
      // Send request
      this.channel.sendToQueue(queueName, 
        Buffer.from(JSON.stringify(message)), {
          correlationId,
          replyTo
        }
      );
    });
  }

  // 6. Message Persistence
  async publishPersistentMessage(exchangeName, routingKey, message, options = {}) {
    const persistent = options.persistent !== false;
    
    this.channel.publish(exchangeName, routingKey, 
      Buffer.from(JSON.stringify(message)), {
        persistent,
        ...options
      }
    );
    
    console.log(`Published persistent message to ${exchangeName} with routing key ${routingKey}`);
  }

  // 7. Message Acknowledgment
  async consumeWithAck(queueName, processor, options = {}) {
    const prefetchCount = options.prefetch || 1;
    await this.channel.prefetch(prefetchCount);
    
    await this.channel.consume(queueName, async (msg) => {
      if (msg !== null) {
        try {
          const message = JSON.parse(msg.content.toString());
          await processor(message);
          
          this.channel.ack(msg);
          console.log(`Processed message from ${queueName}`);
        } catch (error) {
          console.error(`Error processing message from ${queueName}:`, error);
          
          // Negative acknowledgment with requeue
          this.channel.nack(msg, false, options.requeue !== false);
        }
      }
    }, {
      noAck: false
    });
    
    console.log(`Started consuming from ${queueName} with acknowledgment`);
  }

  // 8. Dead Letter Exchanges
  async setupDeadLetterExchange(queueName, dlxName, dlxRoutingKey) {
    await this.channel.assertQueue(queueName, {
      durable: true,
      deadLetterExchange: dlxName,
      deadLetterRoutingKey: dlxRoutingKey
    });
    
    console.log(`Setup DLX ${dlxName} for queue ${queueName}`);
  }

  // 9. Message TTL
  async createQueueWithTTL(queueName, ttlMs) {
    await this.channel.assertQueue(queueName, {
      durable: true,
      messageTtl: ttlMs
    });
    
    console.log(`Created queue ${queueName} with TTL ${ttlMs}ms`);
  }

  // 10. Priority Queues
  async createPriorityQueue(queueName, maxPriority = 10) {
    await this.channel.assertQueue(queueName, {
      durable: true,
      maxPriority
    });
    
    console.log(`Created priority queue ${queueName} with max priority ${maxPriority}`);
  }

  async publishWithPriority(queueName, message, priority) {
    this.channel.sendToQueue(queueName,
      Buffer.from(JSON.stringify(message)), {
        persistent: true,
        priority
      }
    );
    
    console.log(`Published message with priority ${priority} to ${queueName}`);
  }

  generateCorrelationId() {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async getQueueStats(queueName) {
    const queueInfo = await this.channel.checkQueue(queueName);
    
    return {
      name: queueName,
      messageCount: queueInfo.messageCount,
      consumerCount: queueInfo.consumerCount,
      ...queueInfo
    };
  }

  async close() {
    if (this.channel) {
      await this.channel.close();
    }
    
    if (this.connection) {
      await this.connection.close();
    }
    
    console.log('RabbitMQ connection closed');
  }
}

// Kafka Integration
class KafkaManager {
  constructor() {
    this.kafka = require('kafkajs');
    this.producer = null;
    this.consumer = null;
    this.admin = null;
  }

  async connect() {
    const { Kafka } = this.kafka;
    
    this.kafkaClient = new Kafka({
      clientId: 'node-queue-system',
      brokers: process.env.KAFKA_BROKERS.split(','),
      ssl: process.env.KAFKA_SSL === 'true',
      sasl: process.env.KAFKA_USERNAME ? {
        mechanism: 'plain',
        username: process.env.KAFKA_USERNAME,
        password: process.env.KAFKA_PASSWORD
      } : undefined
    });
    
    this.producer = this.kafkaClient.producer();
    this.admin = this.kafkaClient.admin();
    
    await this.producer.connect();
    await this.admin.connect();
    
    console.log('Connected to Kafka');
  }

  // 1. Topic Management
  async createTopic(topic, partitions = 3, replicationFactor = 1) {
    await this.admin.createTopics({
      topics: [{
        topic,
        numPartitions: partitions,
        replicationFactor
      }]
    });
    
    console.log(`Created topic ${topic} with ${partitions} partitions`);
  }

  // 2. Message Production
  async produce(topic, messages, options = {}) {
    const kafkaMessages = Array.isArray(messages) ? messages : [messages];
    
    const formattedMessages = kafkaMessages.map(msg => ({
      value: JSON.stringify(msg.value || msg),
      key: msg.key || null,
      headers: msg.headers || {},
      timestamp: msg.timestamp || Date.now().toString()
    }));
    
    await this.producer.send({
      topic,
      messages: formattedMessages,
      acks: options.acks || -1, // -1 = all replicas
      timeout: options.timeout || 30000
    });
    
    console.log(`Produced ${formattedMessages.length} messages to ${topic}`);
  }

  // 3. Message Consumption
  async consume(topic, groupId, processor, options = {}) {
    this.consumer = this.kafkaClient.consumer({
      groupId,
      sessionTimeout: options.sessionTimeout || 30000,
      heartbeatInterval: options.heartbeatInterval || 3000,
      maxBytesPerPartition: options.maxBytesPerPartition || 1048576, // 1MB
      retry: options.retry || {
        initialRetryTime: 100,
        retries: 8
      }
    });
    
    await this.consumer.connect();
    await this.consumer.subscribe({ topic, fromBeginning: options.fromBeginning || false });
    
    await this.consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const value = JSON.parse(message.value.toString());
          await processor(value, {
            topic,
            partition,
            offset: message.offset,
            timestamp: message.timestamp,
            headers: message.headers
          });
        } catch (error) {
          console.error(`Error processing Kafka message:`, error);
          
          if (options.dlqTopic) {
            await this.sendToDLQ(topic, message, error, options.dlqTopic);
          }
        }
      },
      eachBatch: options.eachBatch || undefined
    });
    
    console.log(`Started consuming from topic ${topic} in group ${groupId}`);
  }

  // 4. Exactly-once Semantics
  async produceTransactional(topic, messages, transactionalId) {
    const producer = this.kafkaClient.producer({
      transactionalId,
      maxInFlightRequests: 1,
      idempotent: true
    });
    
    await producer.connect();
    
    const transaction = await producer.transaction();
    
    try {
      await transaction.send({
        topic,
        messages: messages.map(msg => ({
          value: JSON.stringify(msg)
        }))
      });
      
      await transaction.commit();
      console.log(`Transaction ${transactionalId} committed`);
    } catch (error) {
      await transaction.abort();
      console.error(`Transaction ${transactionalId} aborted:`, error);
      throw error;
    } finally {
      await producer.disconnect();
    }
  }

  // 5. Compaction Topics
  async createCompactedTopic(topic, partitions = 3) {
    await this.admin.createTopics({
      topics: [{
        topic,
        numPartitions: partitions,
        replicationFactor: 1,
        configEntries: [
          { name: 'cleanup.policy', value: 'compact' },
          { name: 'delete.retention.ms', value: '86400000' }, // 1 day
          { name: 'min.cleanable.dirty.ratio', value: '0.5' }
        ]
      }]
    });
    
    console.log(`Created compacted topic ${topic}`);
  }

  // 6. Schema Registry Integration
  async produceWithSchema(topic, messages, schemaId) {
    const { SchemaRegistry } = require('@kafkajs/confluent-schema-registry');
    
    const registry = new SchemaRegistry({
      host: process.env.SCHEMA_REGISTRY_URL
    });
    
    const encodedMessages = await Promise.all(
      messages.map(async (msg) => ({
        value: await registry.encode(schemaId, msg)
      }))
    );
    
    await this.produce(topic, encodedMessages);
  }

  // 7. Consumer Group Management
  async getConsumerGroupInfo(groupId) {
    const groups = await this.admin.describeGroups([groupId]);
    return groups.groups[0];
  }

  async resetConsumerGroupOffset(groupId, topic, partition, offset) {
    await this.admin.setOffsets({
      groupId,
      topic,
      partitions: [{ partition, offset }]
    });
    
    console.log(`Reset offset for group ${groupId}, topic ${topic}, partition ${partition} to ${offset}`);
  }

  // 8. Monitoring
  async getTopicMetrics(topic) {
    const offsets = await this.admin.fetchTopicOffsets(topic);
    
    return {
      topic,
      partitions: offsets.map(offset => ({
        partition: offset.partition,
        offset: offset.offset,
        high: offset.high,
        low: offset.low,
        lag: offset.high - offset.offset
      })),
      totalLag: offsets.reduce((sum, offset) => 
        sum + (offset.high - offset.offset), 0
      )
    };
  }

  // 9. Dead Letter Queue
  async sendToDLQ(originalTopic, message, error, dlqTopic) {
    const dlqMessage = {
      originalTopic,
      originalMessage: message.value.toString(),
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      headers: {
        ...message.headers,
        'x-original-topic': originalTopic,
        'x-error-type': error.constructor.name
      }
    };
    
    await this.produce(dlqTopic, dlqMessage);
    
    console.log(`Sent message to DLQ ${dlqTopic}`);
  }

  async close() {
    if (this.producer) {
      await this.producer.disconnect();
    }
    
    if (this.consumer) {
      await this.consumer.disconnect();
    }
    
    if (this.admin) {
      await this.admin.disconnect();
    }
    
    console.log('Kafka connections closed');
  }
}

// Queue Orchestrator
class QueueOrchestrator {
  constructor() {
    this.queueSystem = new QueueSystem();
    this.rabbitMQ = new RabbitMQManager();
    this.kafka = new KafkaManager();
    
    this.messageRouters = new Map();
    this.setupMessageRouting();
  }

  setupMessageRouting() {
    // Route messages based on type
    this.messageRouters.set('email', this.routeToEmailQueue);
    this.messageRouters.set('notification', this.routeToNotificationQueue);
    this.messageRouters.set('analytics', this.routeToAnalyticsQueue);
    this.messageRouters.set('payment', this.routeToPaymentQueue);
    this.messageRouters.set('report', this.routeToReportQueue);
  }

  async routeMessage(messageType, message, options = {}) {
    const router = this.messageRouters.get(messageType);
    
    if (!router) {
      throw new Error(`No router found for message type: ${messageType}`);
    }
    
    return router.call(this, message, options);
  }

  async routeToEmailQueue(message, options) {
    const priority = options.priority || 'normal';
    const queueName = `email-${priority}`;
    
    return this.queueSystem.submitJob(queueName, {
      type: 'email',
      ...message
    }, {
      priority: this.getPriorityValue(priority),
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 5000
      }
    });
  }

  async routeToNotificationQueue(message, options) {
    // Use RabbitMQ for real-time notifications
    await this.rabbitMQ.connect();
    
    const exchangeName = 'notifications';
    await this.rabbitMQ.createExchange(exchangeName, 'topic');
    
    const routingKey = this.getNotificationRoutingKey(message);
    
    return this.rabbitMQ.publishPersistentMessage(
      exchangeName,
      routingKey,
      message
    );
  }

  async routeToAnalyticsQueue(message, options) {
    // Use Kafka for analytics data
    await this.kafka.connect();
    
    const topic = 'analytics-events';
    await this.kafka.produce(topic, message, {
      acks: 1 // Leader acknowledgment
    });
  }

  async routeToPaymentQueue(message, options) {
    const queueName = 'payment-processing';
    
    return this.queueSystem.submitJob(queueName, {
      type: 'payment',
      ...message
    }, {
      priority: 1, // High priority
      attempts: 5,
      timeout: 30000,
      backoff: {
        type: 'fixed',
        delay: 10000
      }
    });
  }

  async routeToReportQueue(message, options) {
    // Use batch processing for reports
    const queueName = 'report-generation';
    
    return this.queueSystem.submitBatchJobs(queueName, [message], 10);
  }

  getPriorityValue(priority) {
    const priorities = {
      'high': 1,
      'normal': 5,
      'low': 10
    };
    
    return priorities[priority] || 5;
  }

  getNotificationRoutingKey(message) {
    const { type, userId, channel } = message;
    
    let routingKey = `notification.${type}`;
    
    if (channel) {
      routingKey += `.${channel}`;
    }
    
    if (userId) {
      routingKey += `.user.${userId}`;
    }
    
    return routingKey;
  }

  // Queue monitoring dashboard
  async getDashboardData() {
    const queueMetrics = [];
    
    // Get metrics from all queue systems
    for (const [queueName, queue] of this.queueSystem.queues) {
      const metrics = await this.queueSystem.getQueueMetrics(queueName);
      queueMetrics.push({
        system: 'bull',
        ...metrics
      });
    }
    
    // Get RabbitMQ metrics
    if (this.rabbitMQ.channel) {
      for (const [queueName, queueInfo] of this.rabbitMQ.queues) {
        const stats = await this.rabbitMQ.getQueueStats(queueName);
        queueMetrics.push({
          system: 'rabbitmq',
          ...stats
        });
      }
    }
    
    // Get Kafka metrics
    if (this.kafka.admin) {
      const topics = await this.kafka.admin.listTopics();
      
      for (const topic of topics) {
        if (!topic.startsWith('_')) { // Skip internal topics
          const metrics = await this.kafka.getTopicMetrics(topic);
          queueMetrics.push({
            system: 'kafka',
            ...metrics
          });
        }
      }
    }
    
    return {
      timestamp: new Date().toISOString(),
      totalQueues: queueMetrics.length,
      totalMessages: queueMetrics.reduce((sum, q) => sum + (q.messageCount || q.waiting || 0), 0),
      queues: queueMetrics
    };
  }
}

// Usage examples
async function setupQueueSystem() {
  const orchestrator = new QueueOrchestrator();
  
  // Example: Send email
  await orchestrator.routeMessage('email', {
    to: 'user@example.com',
    subject: 'Welcome!',
    template: 'welcome',
    data: { name: 'John Doe' }
  }, { priority: 'high' });
  
  // Example: Send real-time notification
  await orchestrator.routeMessage('notification', {
    type: 'new_message',
    userId: '12345',
    channel: 'push',
    title: 'New Message',
    body: 'You have a new message'
  });
  
  // Example: Track analytics event
  await orchestrator.routeMessage('analytics', {
    event: 'user_signup',
    userId: '12345',
    timestamp: new Date().toISOString(),
    properties: {
      source: 'web',
      plan: 'premium'
    }
  });
  
  // Get dashboard data
  const dashboard = await orchestrator.getDashboardData();
  console.log('Queue Dashboard:', dashboard);
}

// Error handling and recovery
class QueueErrorHandler {
  static async handleQueueError(error, job, queue) {
    console.error(`Queue error for job ${job?.id}:`, error);
    
    // Categorize errors
    const errorType = this.categorizeError(error);
    
    switch (errorType) {
      case 'transient':
        // Transient errors: retry with backoff
        if (job.attemptsMade < (job.opts.attempts || 3)) {
          const delay = this.calculateBackoff(job.attemptsMade);
          await job.retry({ delay });
        }
        break;
        
      case 'business':
        // Business logic errors: move to DLQ
        await queue.moveToFailedDependencies(job, error, true);
        break;
        
      case 'validation':
        // Validation errors: discard with notification
        console.error('Validation error, discarding job:', error);
        await job.discard();
        break;
        
      default:
        // Unknown errors: retry with caution
        if (job.attemptsMade < 2) {
          await job.retry({ delay: 10000 });
        }
    }
  }
  
  static categorizeError(error) {
    if (error.message.includes('timeout') || 
        error.message.includes('connection') ||
        error.code === 'ECONNREFUSED') {
      return 'transient';
    }
    
    if (error.message.includes('validation') ||
        error.message.includes('invalid')) {
      return 'validation';
    }
    
    if (error.message.includes('business') ||
        error.message.includes('logic')) {
      return 'business';
    }
    
    return 'unknown';
  }
  
  static calculateBackoff(attempts) {
    // Exponential backoff with jitter
    const baseDelay = 1000;
    const maxDelay = 60000;
    
    const delay = Math.min(
      baseDelay * Math.pow(2, attempts),
      maxDelay
    );
    
    // Add jitter (±20%)
    const jitter = delay * 0.2 * (Math.random() * 2 - 1);
    
    return Math.round(delay + jitter);
  }
}
```

---

## 9. API Gateway Design

### In-Depth Explanation
API Gateway acts as a single entry point for all client requests, providing routing, composition, and cross-cutting concerns.

### Comprehensive API Gateway Implementation

```javascript
const express = require('express');
const httpProxy = require('http-proxy');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class APIGateway {
  constructor() {
    this.app = express();
    this.proxy = httpProxy.createProxyServer({
      changeOrigin: true,
      timeout: 30000
    });
    
    this.redisClient = new Redis.Cluster([
      { host: process.env.REDIS_HOST, port: process.env.REDIS_PORT }
    ]);
    
    this.services = new Map();
    this.routes = new Map();
    this.middlewareChain = [];
    this.circuitBreakers = new Map();
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupMonitoring();
    this.setupCircuitBreakers();
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'", "'unsafe-inline'"]
        }
      },
      crossOriginEmbedderPolicy: false
    }));
    
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
    }));
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request logging
    this.app.use(this.requestLogger());
    
    // Rate limiting
    this.app.use(this.globalRateLimiter());
    
    // Authentication/Authorization
    this.app.use(this.authMiddleware());
    
    // Request ID
    this.app.use(this.requestIdMiddleware());
    
    // Compression
    this.app.use(require('compression')());
  }

  // 1. Service Registration
  registerService(name, config) {
    const service = {
      name,
      endpoints: config.endpoints || [],
      loadBalancer: config.loadBalancer || 'round-robin',
      healthCheck: config.healthCheck || `${config.url}/health`,
      circuitBreaker: config.circuitBreaker || {
        failureThreshold: 5,
        resetTimeout: 30000,
        halfOpenMaxRequests: 3
      },
      timeout: config.timeout || 30000,
      retry: config.retry || {
        attempts: 3,
        delay: 1000
      },
      instances: config.instances || [{ url: config.url }],
      currentInstance: 0,
      status: 'healthy',
      failures: 0,
      lastFailure: null
    };
    
    this.services.set(name, service);
    
    // Register routes
    service.endpoints.forEach(endpoint => {
      this.registerRoute(endpoint.path, endpoint.methods || ['GET'], name);
    });
    
    console.log(`Registered service: ${name}`);
    
    // Start health checks
    this.startServiceHealthChecks(service);
    
    return service;
  }

  // 2. Route Registration
  registerRoute(path, methods, serviceName, options = {}) {
    const route = {
      path,
      methods: Array.isArray(methods) ? methods : [methods],
      service: serviceName,
      rateLimit: options.rateLimit || null,
      authentication: options.authentication || 'required',
      authorization: options.authorization || null,
      cache: options.cache || null,
      timeout: options.timeout || null,
      transform: options.transform || null
    };
    
    const routeKey = `${methods.join(',')}:${path}`;
    this.routes.set(routeKey, route);
    
    // Register with Express
    methods.forEach(method => {
      this.app[method.toLowerCase()](path, async (req, res) => {
        await this.handleRequest(req, res, route);
      });
    });
    
    console.log(`Registered route: ${method} ${path} -> ${serviceName}`);
  }

  // 3. Request Handling Pipeline
  async handleRequest(req, res, route) {
    const startTime = Date.now();
    const requestId = req.requestId;
    
    try {
      // Check circuit breaker
      if (!this.checkCircuitBreaker(route.service)) {
        throw new Error(`Service ${route.service} is unavailable (circuit open)`);
      }
      
      // Apply route-specific rate limiting
      if (route.rateLimit) {
        await this.applyRateLimit(req, route.rateLimit);
      }
      
      // Apply authentication
      if (route.authentication === 'required') {
        await this.authenticateRequest(req);
      }
      
      // Apply authorization
      if (route.authorization) {
        await this.authorizeRequest(req, route.authorization);
      }
      
      // Check cache
      if (route.cache) {
        const cachedResponse = await this.checkCache(req, route.cache);
        if (cachedResponse) {
          this.sendCachedResponse(res, cachedResponse);
          return;
        }
      }
      
      // Select service instance
      const service = this.services.get(route.service);
      const target = this.selectServiceInstance(service);
      
      // Apply request transformations
      if (route.transform?.request) {
        req = await this.transformRequest(req, route.transform.request);
      }
      
      // Proxy request
      const response = await this.proxyRequest(req, res, target, route);
      
      // Apply response transformations
      if (route.transform?.response) {
        response = await this.transformResponse(response, route.transform.response);
      }
      
      // Cache response if needed
      if (route.cache && this.shouldCacheResponse(response, route.cache)) {
        await this.cacheResponse(req, response, route.cache);
      }
      
      // Record success
      this.recordRequestSuccess(route.service, Date.now() - startTime);
      
    } catch (error) {
      // Record failure
      this.recordRequestFailure(route.service, error);
      
      // Handle error
      await this.handleError(error, req, res, route);
    }
  }

  // 4. Service Discovery & Load Balancing
  selectServiceInstance(service) {
    if (!service.instances || service.instances.length === 0) {
      throw new Error(`No instances available for service ${service.name}`);
    }
    
    switch (service.loadBalancer) {
      case 'round-robin':
        return this.roundRobinSelection(service);
      case 'least-connections':
        return this.leastConnectionsSelection(service);
      case 'random':
        return this.randomSelection(service);
      case 'weighted':
        return this.weightedSelection(service);
      default:
        return this.roundRobinSelection(service);
    }
  }

  roundRobinSelection(service) {
    const instance = service.instances[service.currentInstance];
    service.currentInstance = (service.currentInstance + 1) % service.instances.length;
    return instance;
  }

  async leastConnectionsSelection(service) {
    // Get connection counts from Redis
    const connectionCounts = await Promise.all(
      service.instances.map(async (instance, index) => {
        const count = await this.redisClient.get(`connections:${service.name}:${index}`);
        return {
          instance,
          index,
          connections: parseInt(count) || 0
        };
      })
    );
    
    // Select instance with least connections
    const selected = connectionCounts.reduce((prev, curr) => 
      prev.connections < curr.connections ? prev : curr
    );
    
    // Increment connection count
    await this.redisClient.incr(`connections:${service.name}:${selected.index}`);
    
    // Set expiration
    await this.redisClient.expire(`connections:${service.name}:${selected.index}`, 60);
    
    return selected.instance;
  }

  // 5. Circuit Breaker Pattern
  setupCircuitBreakers() {
    for (const [serviceName, service] of this.services) {
      this.circuitBreakers.set(serviceName, {
        state: 'CLOSED',
        failureCount: 0,
        successCount: 0,
        lastFailure: null,
        nextAttempt: null,
        ...service.circuitBreaker
      });
    }
  }

  checkCircuitBreaker(serviceName) {
    const breaker = this.circuitBreakers.get(serviceName);
    
    if (!breaker) return true;
    
    switch (breaker.state) {
      case 'CLOSED':
        return true;
      case 'OPEN':
        // Check if reset timeout has passed
        if (Date.now() > breaker.nextAttempt) {
          breaker.state = 'HALF_OPEN';
          breaker.successCount = 0;
          return true;
        }
        return false;
      case 'HALF_OPEN':
        if (breaker.successCount >= breaker.halfOpenMaxRequests) {
          breaker.state = 'CLOSED';
          breaker.failureCount = 0;
        } else if (breaker.failureCount > 0) {
          breaker.state = 'OPEN';
          breaker.nextAttempt = Date.now() + breaker.resetTimeout;
        }
        return true;
    }
  }

  recordRequestSuccess(serviceName, responseTime) {
    const breaker = this.circuitBreakers.get(serviceName);
    
    if (!breaker) return;
    
    if (breaker.state === 'HALF_OPEN') {
      breaker.successCount++;
    }
    
    breaker.failureCount = 0;
  }

  recordRequestFailure(serviceName, error) {
    const breaker = this.circuitBreakers.get(serviceName);
    
    if (!breaker) return;
    
    breaker.failureCount++;
    breaker.lastFailure = Date.now();
    
    if (breaker.state === 'CLOSED' && 
        breaker.failureCount >= breaker.failureThreshold) {
      breaker.state = 'OPEN';
      breaker.nextAttempt = Date.now() + breaker.resetTimeout;
    } else if (breaker.state === 'HALF_OPEN') {
      breaker.state = 'OPEN';
      breaker.nextAttempt = Date.now() + breaker.resetTimeout;
    }
  }

  // 6. Request/Response Transformation
  async transformRequest(req, transformRules) {
    const transformed = { ...req };
    
    if (transformRules.headers) {
      Object.entries(transformRules.headers).forEach(([key, value]) => {
        transformed.headers[key] = this.evaluateTemplate(value, req);
      });
    }
    
    if (transformRules.body) {
      transformed.body = this.transformObject(req.body, transformRules.body);
    }
    
    if (transformRules.query) {
      transformed.query = this.transformObject(req.query, transformRules.query);
    }
    
    return transformed;
  }

  async transformResponse(response, transformRules) {
    const transformed = { ...response };
    
    if (transformRules.headers) {
      Object.entries(transformRules.headers).forEach(([key, value]) => {
        transformed.headers[key] = value;
      });
    }
    
    if (transformRules.body) {
      transformed.body = this.transformObject(response.body, transformRules.body);
    }
    
    if (transformRules.status) {
      transformed.statusCode = transformRules.status;
    }
    
    return transformed;
  }

  transformObject(obj, rules) {
    if (typeof rules === 'function') {
      return rules(obj);
    }
    
    if (Array.isArray(rules)) {
      return rules.map(rule => this.transformObject(obj, rule));
    }
    
    if (typeof rules === 'object' && rules !== null) {
      const result = {};
      
      Object.entries(rules).forEach(([key, rule]) => {
        if (typeof rule === 'string' && rule.startsWith('$.')) {
          // JSONPath-like extraction
          const path = rule.substring(2);
          result[key] = this.extractValue(obj, path);
        } else if (typeof rule === 'function') {
          result[key] = rule(obj);
        } else {
          result[key] = rule;
        }
      });
      
      return result;
    }
    
    return obj;
  }

  // 7. Caching Layer
  async checkCache(req, cacheConfig) {
    const cacheKey = this.generateCacheKey(req, cacheConfig);
    
    try {
      const cached = await this.redisClient.get(cacheKey);
      
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Cache check failed:', error);
    }
    
    return null;
  }

  async cacheResponse(req, response, cacheConfig) {
    const cacheKey = this.generateCacheKey(req, cacheConfig);
    const ttl = cacheConfig.ttl || 300;
    
    try {
      await this.redisClient.setex(
        cacheKey,
        ttl,
        JSON.stringify({
          body: response.body,
          headers: response.headers,
          statusCode: response.statusCode,
          cachedAt: Date.now()
        })
      );
    } catch (error) {
      console.error('Cache set failed:', error);
    }
  }

  generateCacheKey(req, cacheConfig) {
    const parts = [
      req.method,
      req.path,
      JSON.stringify(req.query),
      JSON.stringify(req.body)
    ];
    
    if (cacheConfig.varyByHeaders) {
      cacheConfig.varyByHeaders.forEach(header => {
        parts.push(`${header}:${req.headers[header]}`);
      });
    }
    
    if (cacheConfig.varyByUser && req.user) {
      parts.push(`user:${req.user.id}`);
    }
    
    const keyString = parts.join('|');
    
    return crypto
      .createHash('md5')
      .update(keyString)
      .digest('hex');
  }

  shouldCacheResponse(response, cacheConfig) {
    if (cacheConfig.statusCodes && 
        !cacheConfig.statusCodes.includes(response.statusCode)) {
      return false;
    }
    
    if (cacheConfig.methods && 
        !cacheConfig.methods.includes(response.method)) {
      return false;
    }
    
    return response.statusCode >= 200 && response.statusCode < 300;
  }

  sendCachedResponse(res, cached) {
    Object.entries(cached.headers || {}).forEach(([key, value]) => {
      res.set(key, value);
    });
    
    res.set('X-Cache', 'HIT');
    res.set('X-Cache-Age', Date.now() - cached.cachedAt);
    
    res.status(cached.statusCode).json(cached.body);
  }

  // 8. Authentication & Authorization
  authMiddleware() {
    return async (req, res, next) => {
      try {
        const token = this.extractToken(req);
        
        if (!token) {
          throw new Error('No token provided');
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        
        next();
      } catch (error) {
        res.status(401).json({
          error: 'Authentication failed',
          message: error.message
        });
      }
    };
  }

  extractToken(req) {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    return req.query.token || req.cookies?.token;
  }

  async authorizeRequest(req, requiredPermissions) {
    if (!req.user) {
      throw new Error('User not authenticated');
    }
    
    const userPermissions = await this.getUserPermissions(req.user.id);
    
    const hasPermission = requiredPermissions.every(permission =>
      userPermissions.includes(permission)
    );
    
    if (!hasPermission) {
      throw new Error('Insufficient permissions');
    }
  }

  async getUserPermissions(userId) {
    // Fetch from Redis cache or database
    const cacheKey = `permissions:${userId}`;
    
    try {
      const cached = await this.redisClient.get(cacheKey);
      
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Permission cache failed:', error);
    }
    
    // Fetch from user service
    const permissions = await this.fetchUserPermissions(userId);
    
    // Cache for 5 minutes
    await this.redisClient.setex(cacheKey, 300, JSON.stringify(permissions));
    
    return permissions;
  }

  // 9. Rate Limiting
  globalRateLimiter() {
    return rateLimit({
      windowMs: 60000, // 1 minute
      max: 100, // Limit each IP to 100 requests per windowMs
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/health';
      },
      handler: (req, res) => {
        res.status(429).json({
          error: 'Too many requests',
          message: 'Please try again later.'
        });
      }
    });
  }

  async applyRateLimit(req, rateLimitConfig) {
    const key = `rate_limit:${req.ip}:${req.path}`;
    const windowMs = rateLimitConfig.windowMs || 60000;
    const max = rateLimitConfig.max || 100;
    
    const script = `
      local key = KEYS[1]
      local window = tonumber(ARGV[1])
      local max = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      
      local windowStart = now - window
      
      -- Remove old entries
      redis.call('zremrangebyscore', key, 0, windowStart)
      
      -- Count current requests
      local count = redis.call('zcount', key, windowStart, now)
      
      if count >= max then
        return 0
      end
      
      -- Add current request
      redis.call('zadd', key, now, now)
      redis.call('expire', key, math.ceil(window / 1000) + 1)
      
      return 1
    `;
    
    const result = await this.redisClient.eval(
      script,
      1,
      key,
      windowMs,
      max,
      Date.now()
    );
    
    if (result === 0) {
      throw new Error('Rate limit exceeded');
    }
  }

  // 10. Health Checks
  startServiceHealthChecks(service) {
    setInterval(async () => {
      try {
        const response = await fetch(service.healthCheck, {
          timeout: 5000
        });
        
        if (response.ok) {
          service.status = 'healthy';
          service.failures = 0;
        } else {
          service.status = 'unhealthy';
          service.failures++;
        }
      } catch (error) {
        service.status = 'unhealthy';
        service.failures++;
        service.lastFailure = new Date().toISOString();
        
        console.error(`Health check failed for ${service.name}:`, error);
      }
    }, 30000); // Check every 30 seconds
  }

  // 11. Request Logging
  requestLogger() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Log request
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        contentType: req.headers['content-type'],
        contentLength: req.headers['content-length']
      });
      
      // Log response
      const originalSend = res.send;
      res.send = function(body) {
        const responseTime = Date.now() - startTime;
        
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${responseTime}ms`);
        
        originalSend.call(this, body);
      };
      
      next();
    };
  }

  // 12. Request ID
  requestIdMiddleware() {
    return (req, res, next) => {
      req.requestId = crypto.randomUUID();
      res.set('X-Request-ID', req.requestId);
      next();
    };
  }

  // 13. Error Handling
  async handleError(error, req, res, route) {
    console.error(`Request ${req.requestId} failed:`, error);
    
    // Determine error type and status code
    const errorInfo = this.classifyError(error);
    
    // Apply error transformation if configured
    if (route.transform?.error) {
      const transformedError = await this.transformError(error, route.transform.error);
      errorInfo.message = transformedError.message;
      errorInfo.details = transformedError.details;
    }
    
    // Set response headers
    res.set('X-Error-Type', errorInfo.type);
    
    // Send error response
    res.status(errorInfo.statusCode).json({
      error: errorInfo.message,
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
      ...(process.env.NODE_ENV === 'development' && {
        details: errorInfo.details,
        stack: error.stack
      })
    });
  }

  classifyError(error) {
    const errorMap = {
      'Authentication failed': { statusCode: 401, type: 'AUTHENTICATION' },
      'Insufficient permissions': { statusCode: 403, type: 'AUTHORIZATION' },
      'Rate limit exceeded': { statusCode: 429, type: 'RATE_LIMIT' },
      'Service unavailable': { statusCode: 503, type: 'SERVICE_UNAVAILABLE' },
      'Circuit open': { statusCode: 503, type: 'CIRCUIT_BREAKER' },
      'Timeout': { statusCode: 504, type: 'TIMEOUT' }
    };
    
    for (const [message, info] of Object.entries(errorMap)) {
      if (error.message.includes(message)) {
        return {
          statusCode: info.statusCode,
          type: info.type,
          message: error.message,
          details: error.details
        };
      }
    }
    
    // Default
    return {
      statusCode: 500,
      type: 'INTERNAL_ERROR',
      message: 'Internal server error',
      details: error.message
    };
  }

  // 14. Proxy Request with Retry
  async proxyRequest(req, res, target, route) {
    const service = this.services.get(route.service);
    const maxRetries = service.retry?.attempts || 3;
    const retryDelay = service.retry?.delay || 1000;
    
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.proxyToService(req, res, target, route);
      } catch (error) {
        lastError = error;
        
        if (attempt < maxRetries) {
          console.log(`Retry attempt ${attempt} for ${req.requestId}`);
          await this.sleep(retryDelay * Math.pow(2, attempt - 1)); // Exponential backoff
        }
      }
    }
    
    throw lastError;
  }

  async proxyToService(req, res, target, route) {
    return new Promise((resolve, reject) => {
      const timeout = route.timeout || this.services.get(route.service).timeout;
      
      const timeoutId = setTimeout(() => {
        proxyReq.abort();
        reject(new Error('Request timeout'));
      }, timeout);
      
      const proxyReq = this.proxy.web(req, res, { target: target.url }, (error) => {
        clearTimeout(timeoutId);
        
        if (error) {
          reject(error);
        } else {
          resolve({
            body: res.body,
            headers: res.getHeaders(),
            statusCode: res.statusCode
          });
        }
      });
      
      // Handle proxy errors
      proxyReq.on('error', (error) => {
        clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  // 15. Metrics & Monitoring
  setupMonitoring() {
    const metrics = {
      requests: 0,
      errors: 0,
      responseTimes: [],
      circuitBreakers: {}
    };
    
    // Collect metrics
    this.app.use((req, res, next) => {
      metrics.requests++;
      next();
    });
    
    // Expose metrics endpoint
    this.app.get('/metrics', (req, res) => {
      const now = Date.now();
      
      // Calculate average response time (last 5 minutes)
      const fiveMinutesAgo = now - 300000;
      const recentTimes = metrics.responseTimes.filter(
        rt => rt.timestamp > fiveMinutesAgo
      );
      
      const avgResponseTime = recentTimes.length > 0
        ? recentTimes.reduce((sum, rt) => sum + rt.time, 0) / recentTimes.length
        : 0;
      
      // Circuit breaker states
      const circuitStates = {};
      for (const [serviceName, breaker] of this.circuitBreakers) {
        circuitStates[serviceName] = breaker.state;
      }
      
      res.json({
        timestamp: new Date().toISOString(),
        totalRequests: metrics.requests,
        totalErrors: metrics.errors,
        errorRate: metrics.requests > 0 
          ? (metrics.errors / metrics.requests * 100).toFixed(2) 
          : 0,
        avgResponseTime: avgResponseTime.toFixed(2),
        circuitBreakers: circuitStates,
        services: Array.from(this.services.values()).map(s => ({
          name: s.name,
          status: s.status,
          instances: s.instances.length,
          failures: s.failures
        }))
      });
    });
    
    // Store metrics
    this.metrics = metrics;
  }

  recordResponseTime(time) {
    this.metrics.responseTimes.push({
      timestamp: Date.now(),
      time
    });
    
    // Keep only last hour of data
    const oneHourAgo = Date.now() - 3600000;
    this.metrics.responseTimes = this.metrics.responseTimes.filter(
      rt => rt.timestamp > oneHourAgo
    );
  }

  // Utility methods
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  evaluateTemplate(template, data) {
    if (typeof template !== 'string') return template;
    
    return template.replace(/\${([^}]+)}/g, (match, path) => {
      return this.extractValue(data, path);
    });
  }

  extractValue(obj, path) {
    return path.split('.').reduce((current, key) => {
      return current ? current[key] : undefined;
    }, obj);
  }

  // Start the gateway
  start(port = 3000) {
    this.app.listen(port, () => {
      console.log(`API Gateway running on port ${port}`);
      console.log(`Registered ${this.services.size} services`);
      console.log(`Registered ${this.routes.size} routes`);
    });
    
    return this.app;
  }
}

// Usage example
async function setupAPIGateway() {
  const gateway = new APIGateway();
  
  // Register services
  gateway.registerService('user-service', {
    url: 'http://user-service:3000',
    endpoints: [
      { path: '/api/users', methods: ['GET', 'POST'] },
      { path: '/api/users/:id', methods: ['GET', 'PUT', 'DELETE'] },
      { path: '/api/users/:id/profile', methods: ['GET'] }
    ],
    instances: [
      { url: 'http://user-service-1:3000' },
      { url: 'http://user-service-2:3000' },
      { url: 'http://user-service-3:3000' }
    ],
    loadBalancer: 'round-robin',
    circuitBreaker: {
      failureThreshold: 5,
      resetTimeout: 30000
    }
  });
  
  gateway.registerService('order-service', {
    url: 'http://order-service:3000',
    endpoints: [
      { path: '/api/orders', methods: ['GET', 'POST'] },
      { path: '/api/orders/:id', methods: ['GET'] },
      { path: '/api/orders/:id/items', methods: ['GET', 'POST'] }
    ],
    rateLimit: {
      windowMs: 60000,
      max: 1000
    }
  });
  
  gateway.registerService('payment-service', {
    url: 'http://payment-service:3000',
    endpoints: [
      { path: '/api/payments', methods: ['POST'] },
      { path: '/api/payments/:id', methods: ['GET'] }
    ],
    authentication: 'required',
    authorization: ['process_payment'],
    timeout: 60000
  });
  
  // Register routes with transformations
  gateway.registerRoute('/api/v1/users', ['GET'], 'user-service', {
    transform: {
      request: {
        headers: {
          'X-Service-Name': 'user-service',
          'X-User-Id': '${user.id}'
        },
        query: {
          page: (query) => parseInt(query.page) || 1,
          limit: (query) => Math.min(parseInt(query.limit) || 20, 100)
        }
      },
      response: {
        body: (body) => ({
          data: body.users,
          pagination: body.pagination
        })
      }
    },
    cache: {
      ttl: 60,
      varyByHeaders: ['Authorization'],
      varyByUser: true
    }
  });
  
  // Start the gateway
  gateway.start(8080);
}

// Advanced features
class AdvancedAPIGateway extends APIGateway {
  constructor() {
    super();
    
    this.apiKeys = new Map();
    this.quotaManager = new QuotaManager();
    this.analytics = new AnalyticsEngine();
    this.webhookManager = new WebhookManager();
    this.versionManager = new VersionManager();
    
    this.setupAdvancedFeatures();
  }
  
  setupAdvancedFeatures() {
    // API Key validation
    this.app.use(this.apiKeyMiddleware());
    
    // Request/Response validation
    this.app.use(this.validationMiddleware());
    
    // Request signing
    this.app.use(this.signatureMiddleware());
    
    // GraphQL proxy
    this.setupGraphQLProxy();
    
    // WebSocket proxy
    this.setupWebSocketProxy();
    
    // Canary deployments
    this.setupCanaryDeployments();
  }
  
  // API Key Management
  apiKeyMiddleware() {
    return async (req, res, next) => {
      const apiKey = req.headers['x-api-key'];
      
      if (!apiKey) {
        return next();
      }
      
      try {
        const keyInfo = await this.validateApiKey(apiKey);
        
        if (!keyInfo.active) {
          throw new Error('API key is inactive');
        }
        
        // Check rate limits
        const quotaCheck = await this.quotaManager.checkQuota(apiKey, req.path);
        
        if (!quotaCheck.allowed) {
          res.set('X-RateLimit-Limit', quotaCheck.limit);
          res.set('X-RateLimit-Remaining', quotaCheck.remaining);
          res.set('X-RateLimit-Reset', quotaCheck.reset);
          
          return res.status(429).json({
            error: 'Quota exceeded',
            message: quotaCheck.message
          });
        }
        
        // Attach key info to request
        req.apiKey = keyInfo;
        req.user = { id: keyInfo.userId, ...keyInfo };
        
        next();
      } catch (error) {
        res.status(401).json({
          error: 'Invalid API key',
          message: error.message
        });
      }
    };
  }
  
  async validateApiKey(apiKey) {
    const cacheKey = `apikey:${apiKey}`;
    
    // Check cache
    const cached = await this.redisClient.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Validate key (e.g., check database)
    const keyInfo = await this.fetchApiKeyInfo(apiKey);
    
    if (!keyInfo) {
      throw new Error('Invalid API key');
    }
    
    // Cache for 5 minutes
    await this.redisClient.setex(cacheKey, 300, JSON.stringify(keyInfo));
    
    return keyInfo;
  }
  
  // Request/Response Validation
  validationMiddleware() {
    return async (req, res, next) => {
      try {
        // Validate request against schema
        await this.validateRequest(req);
        
        // Override response.send to validate response
        const originalSend = res.send;
        res.send = function(body) {
          try {
            // Validate response if schema exists
            if (res.validateResponse) {
              this.validateResponse(body, res.validateResponse);
            }
            
            originalSend.call(this, body);
          } catch (error) {
            console.error('Response validation failed:', error);
            originalSend.call(this, body); // Still send, but log error
          }
        };
        
        next();
      } catch (error) {
        res.status(400).json({
          error: 'Validation failed',
          message: error.message,
          details: error.details
        });
      }
    };
  }
  
  async validateRequest(req) {
    const route = this.routes.get(`${req.method}:${req.path}`);
    
    if (!route?.validation?.request) {
      return;
    }
    
    const schema = route.validation.request;
    
    // Validate against JSON Schema, Joi, or similar
    const errors = this.validateAgainstSchema(req.body, schema);
    
    if (errors.length > 0) {
      throw new Error('Request validation failed', {
        details: errors
      });
    }
  }
  
  // Request Signing (HMAC)
  signatureMiddleware() {
    return async (req, res, next) => {
      const signature = req.headers['x-signature'];
      const timestamp = req.headers['x-timestamp'];
      
      if (!signature || !timestamp) {
        return next(); // Optional for public endpoints
      }
      
      // Check timestamp (prevent replay attacks)
      const requestTime = parseInt(timestamp);
      const currentTime = Date.now();
      
      if (Math.abs(currentTime - requestTime) > 300000) { // 5 minutes
        return res.status(400).json({
          error: 'Invalid timestamp',
          message: 'Request timestamp is too old or in the future'
        });
      }
      
      // Reconstruct signature
      const dataToSign = this.getDataToSign(req, timestamp);
      const expectedSignature = this.calculateSignature(dataToSign, req.apiKey?.secret);
      
      if (signature !== expectedSignature) {
        return res.status(401).json({
          error: 'Invalid signature',
          message: 'Request signature verification failed'
        });
      }
      
      next();
    };
  }
  
  getDataToSign(req, timestamp) {
    const parts = [
      req.method,
      req.path,
      timestamp,
      JSON.stringify(req.query),
      JSON.stringify(req.body)
    ];
    
    return parts.join('|');
  }
  
  calculateSignature(data, secret) {
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }
  
  // GraphQL Proxy
  setupGraphQLProxy() {
    const { createProxyMiddleware } = require('http-proxy-middleware');
    const { graphqlHTTP } = require('express-graphql');
    
    // GraphQL endpoint
    this.app.use('/graphql', graphqlHTTP({
      schema: this.buildFederatedSchema(),
      graphiql: process.env.NODE_ENV === 'development'
    }));
    
    // GraphQL proxy to individual services
    this.app.use('/graphql/:service', createProxyMiddleware({
      target: 'http://localhost:3000',
      changeOrigin: true,
      pathRewrite: (path, req) => {
        const service = req.params.service;
        return `/graphql`;
      },
      onProxyReq: (proxyReq, req, res) => {
        // Add service-specific headers
        proxyReq.setHeader('X-GraphQL-Service', req.params.service);
      }
    }));
  }
  
  buildFederatedSchema() {
    // Build federated GraphQL schema from multiple services
    // This would integrate with Apollo Federation or similar
    return null; // Implementation depends on GraphQL setup
  }
  
  // WebSocket Proxy
  setupWebSocketProxy() {
    const http = require('http');
    const WebSocket = require('ws');
    const WebSocketProxy = require('http-proxy').WebSocketProxy;
    
    const server = http.createServer(this.app);
    const wss = new WebSocket.Server({ server });
    
    const wsProxy = new WebSocketProxy({
      target: 'ws://backend-service:3000',
      changeOrigin: true
    });
    
    wss.on('connection', (ws, req) => {
      // Authenticate WebSocket connection
      this.authenticateWebSocket(req, (err, user) => {
        if (err) {
          ws.close(1008, 'Authentication failed');
          return;
        }
        
        // Proxy WebSocket connection
        wsProxy.ws(req, ws, {}, (err) => {
          console.error('WebSocket proxy error:', err);
        });
      });
    });
    
    this.wsServer = server;
  }
  
  authenticateWebSocket(req, callback) {
    // Extract token from query string or headers
    const token = req.url.split('token=')[1] || 
                 req.headers['sec-websocket-protocol'];
    
    if (!token) {
      return callback(new Error('No token provided'));
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      callback(null, decoded);
    } catch (error) {
      callback(error);
    }
  }
  
  // Canary Deployments
  setupCanaryDeployments() {
    this.canaryRules = new Map();
    
    // Canary rule examples
    this.canaryRules.set('user-service', {
      percentage: 10, // 10% of traffic to canary
      headers: {
        'X-Canary': 'true'
      },
      cookie: 'canary_user_service'
    });
  }
  
  applyCanaryRouting(req, serviceName) {
    const rule = this.canaryRules.get(serviceName);
    
    if (!rule) {
      return null; // No canary for this service
    }
    
    // Check if user is already in canary
    if (req.cookies?.[rule.cookie] === 'true') {
      return this.getCanaryInstance(serviceName);
    }
    
    // Check header override
    if (req.headers['x-canary'] === 'true') {
      return this.getCanaryInstance(serviceName);
    }
    
    // Apply percentage-based routing
    const random = Math.random() * 100;
    
    if (random < rule.percentage) {
      // Set cookie for future requests
      res.cookie(rule.cookie, 'true', {
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      return this.getCanaryInstance(serviceName);
    }
    
    return null;
  }
  
  getCanaryInstance(serviceName) {
    const service = this.services.get(serviceName);
    
    if (service.canaryInstances && service.canaryInstances.length > 0) {
      return service.canaryInstances[0];
    }
    
    return null;
  }
}

// Quota Management
class QuotaManager {
  constructor() {
    this.redisClient = new Redis.Cluster([
      { host: process.env.REDIS_HOST, port: process.env.REDIS_PORT }
    ]);
  }
  
  async checkQuota(apiKey, endpoint) {
    const quotaKey = `quota:${apiKey}:${endpoint}:${this.getCurrentWindow()}`;
    
    const [current, quota] = await Promise.all([
      this.redisClient.get(quotaKey),
      this.getQuotaForApiKey(apiKey, endpoint)
    ]);
    
    const currentCount = parseInt(current) || 0;
    
    if (currentCount >= quota.limit) {
      return {
        allowed: false,
        limit: quota.limit,
        remaining: 0,
        reset: this.getNextWindowReset(),
        message: `Quota exceeded. Limit: ${quota.limit} requests per ${quota.window}`
      };
    }
    
    // Increment counter
    await this.redisClient.incr(quotaKey);
    await this.redisClient.expire(quotaKey, this.getWindowSeconds(quota.window));
    
    return {
      allowed: true,
      limit: quota.limit,
      remaining: quota.limit - (currentCount + 1),
      reset: this.getNextWindowReset()
    };
  }
  
  getCurrentWindow() {
    const now = new Date();
    
    // Hourly window
    return `${now.getFullYear()}${now.getMonth()}${now.getDate()}${now.getHours()}`;
  }
  
  getNextWindowReset() {
    const now = new Date();
    const nextHour = new Date(now);
    nextHour.setHours(nextHour.getHours() + 1);
    nextHour.setMinutes(0, 0, 0);
    
    return Math.floor(nextHour.getTime() / 1000);
  }
  
  getWindowSeconds(window) {
    const windowMap = {
      'second': 1,
      'minute': 60,
      'hour': 3600,
      'day': 86400,
      'month': 2592000
    };
    
    return windowMap[window] || 3600;
  }
  
  async getQuotaForApiKey(apiKey, endpoint) {
    // Fetch from database or configuration
    // Default quota
    return {
      limit: 1000,
      window: 'hour'
    };
  }
}

// Analytics Engine
class AnalyticsEngine {
  constructor() {
    this.kafkaProducer = new KafkaManager();
    this.analyticsQueue = new QueueSystem();
  }
  
  trackRequest(req, res, metadata) {
    const analyticsEvent = {
      type: 'api_request',
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      responseTime: metadata.responseTime,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      apiKey: req.apiKey?.id,
      userId: req.user?.id,
      service: metadata.service,
      endpoint: metadata.endpoint
    };
    
    // Send to Kafka for real-time analytics
    this.kafkaProducer.produce('api-analytics', analyticsEvent).catch(console.error);
    
    // Also queue for batch processing
    this.analyticsQueue.submitJob('analytics-processing', analyticsEvent, {
      priority: 10 // Low priority
    });
  }
}

// Webhook Manager
class WebhookManager {
  constructor() {
    this.webhooks = new Map();
    this.queue = new QueueSystem();
  }
  
  registerWebhook(eventType, url, options = {}) {
    const webhookId = crypto.randomUUID();
    
    const webhook = {
      id: webhookId,
      eventType,
      url,
      secret: options.secret || crypto.randomBytes(32).toString('hex'),
      active: options.active !== false,
      retry: options.retry || {
        maxAttempts: 3,
        backoff: 'exponential'
      },
      filters: options.filters || {},
      createdAt: new Date().toISOString()
    };
    
    if (!this.webhooks.has(eventType)) {
      this.webhooks.set(eventType, []);
    }
    
    this.webhooks.get(eventType).push(webhook);
    
    console.log(`Registered webhook ${webhookId} for event ${eventType}`);
    
    return webhookId;
  }
  
  async triggerWebhook(eventType, payload) {
    const webhooks = this.webhooks.get(eventType) || [];
    
    const activeWebhooks = webhooks.filter(w => w.active);
    
    for (const webhook of activeWebhooks) {
      // Apply filters
      if (this.matchesFilters(webhook.filters, payload)) {
        await this.queue.submitJob('webhook-delivery', {
          webhookId: webhook.id,
          eventType,
          payload,
          url: webhook.url,
          secret: webhook.secret
        }, {
          attempts: webhook.retry.maxAttempts,
          backoff: {
            type: webhook.retry.backoff,
            delay: 1000
          }
        });
      }
    }
  }
  
  matchesFilters(filters, payload) {
    if (!filters || Object.keys(filters).length === 0) {
      return true;
    }
    
    return Object.entries(filters).every(([key, value]) => {
      const payloadValue = this.extractValue(payload, key);
      return payloadValue === value;
    });
  }
}

// Version Manager
class VersionManager {
  constructor() {
    this.versions = new Map();
    this.defaultVersion = 'v1';
  }
  
  registerVersion(version, config) {
    this.versions.set(version, {
      ...config,
      deprecated: config.deprecated || false,
      sunset: config.sunset || null,
      changelog: config.changelog || []
    });
  }
  
  getVersionInfo(req) {
    const version = req.headers['accept-version'] || 
                   req.headers['x-api-version'] ||
                   this.extractVersionFromPath(req.path) ||
                   this.defaultVersion;
    
    const versionConfig = this.versions.get(version);
    
    if (!versionConfig) {
      throw new Error(`Unsupported API version: ${version}`);
    }
    
    return {
      version,
      ...versionConfig
    };
  }
  
  extractVersionFromPath(path) {
    const match = path.match(/^\/api\/v(\d+)\//);
    return match ? `v${match[1]}` : null;
  }
  
  addVersionHeaders(res, versionInfo) {
    res.set('API-Version', versionInfo.version);
    
    if (versionInfo.deprecated) {
      res.set('Deprecated', 'true');
      
      if (versionInfo.sunset) {
        res.set('Sunset', new Date(versionInfo.sunset).toUTCString());
      }
    }
  }
}
```

---

## 10. High Availability Architecture

### In-Depth Explanation
High Availability ensures system resilience through redundancy, failover mechanisms, and disaster recovery strategies.

### Complete HA Implementation

```javascript
class HighAvailabilityManager {
  constructor() {
    this.nodes = new Map();
    this.leader = null;
    this.healthChecks = new Map();
    this.failoverStrategies = new Map();
    this.dataReplication = new DataReplicationManager();
    this.backupManager = new BackupManager();
    
    this.setupHeartbeat();
    this.setupFailureDetection();
    this.setupAutoRecovery();
  }

  // 1. Node Registration & Discovery
  registerNode(nodeId, nodeInfo) {
    const node = {
      id: nodeId,
      ...nodeInfo,
      status: 'healthy',
      lastHeartbeat: Date.now(),
      role: nodeInfo.role || 'follower',
      priority: nodeInfo.priority || 1,
      weight: nodeInfo.weight || 1
    };
    
    this.nodes.set(nodeId, node);
    
    console.log(`Registered node: ${nodeId} (${node.role})`);
    
    // Start health checks
    this.startHealthChecks(node);
    
    return node;
  }

  // 2. Leader Election (Raft-like algorithm)
  async electLeader() {
    const healthyNodes = Array.from(this.nodes.values())
      .filter(node => node.status === 'healthy')
      .sort((a, b) => b.priority - a.priority || b.weight - a.weight);
    
    if (healthyNodes.length === 0) {
      console.error('No healthy nodes available for leader election');
      return null;
    }
    
    // Simple majority voting
    const votes = new Map();
    let maxVotes = 0;
    let electedLeader = null;
    
    for (const candidate of healthyNodes) {
      // Simulate voting process
      const candidateVotes = await this.collectVotes(candidate);
      votes.set(candidate.id, candidateVotes);
      
      if (candidateVotes > maxVotes) {
        maxVotes = candidateVotes;
        electedLeader = candidate;
      }
    }
    
    if (electedLeader && maxVotes > Math.floor(healthyNodes.length / 2)) {
      this.leader = electedLeader;
      await this.announceNewLeader(electedLeader);
      console.log(`Elected new leader: ${electedLeader.id}`);
      return electedLeader;
    }
    
    return null;
  }

  async collectVotes(candidate) {
    // In real implementation, nodes would vote
    // This is a simplified version
    return 1; // Each candidate gets 1 vote in this simulation
  }

  async announceNewLeader(leader) {
    // Notify all nodes about new leader
    for (const node of this.nodes.values()) {
      if (node.id !== leader.id) {
        await this.sendToNode(node, {
          type: 'NEW_LEADER',
          leaderId: leader.id,
          timestamp: Date.now()
        });
      }
    }
  }

  // 3. Heartbeat Mechanism
  setupHeartbeat() {
    setInterval(() => {
      this.sendHeartbeats();
    }, 5000); // Every 5 seconds
  }

  async sendHeartbeats() {
    if (this.leader) {
      // Leader sends heartbeats to followers
      for (const node of this.nodes.values()) {
        if (node.id !== this.leader.id && node.status === 'healthy') {
          try {
            await this.sendToNode(node, {
              type: 'HEARTBEAT',
              leaderId: this.leader.id,
              timestamp: Date.now(),
              term: this.currentTerm
            });
            
            node.lastHeartbeat = Date.now();
          } catch (error) {
            console.error(`Failed to send heartbeat to ${node.id}:`, error);
            node.failures = (node.failures || 0) + 1;
          }
        }
      }
    }
  }

  // 4. Failure Detection
  setupFailureDetection() {
    setInterval(() => {
      this.detectFailures();
    }, 10000); // Every 10 seconds
  }

  detectFailures() {
    const now = Date.now();
    const failureThreshold = 30000; // 30 seconds without heartbeat
    
    for (const node of this.nodes.values()) {
      if (node.status === 'healthy' && 
          now - node.lastHeartbeat > failureThreshold) {
        
        console.warn(`Node ${node.id} appears to be down`);
        node.status = 'suspected';
        node.lastFailure = now;
        
        // Start confirmation checks
        this.confirmNodeFailure(node);
      }
    }
  }

  async confirmNodeFailure(node) {
    // Try multiple confirmation methods
    const confirmations = await Promise.allSettled([
      this.pingNode(node),
      this.checkServiceHealth(node),
      this.checkNetworkConnectivity(node)
    ]);
    
    const failedConfirmations = confirmations.filter(c => c.status === 'rejected');
    
    if (failedConfirmations.length >= 2) { // Majority failed
      node.status = 'failed';
      node.failedAt = Date.now();
      
      console.error(`Confirmed node failure: ${node.id}`);
      
      // Trigger failover if leader failed
      if (node.id === this.leader?.id) {
        await this.handleLeaderFailure();
      } else {
        await this.handleFollowerFailure(node);
      }
    } else {
      node.status = 'healthy'; // False alarm
    }
  }

  // 5. Automatic Failover
  async handleLeaderFailure() {
    console.log('Leader failure detected, initiating failover...');
    
    // Mark leader as failed
    if (this.leader) {
      this.leader.status = 'failed';
    }
    
    // Elect new leader
    const newLeader = await this.electLeader();
    
    if (!newLeader) {
      console.error('Failed to elect new leader');
      await this.enterDegradedMode();
      return;
    }
    
    // Replicate data to new leader
    await this.dataReplication.promoteToLeader(newLeader);
    
    // Update service discovery
    await this.updateServiceDiscovery(newLeader);
    
    console.log(`Failover complete. New leader: ${newLeader.id}`);
  }

  async handleFollowerFailure(node) {
    console.log(`Follower ${node.id} failed, handling...`);
    
    // Remove from load balancer
    await this.removeFromLoadBalancer(node);
    
    // Trigger replacement if needed
    if (this.shouldReplaceNode(node)) {
      await this.replaceFailedNode(node);
    }
    
    // Update replication factor
    await this.dataReplication.adjustReplication(node);
  }

  // 6. Data Replication & Consistency
  async replicateData(data, options = {}) {
    const replicationFactor = options.replicationFactor || 3;
    const consistencyLevel = options.consistencyLevel || 'quorum';
    
    const healthyNodes = Array.from(this.nodes.values())
      .filter(n => n.status === 'healthy')
      .slice(0, replicationFactor);
    
    if (healthyNodes.length < replicationFactor) {
      throw new Error(`Insufficient healthy nodes for replication factor ${replicationFactor}`);
    }
    
    // Write to multiple nodes based on consistency level
    const writePromises = healthyNodes.map(node => 
      this.writeToNode(node, data)
    );
    
    const results = await Promise.allSettled(writePromises);
    
    const successfulWrites = results.filter(r => r.status === 'fulfilled').length;
    
    // Check consistency requirements
    switch (consistencyLevel) {
      case 'one':
        if (successfulWrites < 1) throw new Error('Write failed');
        break;
      case 'quorum':
        if (successfulWrites < Math.ceil(replicationFactor / 2)) {
          throw new Error('Quorum not reached');
        }
        break;
      case 'all':
        if (successfulWrites < replicationFactor) {
          throw new Error('Not all replicas written');
        }
        break;
    }
    
    return {
      successful: successfulWrites,
      total: replicationFactor,
      nodes: healthyNodes.map(n => n.id)
    };
  }

  // 7. Read Repair & Hinted Handoff
  async readWithRepair(key) {
    const nodes = this.getReplicaNodes(key);
    
    // Read from multiple replicas
    const readPromises = nodes.map(node => 
      this.readFromNode(node, key)
    );
    
    const results = await Promise.allSettled(readPromises);
    
    const successfulReads = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);
    
    if (successfulReads.length === 0) {
      throw new Error('Data not found');
    }
    
    // Check consistency
    const values = successfulReads.map(r => r.value);
    const uniqueValues = [...new Set(values)];
    
    if (uniqueValues.length > 1) {
      // Inconsistency detected, perform read repair
      console.warn(`Inconsistency detected for key ${key}, performing read repair`);
      
      const latestValue = this.resolveConflict(values);
      
      // Repair inconsistent replicas
      await this.repairInconsistentReplicas(nodes, results, latestValue);
      
      return latestValue;
    }
    
    return values[0];
  }

  async repairInconsistentReplicas(nodes, readResults, correctValue) {
    const repairPromises = nodes.map((node, index) => {
      const result = readResults[index];
      
      if (result.status === 'fulfilled' && result.value.value !== correctValue) {
        return this.writeToNode(node, {
          key: result.value.key,
          value: correctValue,
          timestamp: Date.now()
        });
      }
      
      return Promise.resolve();
    });
    
    await Promise.allSettled(repairPromises);
  }

  // 8. Backup & Restore
  async performBackup(backupType = 'incremental') {
    console.log(`Starting ${backupType} backup...`);
    
    const backupId = `backup_${Date.now()}`;
    const backupData = {
      id: backupId,
      type: backupType,
      timestamp: new Date().toISOString(),
      nodes: Array.from(this.nodes.values()).map(n => ({
        id: n.id,
        status: n.status,
        role: n.role
      }))
    };
    
    // Take snapshot of leader data
    if (this.leader) {
      const snapshot = await this.createSnapshot(this.leader);
      backupData.snapshot = snapshot;
    }
    
    // Backup configuration
    const config = await this.backupConfiguration();
    backupData.configuration = config;
    
    // Store backup
    await this.backupManager.storeBackup(backupData);
    
    // Replicate backup to secondary location
    await this.replicateBackup(backupData);
    
    console.log(`Backup ${backupId} completed`);
    
    return backupId;
  }

  async restoreFromBackup(backupId, targetNode = null) {
    console.log(`Restoring from backup ${backupId}...`);
    
    // Retrieve backup
    const backup = await this.backupManager.retrieveBackup(backupId);
    
    if (!backup) {
      throw new Error(`Backup ${backupId} not found`);
    }
    
    // Stop writes during restore
    await this.pauseWrites();
    
    try {
      // Restore data
      if (backup.snapshot) {
        await this.restoreSnapshot(backup.snapshot, targetNode);
      }
      
      // Restore configuration
      if (backup.configuration) {
        await this.restoreConfiguration(backup.configuration);
      }
      
      // Verify restore
      await this.verifyRestore(backup);
      
      console.log(`Restore from backup ${backupId} completed successfully`);
    } finally {
      // Resume writes
      await this.resumeWrites();
    }
  }

  // 9. Disaster Recovery
  async initiateDisasterRecovery() {
    console.log('Initiating disaster recovery...');
    
    // 1. Assess damage
    const damageAssessment = await this.assessDamage();
    
    if (damageAssessment.severity === 'critical') {
      // 2. Activate DR site
      await this.activateDRSite();
      
      // 3. Restore from latest backup
      const latestBackup = await this.backupManager.getLatestBackup();
      
      if (latestBackup) {
        await this.restoreFromBackup(latestBackup.id);
      }
      
      // 4. Update DNS/load balancer
      await this.updateTrafficRouting();
      
      // 5. Monitor recovery
      await this.monitorRecovery();
    }
    
    console.log('Disaster recovery initiated');
  }

  async activateDRSite() {
    const drSite = await this.getDRSiteConfig();
    
    // Power on DR instances
    await this.powerOnInstances(drSite.instances);
    
    // Configure networking
    await this.configureDRNetworking(drSite);
    
    // Sync critical data
    await this.syncCriticalData(drSite);
    
    console.log('DR site activated');
  }

  // 10. Rolling Updates & Zero-Downtime Deployments
  async performRollingUpdate(updateConfig) {
    console.log('Starting rolling update...');
    
    const batchSize = updateConfig.batchSize || 1;
    const healthCheckTimeout = updateConfig.healthCheckTimeout || 300000; // 5 minutes
    const rollbackOnFailure = updateConfig.rollbackOnFailure !== false;
    
    const nodes = Array.from(this.nodes.values())
      .filter(n => n.status === 'healthy')
      .sort((a, b) => a.priority - b.priority);
    
    let successfulUpdates = 0;
    let failedUpdates = 0;
    
    for (let i = 0; i < nodes.length; i += batchSize) {
      const batch = nodes.slice(i, i + batchSize);
      
      console.log(`Updating batch ${i / batchSize + 1}: ${batch.map(n => n.id).join(', ')}`);
      
      // Drain traffic from batch nodes
      await this.drainNodes(batch);
      
      // Update batch
      const batchResults = await Promise.allSettled(
        batch.map(node => this.updateNode(node, updateConfig))
      );
      
      // Check batch results
      const batchFailures = batchResults.filter(r => r.status === 'rejected');
      
      if (batchFailures.length > 0 && rollbackOnFailure) {
        console.error('Batch update failed, rolling back...');
        await this.rollbackBatch(batch, updateConfig);
        throw new Error('Rolling update failed');
      }
      
      // Wait for health checks
      await this.waitForHealthChecks(batch, healthCheckTimeout);
      
      // Resume traffic
      await this.resumeNodes(batch);
      
      successfulUpdates += batchResults.length - batchFailures.length;
      failedUpdates += batchFailures.length;
      
      console.log(`Batch ${i / batchSize + 1} completed`);
    }
    
    console.log(`Rolling update completed. Successful: ${successfulUpdates}, Failed: ${failedUpdates}`);
  }

  async updateNode(node, updateConfig) {
    // Implementation depends on infrastructure
    // This could be Docker container update, AMI replacement, etc.
    console.log(`Updating node ${node.id}...`);
    
    // Simulate update
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Verify update
    await this.verifyNodeUpdate(node, updateConfig);
    
    console.log(`Node ${node.id} updated successfully`);
  }

  // 11. Health Checks with Degradation Detection
  startHealthChecks(node) {
    const checkId = setInterval(async () => {
      try {
        const health = await this.performComprehensiveHealthCheck(node);
        
        if (health.status === 'healthy') {
          node.status = 'healthy';
          node.metrics = health.metrics;
        } else if (health.status === 'degraded') {
          node.status = 'degraded';
          node.degradationReason = health.reason;
          console.warn(`Node ${node.id} is degraded: ${health.reason}`);
        } else {
          node.status = 'unhealthy';
          node.lastFailure = Date.now();
          console.error(`Node ${node.id} health check failed`);
        }
      } catch (error) {
        console.error(`Health check failed for node ${node.id}:`, error);
        node.status = 'unhealthy';
      }
    }, 30000); // Every 30 seconds
    
    this.healthChecks.set(node.id, checkId);
  }

  async performComprehensiveHealthCheck(node) {
    const checks = [
      this.checkNodeConnectivity(node),
      this.checkServiceHealth(node),
      this.checkResourceUsage(node),
      this.checkResponseTime(node),
      this.checkErrorRate(node)
    ];
    
    const results = await Promise.allSettled(checks);
    
    const failedChecks = results.filter(r => r.status === 'rejected');
    const successfulChecks = results.filter(r => r.status === 'fulfilled');
    
    const metrics = successfulChecks.reduce((acc, result) => ({
      ...acc,
      ...result.value.metrics
    }), {});
    
    if (failedChecks.length === 0) {
      // Check for degradation
      if (metrics.responseTime > 1000 || metrics.errorRate > 5) {
        return {
          status: 'degraded',
          reason: 'Performance issues detected',
          metrics
        };
      }
      
      return {
        status: 'healthy',
        metrics
      };
    } else if (failedChecks.length <= 2) {
      return {
        status: 'degraded',
        reason: 'Partial failures detected',
        metrics
      };
    } else {
      return {
        status: 'unhealthy',
        reason: 'Multiple health checks failed',
        metrics
      };
    }
  }

  // 12. Load Shedding & Graceful Degradation
  async handleHighLoad() {
    const systemLoad = await this.getSystemLoad();
    
    if (systemLoad.cpu > 80 || systemLoad.memory > 90) {
      console.warn('High system load detected, initiating load shedding');
      
      // 1. Shed non-critical traffic
      await this.shedNonCriticalTraffic();
      
      // 2. Reduce service quality
      await this.reduceServiceQuality();
      
      // 3. Enable caching aggressively
      await this.enableAggressiveCaching();
      
      // 4. Notify monitoring
      await this.notifyLoadShedding();
    }
  }

  async shedNonCriticalTraffic() {
    // Implement load shedding strategies:
    
    // 1. Reject new connections from non-priority clients
    // 2. Rate limit aggressive clients
    // 3. Delay background jobs
    // 4. Return cached data instead of computing
    
    console.log('Shedding non-critical traffic...');
  }

  // 13. Geographic Distribution & Latency-based Routing
  async routeToNearestRegion(userLocation) {
    const regions = await this.getAvailableRegions();
    
    // Calculate distances
    const distances = regions.map(region => ({
      region,
      distance: this.calculateDistance(userLocation, region.location),
      latency: await this.measureLatency(region)
    }));
    
    // Sort by latency
    distances.sort((a, b) => a.latency - b.latency);
    
    // Select best region (considering load)
    const bestRegion = distances.find(d => 
      d.region.load < 80 && d.latency < 100
    ) || distances[0];
    
    return bestRegion.region;
  }

  // 14. Chaos Engineering & Resilience Testing
  async runChaosExperiment(experimentConfig) {
    console.log(`Running chaos experiment: ${experimentConfig.name}`);
    
    // 1. Establish steady state
    const baseline = await this.measureSteadyState();
    
    // 2. Introduce failure
    await this.introduceFailure(experimentConfig.failure);
    
    // 3. Monitor system behavior
    const observations = await this.observeSystemBehavior(
      experimentConfig.duration
    );
    
    // 4. Stop experiment
    await this.stopFailure(experimentConfig.failure);
    
    // 5. Compare with baseline
    const analysis = await this.analyzeExperimentResults(
      baseline,
      observations
    );
    
    // 6. Generate report
    const report = this.generateChaosReport(
      experimentConfig,
      baseline,
      observations,
      analysis
    );
    
    console.log('Chaos experiment completed');
    
    return report;
  }

  async introduceFailure(failureType) {
    switch (failureType) {
      case 'network_partition':
        await this.simulateNetworkPartition();
        break;
      case 'node_failure':
        await this.simulateNodeFailure();
        break;
      case 'latency_spike':
        await this.simulateLatencySpike();
        break;
      case 'resource_exhaustion':
        await this.simulateResourceExhaustion();
        break;
    }
  }

  // 15. Capacity Planning & Auto-scaling
  async planCapacity(forecastPeriod = '30 days') {
    const historicalData = await this.getHistoricalMetrics(forecastPeriod);
    const forecast = await this.forecastDemand(historicalData);
    
    const currentCapacity = await this.getCurrentCapacity();
    const projectedGap = forecast.peak - currentCapacity;
    
    if (projectedGap > 0) {
      console.log(`Capacity gap detected: ${projectedGap} units`);
      
      const scalingPlan = await this.createScalingPlan(projectedGap, forecast);
      
      // Execute scaling plan
      if (scalingPlan.immediateAction) {
        await this.executeScalingAction(scalingPlan.immediateAction);
      }
      
      if (scalingPlan.longTermPlan) {
        await this.scheduleLongTermScaling(scalingPlan.longTermPlan);
      }
    }
    
    return {
      forecast,
      currentCapacity,
      gap: projectedGap,
      scalingPlan
    };
  }

  async forecastDemand(historicalData) {
    // Use time series forecasting (ARIMA, Prophet, etc.)
    // This is a simplified linear regression
    
    const timestamps = historicalData.map(d => d.timestamp);
    const values = historicalData.map(d => d.value);
    
    // Simple linear regression
    const n = timestamps.length;
    const sumX = timestamps.reduce((a, b) => a + b, 0);
    const sumY = values.reduce((a, b) => a + b, 0);
    const sumXY = timestamps.reduce((sum, x, i) => sum + x * values[i], 0);
    const sumX2 = timestamps.reduce((sum, x) => sum + x * x, 0);
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;
    
    // Forecast next period
    const futureTimestamp = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
    const forecastValue = slope * futureTimestamp + intercept;
    
    return {
      peak: forecastValue * 1.5, // Add 50% buffer
      average: forecastValue,
      confidence: 0.85
    };
  }

  // Utility methods
  async sendToNode(node, message) {
    // Implementation depends on communication method
    // Could be HTTP, gRPC, WebSocket, etc.
    return new Promise((resolve, reject) => {
      // Simulated network call
      setTimeout(() => {
        if (Math.random() > 0.1) { // 90% success rate
          resolve();
        } else {
          reject(new Error('Network error'));
        }
      }, 100);
    });
  }

  async writeToNode(node, data) {
    // Implementation for writing data to a node
    return this.sendToNode(node, {
      type: 'WRITE',
      data
    });
  }

  async readFromNode(node, key) {
    // Implementation for reading data from a node
    return {
      key,
      value: 'simulated-value',
      timestamp: Date.now()
    };
  }

  calculateDistance(loc1, loc2) {
    // Haversine formula for geographic distance
    const R = 6371; // Earth's radius in km
    const dLat = this.toRad(loc2.lat - loc1.lat);
    const dLon = this.toRad(loc2.lon - loc1.lon);
    
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(this.toRad(loc1.lat)) * Math.cos(this.toRad(loc2.lat)) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    
    return R * c;
  }

  toRad(degrees) {
    return degrees * Math.PI / 180;
  }
}

// Data Replication Manager
class DataReplicationManager {
  constructor() {
    this.replicationFactor = 3;
    this.consistencyLevel = 'quorum';
    this.replicationLog = [];
  }

  async promoteToLeader(node) {
    console.log(`Promoting ${node.id} to leader`);
    
    // 1. Stop accepting writes on old leader
    // 2. Sync latest data to new leader
    // 3. Update replication topology
    // 4. Start accepting writes on new leader
    
    await this.syncDataToLeader(node);
    await this.updateReplicationTopology(node);
    
    return node;
  }

  async adjustReplication(failedNode) {
    console.log(`Adjusting replication after ${failedNode.id} failure`);
    
    // 1. Identify under-replicated data
    const underReplicated = await this.findUnderReplicatedData(failedNode);
    
    // 2. Replicate to other nodes
    await this.replicateToOtherNodes(underReplicated);
    
    // 3. Update replication metadata
    await this.updateReplicationMetadata(failedNode);
  }

  async findUnderReplicatedData(failedNode) {
    // Find data that was only on the failed node
    return []; // Simplified
  }
}

// Backup Manager
class BackupManager {
  constructor() {
    this.storage = new BackupStorage();
    this.retentionPolicy = {
      daily: 7,
      weekly: 4,
      monthly: 12,
      yearly: 3
    };
  }

  async storeBackup(backupData) {
    const backupId = backupData.id;
    
    // Store locally
    await this.storage.storeLocal(backupId, backupData);
    
    // Replicate to remote
    await this.storage.replicateRemote(backupId, backupData);
    
    // Update backup index
    await this.updateBackupIndex(backupId, backupData);
    
    // Apply retention policy
    await this.applyRetentionPolicy();
  }

  async getLatestBackup() {
    const index = await this.getBackupIndex();
    
    if (index.length === 0) {
      return null;
    }
    
    // Sort by timestamp descending
    index.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    return index[0];
  }

  async applyRetentionPolicy() {
    const index = await this.getBackupIndex();
    
    // Group by time period
    const now = new Date();
    
    const toDelete = [];
    
    // Apply retention policies
    // Implementation depends on specific requirements
    
    // Delete old backups
    for (const backupId of toDelete) {
      await this.deleteBackup(backupId);
    }
  }
}

// Monitoring & Alerting for HA
class HAMonitoring {
  constructor() {
    this.metrics = new Map();
    this.alerts = new Map();
    this.dashboards = new Map();
  }

  async trackHAMetrics() {
    setInterval(async () => {
      const metrics = await this.collectHAMetrics();
      this.storeMetrics(metrics);
      this.checkAlerts(metrics);
      this.updateDashboards(metrics);
    }, 10000); // Every 10 seconds
  }

  async collectHAMetrics() {
    return {
      timestamp: new Date().toISOString(),
      nodeCount: this.nodes.size,
      healthyNodes: Array.from(this.nodes.values()).filter(n => n.status === 'healthy').length,
      leader: this.leader?.id,
      replicationHealth: await this.checkReplicationHealth(),
      backupStatus: await this.checkBackupStatus(),
      systemLoad: await this.getSystemLoad(),
      networkLatency: await this.measureNetworkLatency()
    };
  }

  async checkAlerts(metrics) {
    const alertRules = this.getAlertRules();
    
    for (const rule of alertRules) {
      if (this.evaluateRule(rule, metrics)) {
        await this.triggerAlert(rule, metrics);
      }
    }
  }

  getAlertRules() {
    return [
      {
        id: 'node_failure',
        condition: (metrics) => metrics.healthyNodes / metrics.nodeCount < 0.5,
        severity: 'critical',
        message: 'More than 50% of nodes are unhealthy'
      },
      {
        id: 'no_leader',
        condition: (metrics) => !metrics.leader,
        severity: 'critical',
        message: 'No leader elected'
      },
      {
        id: 'high_latency',
        condition: (metrics) => metrics.networkLatency > 1000,
        severity: 'warning',
        message: 'Network latency above threshold'
      }
    ];
  }
}

// Example usage
async function setupHighAvailability() {
  const haManager = new HighAvailabilityManager();
  
  // Register nodes
  haManager.registerNode('node-1', {
    host: '10.0.0.1',
    port: 3000,
    role: 'leader',
    priority: 10,
    region: 'us-east-1'
  });
  
  haManager.registerNode('node-2', {
    host: '10.0.0.2',
    port: 3000,
    role: 'follower',
    priority: 8,
    region: 'us-east-1'
  });
  
  haManager.registerNode('node-3', {
    host: '10.0.0.3',
    port: 3000,
    role: 'follower',
    priority: 6,
    region: 'us-west-2'
  });
  
  // Set up monitoring
  const monitoring = new HAMonitoring();
  await monitoring.trackHAMetrics();
  
  // Perform regular backups
  setInterval(async () => {
    await haManager.performBackup('incremental');
  }, 24 * 60 * 60 * 1000); // Daily
  
  // Run chaos experiments (in development/staging)
  if (process.env.NODE_ENV === 'development') {
    setInterval(async () => {
      await haManager.runChaosExperiment({
        name: 'Network partition test',
        failure: 'network_partition',
        duration: 300000 // 5 minutes
      });
    }, 7 * 24 * 60 * 60 * 1000); // Weekly
  }
  
  // Capacity planning
  setInterval(async () => {
    const plan = await haManager.planCapacity('30 days');
    console.log('Capacity plan:', plan);
  }, 24 * 60 * 60 * 1000); // Daily
  
  return haManager;
}
```

---

## 11. Interview Questions

### Load Balancing
**Technical Questions:**
1. Explain different load balancing algorithms and their use cases.
2. How does sticky session (session persistence) work in load balancing?
3. What are the differences between Layer 4 and Layer 7 load balancing?

**Scenario-Based Questions:**
1. You notice one server is receiving 90% of traffic while others are idle. How would you diagnose and fix this?
2. How would you implement zero-downtime deployment with a load balancer?
3. Your load balancer is returning 502 errors. What steps would you take to troubleshoot?

### Horizontal vs Vertical Scaling
**Technical Questions:**
1. When would you choose vertical scaling over horizontal scaling?
2. What are the challenges of scaling Node.js applications horizontally?
3. How do you handle shared state in a horizontally scaled application?

**Scenario-Based Questions:**
1. Your application needs to handle 100x more traffic. What scaling strategy would you choose and why?
2. How would you migrate from vertical to horizontal scaling without downtime?
3. What metrics would you monitor to decide when to scale?

### Cache Layers
**Technical Questions:**
1. Explain different cache invalidation strategies and their trade-offs.
2. How would you implement a multi-level caching strategy?
3. What is cache stampede and how do you prevent it?

**Scenario-Based Questions:**
1. Users report seeing stale data after updates. How would you debug cache invalidation?
2. Your cache hit rate dropped from 95% to 60%. How would you investigate?
3. How would you design caching for a globally distributed application?

### CDN Usage
**Technical Questions:**
1. What types of content should and shouldn't be served through a CDN?
2. How do you handle cache invalidation in a CDN?
3. What are edge functions and when would you use them?

**Scenario-Based Questions:**
1. Users in Asia report slow load times for your US-based application. How would you use CDN to solve this?
2. How would you implement A/B testing at the CDN level?
3. Your CDN costs have unexpectedly tripled. How would you investigate and optimize?

### Database Sharding
**Technical Questions:**
1. Explain different sharding strategies and when to use each.
2. How do you handle cross-shard queries and transactions?
3. What are the challenges of re-sharding an existing database?

**Scenario-Based Questions:**
1. Your database is hitting performance limits. How would you decide whether to shard or optimize?
2. How would you migrate a monolithic database to a sharded architecture?
3. What would you do if one shard fails and needs to be recovered?

### Indexing & Query Optimization
**Technical Questions:**
1. When should you create an index and when should you avoid it?
2. Explain different types of database indexes and their use cases.
3. How do you identify slow queries in production?

**Scenario-Based Questions:**
1. A critical query suddenly becomes slow. How would you diagnose and fix it?
2. Your database has too many indexes affecting write performance. How would you optimize?
3. How would you design indexes for a time-series database?

### Rate Limiting Strategies
**Technical Questions:**
1. Compare token bucket, leaky bucket, and fixed window algorithms.
2. How would you implement distributed rate limiting?
3. What are the security considerations for rate limiting?

**Scenario-Based Questions:**
1. Your API is under DDoS attack. How would you adjust rate limiting?
2. A legitimate customer complains about being rate limited. How would you handle this?
3. How would you implement different rate limits for different API tiers?

### Queues & Async Processing
**Technical Questions:**
1. When should you use synchronous vs asynchronous processing?
2. Explain different message delivery semantics (at-most-once, at-least-once, exactly-once).
3. How do you handle poison messages in a queue?

**Scenario-Based Questions:**
1. Your queue is backing up with millions of messages. How would you handle this?
2. How would you implement ordered message processing across multiple consumers?
3. Messages are being processed multiple times. How would you implement deduplication?

### API Gateway Design
**Technical Questions:**
1. What are the benefits and drawbacks of using an API gateway?
2. How would you implement circuit breaking in an API gateway?
3. What security features should an API gateway provide?

**Scenario-Based Questions:**
1. Your API gateway is becoming a performance bottleneck. How would you scale it?
2. How would you implement canary deployments through an API gateway?
3. Users report inconsistent responses from different API endpoints. How would you debug?

### High Availability Architecture
**Technical Questions:**
1. Explain different disaster recovery strategies (hot, warm, cold standby).
2. How does leader election work in distributed systems?
3. What are the CAP theorem trade-offs in your system?

**Scenario-Based Questions:**
1. Your primary data center goes down. What's your recovery plan?
2. How would you design a system for 99.999% availability?
3. During a partial network partition, how would you maintain system consistency?

### Senior Developer Real-World Scenarios

1. **System Design**: "Design Twitter's timeline service that serves 1 million requests per second with < 200ms latency. Consider read/write patterns, caching, and consistency."

2. **Performance Crisis**: "Production system response times increased from 50ms to 2 seconds overnight. What's your investigation and resolution plan?"

3. **Database Migration**: "You need to migrate a 10TB production database from MongoDB to PostgreSQL without downtime. How would you approach this?"

4. **Security Incident**: "An attacker exploited a rate limiting vulnerability causing service disruption. What immediate actions and long-term fixes?"

5. **Cost Optimization**: "Your cloud bill increased 300% in one month with no traffic increase. How would you identify and fix cost issues?"

6. **Scaling Decision**: "Your monolith is hitting limits. Would you refactor to microservices, scale vertically, or implement caching? Justify your choice."

7. **Third-Party Dependency Failure**: "A critical payment provider is down. How do you maintain service availability?"

8. **Data Consistency**: "Users report seeing different data on different devices. How do you debug and fix consistency issues?"

9. **Team Leadership**: "You're leading migration to a new architecture. How do you manage risk and ensure team adoption?"

10. **Cross-Region Deployment**: "You need to deploy your application to comply with GDPR in Europe while maintaining global consistency."

---

## 🎯 Conclusion

System design for Node.js developers requires understanding distributed systems principles and applying them practically. Key takeaways:

1. **Start Simple, Scale Smart**: Begin with simple architectures and add complexity only when needed.
2. **Measure Everything**: You can't optimize what you can't measure.
3. **Design for Failure**: Everything fails eventually - plan for it.
4. **Iterate and Improve**: System design is an iterative process.
5. **Balance Trade-offs**: Every decision has trade-offs - understand and document them.

Remember, the best system design depends on your specific requirements, constraints, and team capabilities. Use these patterns as guidelines, not rules.

---

**Next Steps**:
1. Implement monitoring before optimization
2. Start with vertical scaling, move to horizontal when needed
3. Use caching strategically, not everywhere
4. Test failure scenarios regularly
5. Document design decisions and their trade-offs

**Recommended Resources**:
- Designing Data-Intensive Applications by Martin Kleppmann
- Site Reliability Engineering by Google
- AWS Well-Architected Framework
- The System Design Primer (GitHub)

