# Redis: Complete Guide for Node.js

## Table of Contents
- [Introduction to Redis](#introduction-to-redis)
- [Getting Started with Redis in Node.js](#getting-started-with-redis-in-nodejs)
- [Caching](#caching)
  - [Cache Patterns](#cache-patterns)
  - [Cache Invalidation Strategies](#cache-invalidation-strategies)
  - [Distributed Caching](#distributed-caching)
  - [Cache Performance Optimization](#cache-performance-optimization)
- [Rate Limiting](#rate-limiting)
  - [Rate Limiting Algorithms](#rate-limiting-algorithms)
  - [Distributed Rate Limiting](#distributed-rate-limiting)
  - [Advanced Rate Limiting Patterns](#advanced-rate-limiting-patterns)
- [Blacklisting Tokens](#blacklisting-tokens)
  - [JWT Token Blacklisting](#jwt-token-blacklisting)
  - [Session Management](#session-management)
  - [Token Rotation & Refresh](#token-rotation--refresh)
- [Pub/Sub for Notifications](#pubsub-for-notifications)
  - [Real-time Communication](#real-time-communication)
  - [Message Queue Patterns](#message-queue-patterns)
  - [Event Sourcing with Redis Streams](#event-sourcing-with-redis-streams)
- [Advanced Redis Patterns](#advanced-redis-patterns)
  - [Redis Data Structures](#redis-data-structures)
  - [Redis Cluster & Sentinel](#redis-cluster--sentinel)
  - [Performance Monitoring](#performance-monitoring)
- [Interview Questions](#interview-questions)
  - [Junior to Mid-Level](#junior-to-mid-level)
  - [Senior Level](#senior-level)
  - [Real-World Scenarios](#real-world-scenarios)

---

## Introduction to Redis

Redis (Remote Dictionary Server) is an in-memory data structure store used as a database, cache, and message broker. It supports various data structures such as strings, hashes, lists, sets, sorted sets, bitmaps, hyperloglogs, and streams.

### Why Redis?

1. **Performance**: In-memory operations with sub-millisecond latency
2. **Versatility**: Multiple data structures for different use cases
3. **Persistence**: Options for disk persistence (RDB, AOF)
4. **Replication**: Master-slave replication for high availability
5. **Partitioning**: Redis Cluster for horizontal scaling
6. **Pub/Sub**: Built-in publish/subscribe messaging
7. **Transactions**: Support for atomic operations

### Common Use Cases
- Caching layer for databases
- Session storage
- Real-time analytics
- Message queues
- Rate limiting
- Leaderboards and counting
- Geospatial indexing
- Full-text search

---

## Getting Started with Redis in Node.js

### Installation & Setup

```bash
# Install Redis
brew install redis  # macOS
sudo apt-get install redis-server  # Ubuntu

# Install Redis client for Node.js
npm install redis ioredis
npm install -D @types/redis  # TypeScript types
```

### Basic Configuration

```javascript
// Using redis package
const redis = require('redis');

// Using ioredis (recommended for production)
const Redis = require('ioredis');

// Create Redis client
const redisClient = redis.createClient({
  url: 'redis://localhost:6379',
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.log('Too many retries. Giving up.');
        return new Error('Max retries reached');
      }
      return Math.min(retries * 50, 2000);
    }
  }
});

// Create ioredis client with advanced configuration
const redis = new Redis({
  port: 6379,
  host: 'localhost',
  password: process.env.REDIS_PASSWORD,
  db: 0, // Database index
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  autoResendUnfulfilledCommands: true,
  lazyConnect: false,
  enableAutoPipelining: true,
  autoPipeliningIgnoredCommands: ['multi', 'exec', 'info'],
  connectionName: 'app-server',
  showFriendlyErrorStack: process.env.NODE_ENV === 'development'
});

// Handle connection events
redis.on('connect', () => {
  console.log('Redis connected');
});

redis.on('ready', () => {
  console.log('Redis ready for commands');
});

redis.on('error', (err) => {
  console.error('Redis error:', err);
});

redis.on('close', () => {
  console.log('Redis connection closed');
});

redis.on('reconnecting', (time) => {
  console.log(`Redis reconnecting in ${time}ms`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing Redis connection');
  await redis.quit();
  process.exit(0);
});

// Test connection
async function testConnection() {
  try {
    await redis.ping();
    console.log('Redis connection successful');
  } catch (error) {
    console.error('Redis connection failed:', error);
  }
}

// Connection pool for multiple Redis instances
class RedisPool {
  constructor() {
    this.clients = new Map();
    this.configs = new Map();
  }
  
  addClient(name, config) {
    const client = new Redis(config);
    this.clients.set(name, client);
    this.configs.set(name, config);
    return client;
  }
  
  getClient(name) {
    return this.clients.get(name);
  }
  
  async closeAll() {
    const promises = [];
    for (const [name, client] of this.clients) {
      promises.push(client.quit());
    }
    await Promise.all(promises);
    this.clients.clear();
  }
  
  async healthCheck() {
    const results = {};
    for (const [name, client] of this.clients) {
      try {
        await client.ping();
        results[name] = { status: 'healthy' };
      } catch (error) {
        results[name] = { status: 'unhealthy', error: error.message };
      }
    }
    return results;
  }
}
```

---

## Caching

### Cache Patterns

#### 1. Cache-Aside (Lazy Loading)

```javascript
class CacheAsideService {
  constructor(redisClient, database) {
    this.redis = redisClient;
    this.db = database;
    this.cachePrefix = 'cache:';
    this.defaultTTL = 300; // 5 minutes
  }
  
  async getUser(userId) {
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    
    // Try to get from cache
    try {
      const cachedData = await this.redis.get(cacheKey);
      if (cachedData) {
        console.log('Cache hit for user:', userId);
        return JSON.parse(cachedData);
      }
    } catch (error) {
      console.error('Cache read error:', error);
      // Continue to database on cache error
    }
    
    console.log('Cache miss for user:', userId);
    
    // Get from database
    const user = await this.db.user.findUnique({
      where: { id: userId },
      include: { profile: true }
    });
    
    if (!user) {
      return null;
    }
    
    // Store in cache
    try {
      await this.redis.setex(
        cacheKey,
        this.defaultTTL,
        JSON.stringify(user)
      );
    } catch (error) {
      console.error('Cache write error:', error);
      // Don't throw, just log the error
    }
    
    return user;
  }
  
  async getProducts(category, page = 1, limit = 20) {
    const cacheKey = `${this.cachePrefix}products:${category}:${page}:${limit}`;
    
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Cache read error:', error);
    }
    
    const products = await this.db.product.findMany({
      where: { category, status: 'ACTIVE' },
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: 'desc' }
    });
    
    try {
      // Cache for shorter time for paginated data
      await this.redis.setex(cacheKey, 60, JSON.stringify(products));
      
      // Also cache individual products
      await this.cacheIndividualProducts(products);
    } catch (error) {
      console.error('Cache write error:', error);
    }
    
    return products;
  }
  
  async cacheIndividualProducts(products) {
    const pipeline = this.redis.pipeline();
    
    products.forEach(product => {
      const key = `${this.cachePrefix}product:${product.id}`;
      pipeline.setex(key, 3600, JSON.stringify(product)); // 1 hour
    });
    
    await pipeline.exec();
  }
  
  async invalidateUser(userId) {
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    try {
      await this.redis.del(cacheKey);
    } catch (error) {
      console.error('Cache invalidation error:', error);
    }
  }
  
  async batchGetUsers(userIds) {
    const pipeline = this.redis.pipeline();
    const cacheKeys = userIds.map(id => `${this.cachePrefix}user:${id}`);
    
    // Get all from cache
    cacheKeys.forEach(key => pipeline.get(key));
    
    const results = await pipeline.exec();
    const users = [];
    const missingIds = [];
    
    results.forEach(([error, data], index) => {
      if (!error && data) {
        users[index] = JSON.parse(data);
      } else {
        missingIds.push(userIds[index]);
      }
    });
    
    // Fetch missing users from database
    if (missingIds.length > 0) {
      const dbUsers = await this.db.user.findMany({
        where: { id: { in: missingIds } }
      });
      
      // Cache fetched users
      const cachePipeline = this.redis.pipeline();
      dbUsers.forEach(user => {
        const key = `${this.cachePrefix}user:${user.id}`;
        cachePipeline.setex(key, this.defaultTTL, JSON.stringify(user));
        // Update users array
        const index = userIds.indexOf(user.id);
        users[index] = user;
      });
      
      await cachePipeline.exec();
    }
    
    return users;
  }
}
```

#### 2. Write-Through Cache

```javascript
class WriteThroughCache {
  constructor(redisClient, database) {
    this.redis = redisClient;
    this.db = database;
    this.cachePrefix = 'write-through:';
  }
  
  async createUser(userData) {
    // Create in database
    const user = await this.db.user.create({
      data: userData
    });
    
    // Immediately write to cache
    const cacheKey = `${this.cachePrefix}user:${user.id}`;
    await this.redis.setex(
      cacheKey,
      3600, // 1 hour
      JSON.stringify(user)
    );
    
    // Invalidate related caches
    await this.invalidateRelatedCaches(user);
    
    return user;
  }
  
  async updateUser(userId, updateData) {
    // Update in database
    const user = await this.db.user.update({
      where: { id: userId },
      data: updateData
    });
    
    // Update cache
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    await this.redis.setex(
      cacheKey,
      3600,
      JSON.stringify(user)
    );
    
    // Invalidate related caches
    await this.invalidateRelatedCaches(user);
    
    return user;
  }
  
  async invalidateRelatedCaches(user) {
    const pipeline = this.redis.pipeline();
    
    // Invalidate user lists that might include this user
    pipeline.del(`${this.cachePrefix}users:active`);
    pipeline.del(`${this.cachePrefix}users:recent`);
    
    // Invalidate search indexes
    if (user.email) {
      pipeline.del(`${this.cachePrefix}user:email:${user.email}`);
    }
    
    await pipeline.exec();
  }
  
  async getUser(userId) {
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Cache read error:', error);
    }
    
    // Should not happen in write-through, but fallback
    return this.db.user.findUnique({
      where: { id: userId }
    });
  }
}
```

#### 3. Write-Behind (Write-Back) Cache

```javascript
class WriteBehindCache {
  constructor(redisClient, database, queue) {
    this.redis = redisClient;
    this.db = database;
    this.queue = queue;
    this.cachePrefix = 'write-behind:';
    this.writeQueueKey = 'write-queue';
    this.batchSize = 100;
    this.flushInterval = 5000; // 5 seconds
  }
  
  async startBackgroundWriter() {
    setInterval(() => {
      this.flushWriteQueue();
    }, this.flushInterval);
  }
  
  async updateUser(userId, updateData) {
    // Update cache immediately
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    const currentUser = await this.getUser(userId);
    const updatedUser = { ...currentUser, ...updateData };
    
    await this.redis.setex(
      cacheKey,
      3600,
      JSON.stringify(updatedUser)
    );
    
    // Queue database write for later
    await this.queueWrite('user', userId, updateData);
    
    return updatedUser;
  }
  
  async queueWrite(entity, id, data) {
    const writeJob = {
      entity,
      id,
      data,
      timestamp: Date.now(),
      retryCount: 0
    };
    
    await this.redis.lpush(
      this.writeQueueKey,
      JSON.stringify(writeJob)
    );
    
    // Trim queue if too long
    await this.redis.ltrim(this.writeQueueKey, 0, 10000);
  }
  
  async flushWriteQueue() {
    try {
      // Get batch of writes
      const writeJobs = [];
      for (let i = 0; i < this.batchSize; i++) {
        const job = await this.redis.rpop(this.writeQueueKey);
        if (!job) break;
        writeJobs.push(JSON.parse(job));
      }
      
      if (writeJobs.length === 0) return;
      
      // Group writes by entity for batch processing
      const writesByEntity = {};
      writeJobs.forEach(job => {
        if (!writesByEntity[job.entity]) {
          writesByEntity[job.entity] = [];
        }
        writesByEntity[job.entity].push(job);
      });
      
      // Process each entity type
      for (const [entity, jobs] of Object.entries(writesByEntity)) {
        await this.processEntityWrites(entity, jobs);
      }
      
      console.log(`Flushed ${writeJobs.length} writes to database`);
    } catch (error) {
      console.error('Error flushing write queue:', error);
    }
  }
  
  async processEntityWrites(entity, jobs) {
    switch (entity) {
      case 'user':
        await this.processUserWrites(jobs);
        break;
      case 'product':
        await this.processProductWrites(jobs);
        break;
      default:
        console.warn(`Unknown entity: ${entity}`);
    }
  }
  
  async processUserWrites(jobs) {
    // Batch update users
    const updates = jobs.map(job => ({
      where: { id: job.id },
      data: job.data
    }));
    
    // Use transaction for batch updates
    await this.db.$transaction(
      updates.map(update => 
        this.db.user.update(update)
      )
    );
  }
  
  async getUser(userId) {
    const cacheKey = `${this.cachePrefix}user:${userId}`;
    
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Cache read error:', error);
    }
    
    // Fallback to database (should be rare)
    return this.db.user.findUnique({
      where: { id: userId }
    });
  }
}
```

#### 4. Refresh-Ahead Cache

```javascript
class RefreshAheadCache {
  constructor(redisClient, database) {
    this.redis = redisClient;
    this.db = database;
    this.cachePrefix = 'refresh-ahead:';
    this.refreshThreshold = 0.8; // Refresh when 80% of TTL passed
    this.backgroundJobs = new Map();
  }
  
  async getProduct(productId) {
    const cacheKey = `${this.cachePrefix}product:${productId}`;
    
    // Get with TTL
    const pipeline = this.redis.pipeline();
    pipeline.get(cacheKey);
    pipeline.ttl(cacheKey);
    
    const [[getError, data], [ttlError, ttl]] = await pipeline.exec();
    
    if (getError || ttlError) {
      console.error('Cache error:', getError || ttlError);
      return this.fetchFromDBAndCache(productId);
    }
    
    if (!data) {
      return this.fetchFromDBAndCache(productId);
    }
    
    const product = JSON.parse(data);
    
    // Check if we need to refresh
    if (ttl > 0 && this.shouldRefresh(ttl, 3600)) { // Assuming 1 hour TTL
      this.scheduleRefresh(productId);
    }
    
    return product;
  }
  
  shouldRefresh(currentTTL, originalTTL) {
    const timeLived = originalTTL - currentTTL;
    const percentageLived = timeLived / originalTTL;
    return percentageLived >= this.refreshThreshold;
  }
  
  scheduleRefresh(productId) {
    // Don't schedule if already refreshing
    if (this.backgroundJobs.has(productId)) {
      return;
    }
    
    const job = setTimeout(async () => {
      try {
        await this.refreshProduct(productId);
      } catch (error) {
        console.error('Refresh error:', error);
      } finally {
        this.backgroundJobs.delete(productId);
      }
    }, 1000); // Delay 1 second
    
    this.backgroundJobs.set(productId, job);
  }
  
  async refreshProduct(productId) {
    console.log('Refreshing product:', productId);
    
    const product = await this.db.product.findUnique({
      where: { id: productId },
      include: { inventory: true }
    });
    
    if (!product) {
      // Product deleted, remove from cache
      await this.redis.del(`${this.cachePrefix}product:${productId}`);
      return;
    }
    
    const cacheKey = `${this.cachePrefix}product:${productId}`;
    await this.redis.setex(cacheKey, 3600, JSON.stringify(product));
  }
  
  async fetchFromDBAndCache(productId) {
    const product = await this.db.product.findUnique({
      where: { id: productId },
      include: { inventory: true }
    });
    
    if (!product) {
      return null;
    }
    
    const cacheKey = `${this.cachePrefix}product:${productId}`;
    await this.redis.setex(cacheKey, 3600, JSON.stringify(product));
    
    return product;
  }
  
  stop() {
    // Clear all scheduled refreshes
    for (const job of this.backgroundJobs.values()) {
      clearTimeout(job);
    }
    this.backgroundJobs.clear();
  }
}
```

### Cache Invalidation Strategies

```javascript
class CacheInvalidationManager {
  constructor(redisClient) {
    this.redis = redisClient;
    this.tagPrefix = 'tag:';
    this.cachePrefix = 'cache:';
  }
  
  // Tag-based invalidation
  async setWithTags(key, value, ttl, tags) {
    // Store the cache value
    await this.redis.setex(key, ttl, JSON.stringify(value));
    
    // Store reverse mapping from tags to keys
    const pipeline = this.redis.pipeline();
    
    tags.forEach(tag => {
      const tagKey = `${this.tagPrefix}${tag}`;
      pipeline.sadd(tagKey, key);
      pipeline.expire(tagKey, ttl + 3600); // Tag expires after cache + 1 hour
    });
    
    await pipeline.exec();
  }
  
  async invalidateByTag(tag) {
    const tagKey = `${this.tagPrefix}${tag}`;
    
    // Get all keys with this tag
    const keys = await this.redis.smembers(tagKey);
    
    if (keys.length > 0) {
      // Delete all cached items
      await this.redis.del(...keys);
      
      // Remove the tag
      await this.redis.del(tagKey);
    }
    
    console.log(`Invalidated ${keys.length} items with tag: ${tag}`);
  }
  
  async invalidateByPattern(pattern) {
    let cursor = '0';
    let deletedCount = 0;
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.cachePrefix}${pattern}`,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      if (keys.length > 0) {
        await this.redis.del(...keys);
        deletedCount += keys.length;
      }
    } while (cursor !== '0');
    
    console.log(`Invalidated ${deletedCount} items matching pattern: ${pattern}`);
  }
  
  // Version-based cache invalidation
  async getWithVersion(key, versionKey) {
    const currentVersion = await this.redis.get(versionKey);
    
    if (!currentVersion) {
      return null; // No cached version
    }
    
    const versionedKey = `${key}:v${currentVersion}`;
    const cached = await this.redis.get(versionedKey);
    
    return cached ? JSON.parse(cached) : null;
  }
  
  async setWithVersion(key, value, versionKey, ttl) {
    // Get or create version
    let version = await this.redis.get(versionKey);
    
    if (!version) {
      version = '1';
      await this.redis.set(versionKey, version);
    }
    
    const versionedKey = `${key}:v${version}`;
    await this.redis.setex(versionedKey, ttl, JSON.stringify(value));
  }
  
  async invalidateVersion(versionKey) {
    // Increment version to invalidate all cached items
    const newVersion = await this.redis.incr(versionKey);
    console.log(`Invalidated cache, new version: ${newVersion}`);
    return newVersion;
  }
  
  // Time-based invalidation with grace period
  async getWithGracePeriod(key, fetchFn, ttl, gracePeriod) {
    const cacheKey = `${this.cachePrefix}${key}`;
    const staleKey = `${this.cachePrefix}${key}:stale`;
    
    // Try to get from cache
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      const data = JSON.parse(cached);
      
      // Check if cache is stale
      const ttlRemaining = await this.redis.ttl(cacheKey);
      
      if (ttlRemaining <= gracePeriod) {
        // Cache is stale, refresh in background
        this.refreshInBackground(key, fetchFn, ttl).catch(console.error);
        
        // Return stale data with warning
        data._cacheStatus = 'stale';
        return data;
      }
      
      data._cacheStatus = 'fresh';
      return data;
    }
    
    // Cache miss, fetch and cache
    const freshData = await fetchFn();
    
    if (freshData) {
      await this.redis.setex(cacheKey, ttl, JSON.stringify(freshData));
      freshData._cacheStatus = 'miss';
    }
    
    return freshData;
  }
  
  async refreshInBackground(key, fetchFn, ttl) {
    try {
      const freshData = await fetchFn();
      
      if (freshData) {
        const cacheKey = `${this.cachePrefix}${key}`;
        await this.redis.setex(cacheKey, ttl, JSON.stringify(freshData));
        console.log(`Background refresh completed for: ${key}`);
      }
    } catch (error) {
      console.error(`Background refresh failed for ${key}:`, error);
    }
  }
  
  // Cache warming
  async warmCache(patterns) {
    console.log('Starting cache warm-up...');
    
    const warmUpPromises = patterns.map(async pattern => {
      try {
        await pattern.warmUp(this.redis);
        console.log(`Warmed up: ${pattern.name}`);
      } catch (error) {
        console.error(`Failed to warm up ${pattern.name}:`, error);
      }
    });
    
    await Promise.all(warmUpPromises);
    console.log('Cache warm-up completed');
  }
}

// Cache warming patterns
const cacheWarmingPatterns = {
  popularProducts: {
    name: 'popular-products',
    warmUp: async (redis) => {
      // Fetch popular products from database
      const popularProducts = await db.product.findMany({
        where: { status: 'ACTIVE' },
        orderBy: { views: 'desc' },
        take: 100
      });
      
      const pipeline = redis.pipeline();
      
      popularProducts.forEach(product => {
        const key = `cache:product:${product.id}`;
        pipeline.setex(key, 3600, JSON.stringify(product));
      });
      
      await pipeline.exec();
    }
  },
  
  userSessions: {
    name: 'user-sessions',
    warmUp: async (redis) => {
      // Pre-cache active user sessions
      const activeUsers = await db.user.findMany({
        where: { 
          lastActiveAt: { gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        },
        take: 1000
      });
      
      const pipeline = redis.pipeline();
      
      activeUsers.forEach(user => {
        const key = `cache:user:${user.id}`;
        pipeline.setex(key, 1800, JSON.stringify(user));
      });
      
      await pipeline.exec();
    }
  }
};
```

### Distributed Caching

```javascript
class DistributedCache {
  constructor(redisClient, cacheName) {
    this.redis = redisClient;
    this.cacheName = cacheName;
    this.lockPrefix = 'lock:';
    this.stampedeProtection = new Map();
  }
  
  // Cache stampede protection
  async getWithStampedeProtection(key, fetchFn, ttl = 300) {
    const cacheKey = `${this.cacheName}:${key}`;
    
    // Try to get from cache
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Check if another process is already fetching
    const lockKey = `${this.lockPrefix}${cacheKey}`;
    const lockAcquired = await this.acquireLock(lockKey, 5000); // 5 second lock
    
    if (!lockAcquired) {
      // Another process is fetching, wait and retry
      await new Promise(resolve => setTimeout(resolve, 100));
      return this.getWithStampedeProtection(key, fetchFn, ttl);
    }
    
    try {
      // Fetch data
      const data = await fetchFn();
      
      if (data) {
        // Cache with TTL
        await this.redis.setex(cacheKey, ttl, JSON.stringify(data));
      }
      
      return data;
    } finally {
      // Release lock
      await this.releaseLock(lockKey);
    }
  }
  
  async acquireLock(lockKey, ttl) {
    try {
      const result = await this.redis.set(
        lockKey,
        '1',
        'NX',        // Only set if not exists
        'PX',        // Expire in milliseconds
        ttl
      );
      
      return result === 'OK';
    } catch (error) {
      console.error('Lock acquisition error:', error);
      return false;
    }
  }
  
  async releaseLock(lockKey) {
    await this.redis.del(lockKey);
  }
  
  // Cache coherency with publish/subscribe
  async setWithCoherence(key, value, ttl) {
    const cacheKey = `${this.cacheName}:${key}`;
    
    // Store in cache
    await this.redis.setex(cacheKey, ttl, JSON.stringify(value));
    
    // Publish invalidation to other instances
    await this.redis.publish(
      'cache-invalidate',
      JSON.stringify({ key: cacheKey, action: 'update' })
    );
  }
  
  async subscribeToInvalidations() {
    const subscriber = this.redis.duplicate();
    
    await subscriber.subscribe('cache-invalidate');
    
    subscriber.on('message', async (channel, message) => {
      if (channel === 'cache-invalidate') {
        const { key, action } = JSON.parse(message);
        
        if (action === 'invalidate') {
          await this.redis.del(key);
          console.log(`Invalidated cache key: ${key}`);
        } else if (action === 'update') {
          // Optional: Handle update notifications
          console.log(`Cache key updated: ${key}`);
        }
      }
    });
    
    return subscriber;
  }
  
  // Two-level caching (local + Redis)
  async getWithTwoLevelCache(key, fetchFn, ttl = 300) {
    const localCache = new Map();
    const cacheKey = `${this.cacheName}:${key}`;
    
    // Check local cache first
    if (localCache.has(cacheKey)) {
      const { value, expiry } = localCache.get(cacheKey);
      
      if (Date.now() < expiry) {
        return value;
      } else {
        localCache.delete(cacheKey);
      }
    }
    
    // Check Redis cache
    const redisCached = await this.redis.get(cacheKey);
    
    if (redisCached) {
      const value = JSON.parse(redisCached);
      
      // Store in local cache with shorter TTL
      localCache.set(cacheKey, {
        value,
        expiry: Date.now() + (ttl * 1000) / 2 // Half the Redis TTL
      });
      
      return value;
    }
    
    // Fetch from source
    const data = await fetchFn();
    
    if (data) {
      // Store in Redis
      await this.redis.setex(cacheKey, ttl, JSON.stringify(data));
      
      // Store in local cache
      localCache.set(cacheKey, {
        value: data,
        expiry: Date.now() + (ttl * 1000) / 2
      });
    }
    
    return data;
  }
  
  // Cache with compression
  async setCompressed(key, value, ttl) {
    const cacheKey = `${this.cacheName}:${key}`;
    
    // Compress data
    const compressed = await this.compress(JSON.stringify(value));
    
    await this.redis.setex(cacheKey, ttl, compressed);
  }
  
  async getCompressed(key) {
    const cacheKey = `${this.cacheName}:${key}`;
    const compressed = await this.redis.get(cacheKey);
    
    if (!compressed) {
      return null;
    }
    
    // Decompress data
    const decompressed = await this.decompress(compressed);
    return JSON.parse(decompressed);
  }
  
  async compress(data) {
    // Use zlib for compression
    const zlib = require('zlib');
    return new Promise((resolve, reject) => {
      zlib.deflate(data, (err, buffer) => {
        if (err) reject(err);
        else resolve(buffer.toString('base64'));
      });
    });
  }
  
  async decompress(compressed) {
    const zlib = require('zlib');
    return new Promise((resolve, reject) => {
      const buffer = Buffer.from(compressed, 'base64');
      zlib.inflate(buffer, (err, result) => {
        if (err) reject(err);
        else resolve(result.toString());
      });
    });
  }
  
  // Cache statistics
  async getStats() {
    const pattern = `${this.cacheName}:*`;
    let cursor = '0';
    let totalKeys = 0;
    let totalMemory = 0;
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      totalKeys += keys.length;
      
      // Get memory usage for each key
      if (keys.length > 0) {
        const memoryPipeline = this.redis.pipeline();
        keys.forEach(key => memoryPipeline.memory('USAGE', key));
        
        const results = await memoryPipeline.exec();
        results.forEach(([error, memory]) => {
          if (!error && memory) {
            totalMemory += parseInt(memory);
          }
        });
      }
    } while (cursor !== '0');
    
    return {
      totalKeys,
      totalMemory: `${(totalMemory / 1024 / 1024).toFixed(2)} MB`,
      hitRate: await this.calculateHitRate()
    };
  }
  
  async calculateHitRate() {
    const hits = await this.redis.get(`${this.cacheName}:stats:hits`) || 0;
    const misses = await this.redis.get(`${this.cacheName}:stats:misses`) || 0;
    const total = parseInt(hits) + parseInt(misses);
    
    return total > 0 ? (parseInt(hits) / total * 100).toFixed(2) + '%' : '0%';
  }
  
  async incrementHit() {
    await this.redis.incr(`${this.cacheName}:stats:hits`);
  }
  
  async incrementMiss() {
    await this.redis.incr(`${this.cacheName}:stats:misses`);
  }
}
```

### Cache Performance Optimization

```javascript
class CacheOptimizer {
  constructor(redisClient) {
    this.redis = redisClient;
    this.metrics = {
      hitRate: 0,
      avgResponseTime: 0,
      evictionCount: 0
    };
  }
  
  // Predictive caching based on access patterns
  async predictiveCache(key, fetchFn, ttl, relatedKeys = []) {
    const cacheKey = `cache:${key}`;
    
    // Get cache and track access
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      // Track hit
      await this.trackAccess(key);
      
      // Pre-fetch related items
      this.prefetchRelated(relatedKeys).catch(console.error);
      
      return JSON.parse(cached);
    }
    
    // Track miss
    await this.trackMiss(key);
    
    const data = await fetchFn();
    
    if (data) {
      await this.redis.setex(cacheKey, ttl, JSON.stringify(data));
    }
    
    return data;
  }
  
  async trackAccess(key) {
    const pipeline = this.redis.pipeline();
    
    // Increment access count
    pipeline.zincrby('cache:access:frequency', 1, key);
    
    // Update last accessed time
    pipeline.zadd('cache:access:recent', Date.now(), key);
    
    // Trim sorted sets to prevent unbounded growth
    pipeline.zremrangebyrank('cache:access:frequency', 0, -1000); // Keep top 1000
    pipeline.zremrangebyrank('cache:access:recent', 0, -1000);
    
    await pipeline.exec();
  }
  
  async trackMiss(key) {
    await this.redis.zincrby('cache:miss:frequency', 1, key);
  }
  
  async prefetchRelated(relatedKeys) {
    const frequentlyAccessed = await this.getFrequentlyAccessedKeys(10);
    
    const keysToPrefetch = [...relatedKeys, ...frequentlyAccessed]
      .slice(0, 5); // Prefetch up to 5 keys
    
    for (const key of keysToPrefetch) {
      this.prefetchKey(key).catch(console.error);
    }
  }
  
  async getFrequentlyAccessedKeys(limit = 10) {
    return this.redis.zrevrange('cache:access:frequency', 0, limit - 1);
  }
  
  async prefetchKey(key) {
    // Check if already cached
    const cached = await this.redis.get(`cache:${key}`);
    
    if (cached) {
      return; // Already cached
    }
    
    // Fetch and cache in background
    // Implementation depends on your data fetching logic
    console.log(`Prefetching: ${key}`);
  }
  
  // Adaptive TTL based on access patterns
  async getWithAdaptiveTTL(key, fetchFn, baseTTL = 300) {
    const cacheKey = `cache:${key}`;
    const accessKey = `cache:access:${key}`;
    
    // Get current access count
    const accessCount = await this.redis.get(accessKey) || 0;
    
    // Calculate adaptive TTL (more accesses = longer TTL)
    const adaptiveTTL = baseTTL * (1 + Math.log(parseInt(accessCount) + 1));
    
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      // Increment access count
      await this.redis.incr(accessKey);
      return JSON.parse(cached);
    }
    
    const data = await fetchFn();
    
    if (data) {
      // Store with adaptive TTL
      await this.redis.setex(cacheKey, Math.min(adaptiveTTL, 3600), JSON.stringify(data));
      
      // Initialize access count
      await this.redis.setex(accessKey, 86400, '1'); // 24 hours
    }
    
    return data;
  }
  
  // Cache warming based on predictive analytics
  async warmCachePredictively() {
    console.log('Starting predictive cache warming...');
    
    // Get frequently accessed items
    const frequentItems = await this.getFrequentlyAccessedKeys(50);
    
    // Get items with recent misses
    const missedItems = await this.redis.zrevrange('cache:miss:frequency', 0, 49);
    
    // Combine and deduplicate
    const itemsToWarm = [...new Set([...frequentItems, ...missedItems])].slice(0, 50);
    
    const warmPromises = itemsToWarm.map(async key => {
      try {
        await this.warmItem(key);
      } catch (error) {
        console.error(`Failed to warm item ${key}:`, error);
      }
    });
    
    await Promise.all(warmPromises);
    console.log('Predictive cache warming completed');
  }
  
  async warmItem(key) {
    // Implementation depends on your data fetching logic
    console.log(`Warming item: ${key}`);
    
    // Simulated fetch
    const data = { id: key, warmedAt: new Date().toISOString() };
    
    // Cache with extended TTL for warmed items
    await this.redis.setex(`cache:${key}`, 7200, JSON.stringify(data));
  }
  
  // Monitor and optimize cache performance
  async monitorAndOptimize() {
    const stats = await this.getCacheStats();
    
    console.log('Cache Performance Stats:', {
      hitRate: stats.hitRate,
      totalKeys: stats.totalKeys,
      memoryUsage: stats.memoryUsage,
      evictionRate: stats.evictionRate
    });
    
    // Optimize based on stats
    if (stats.hitRate < 70) {
      console.log('Low hit rate detected. Increasing cache size...');
      await this.optimizeCacheSize();
    }
    
    if (stats.evictionRate > 10) {
      console.log('High eviction rate detected. Adjusting TTLs...');
      await this.adjustTTLs();
    }
  }
  
  async getCacheStats() {
    const info = await this.redis.info('stats');
    const lines = info.split('\n');
    
    const stats = {
      hitRate: 0,
      totalKeys: 0,
      memoryUsage: 0,
      evictionRate: 0
    };
    
    lines.forEach(line => {
      if (line.startsWith('keyspace_hits:')) {
        const hits = parseInt(line.split(':')[1]);
        const misses = parseInt(lines.find(l => l.startsWith('keyspace_misses:')).split(':')[1]);
        stats.hitRate = hits + misses > 0 ? (hits / (hits + misses) * 100).toFixed(2) : 0;
      } else if (line.startsWith('db0:keys=')) {
        stats.totalKeys = parseInt(line.split('=')[1].split(',')[0]);
      } else if (line.startsWith('used_memory:')) {
        stats.memoryUsage = line.split(':')[1];
      } else if (line.startsWith('evicted_keys:')) {
        stats.evictionRate = parseInt(line.split(':')[1]);
      }
    });
    
    return stats;
  }
  
  async optimizeCacheSize() {
    // Implementation depends on your Redis configuration
    // This could involve adjusting maxmemory policy or increasing memory
    console.log('Optimizing cache size...');
  }
  
  async adjustTTLs() {
    // Adjust TTLs based on access patterns
    const frequentKeys = await this.getFrequentlyAccessedKeys(100);
    
    const pipeline = this.redis.pipeline();
    
    frequentKeys.forEach(key => {
      // Increase TTL for frequently accessed items
      pipeline.expire(`cache:${key}`, 7200); // 2 hours
    });
    
    await pipeline.exec();
    console.log(`Adjusted TTLs for ${frequentKeys.length} frequent items`);
  }
}
```

---

## Rate Limiting

### Rate Limiting Algorithms

#### 1. Fixed Window Counter

```javascript
class FixedWindowRateLimiter {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.windowSize = options.windowSize || 60; // seconds
    this.maxRequests = options.maxRequests || 100;
    this.prefix = options.prefix || 'rate-limit:';
  }
  
  async isRateLimited(key, increment = true) {
    const windowKey = `${this.prefix}${key}:${Math.floor(Date.now() / 1000 / this.windowSize)}`;
    
    try {
      if (increment) {
        // Increment counter and get current value
        const current = await this.redis.incr(windowKey);
        
        // Set expiry on first increment
        if (current === 1) {
          await this.redis.expire(windowKey, this.windowSize);
        }
        
        return current > this.maxRequests;
      } else {
        // Just check current count
        const current = await this.redis.get(windowKey);
        return parseInt(current || 0) >= this.maxRequests;
      }
    } catch (error) {
      console.error('Rate limit error:', error);
      return false; // Fail open on error
    }
  }
  
  async getRemainingRequests(key) {
    const windowKey = `${this.prefix}${key}:${Math.floor(Date.now() / 1000 / this.windowSize)}`;
    const current = await this.redis.get(windowKey) || 0;
    return Math.max(0, this.maxRequests - parseInt(current));
  }
  
  async reset(key) {
    const windowKey = `${this.prefix}${key}:${Math.floor(Date.now() / 1000 / this.windowSize)}`;
    await this.redis.del(windowKey);
  }
}
```

#### 2. Sliding Window Log

```javascript
class SlidingWindowLogRateLimiter {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.windowSize = options.windowSize || 60; // seconds
    this.maxRequests = options.maxRequests || 100;
    this.prefix = options.prefix || 'rate-limit:sliding:';
  }
  
  async isRateLimited(key) {
    const now = Date.now();
    const windowStart = now - (this.windowSize * 1000);
    const redisKey = `${this.prefix}${key}`;
    
    const pipeline = this.redis.pipeline();
    
    // Add current request timestamp
    pipeline.zadd(redisKey, now, `${now}-${Math.random()}`);
    
    // Remove old requests outside window
    pipeline.zremrangebyscore(redisKey, 0, windowStart);
    
    // Count requests in window
    pipeline.zcard(redisKey);
    
    // Set expiry on the key
    pipeline.expire(redisKey, this.windowSize);
    
    const results = await pipeline.exec();
    const requestCount = results[2][1]; // zcard result
    
    return requestCount > this.maxRequests;
  }
  
  async getWindowStats(key) {
    const now = Date.now();
    const windowStart = now - (this.windowSize * 1000);
    const redisKey = `${this.prefix}${key}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.zremrangebyscore(redisKey, 0, windowStart);
    pipeline.zcard(redisKey);
    pipeline.zrange(redisKey, 0, -1, 'WITHSCORES');
    
    const results = await pipeline.exec();
    const requestCount = results[1][1];
    const requests = results[2][1];
    
    return {
      count: requestCount,
      remaining: Math.max(0, this.maxRequests - requestCount),
      windowStart: new Date(windowStart),
      windowEnd: new Date(now),
      requests: this.parseRequests(requests)
    };
  }
  
  parseRequests(requestsArray) {
    const requests = [];
    for (let i = 0; i < requestsArray.length; i += 2) {
      requests.push({
        timestamp: new Date(parseInt(requestsArray[i + 1])),
        id: requestsArray[i]
      });
    }
    return requests;
  }
}
```

#### 3. Token Bucket Algorithm

```javascript
class TokenBucketRateLimiter {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.capacity = options.capacity || 100;
    this.refillRate = options.refillRate || 10; // tokens per second
    this.prefix = options.prefix || 'rate-limit:token-bucket:';
  }
  
  async isRateLimited(key, tokens = 1) {
    const bucketKey = `${this.prefix}${key}`;
    const now = Date.now() / 1000; // Current time in seconds
    
    const pipeline = this.redis.pipeline();
    
    // Get current bucket state
    pipeline.hgetall(bucketKey);
    
    const results = await pipeline.exec();
    const bucket = results[0][1] || { tokens: this.capacity, lastRefill: now };
    
    // Calculate refill
    const elapsed = now - parseFloat(bucket.lastRefill || now);
    const refillAmount = elapsed * this.refillRate;
    const currentTokens = Math.min(
      this.capacity,
      parseFloat(bucket.tokens || this.capacity) + refillAmount
    );
    
    if (currentTokens < tokens) {
      // Not enough tokens
      return {
        limited: true,
        retryAfter: Math.ceil((tokens - currentTokens) / this.refillRate),
        remainingTokens: currentTokens
      };
    }
    
    // Consume tokens
    const newTokens = currentTokens - tokens;
    
    const updatePipeline = this.redis.pipeline();
    updatePipeline.hset(bucketKey, {
      tokens: newTokens,
      lastRefill: now
    });
    updatePipeline.expire(bucketKey, Math.ceil(this.capacity / this.refillRate) * 2);
    
    await updatePipeline.exec();
    
    return {
      limited: false,
      remainingTokens: newTokens,
      retryAfter: 0
    };
  }
  
  async getBucketStatus(key) {
    const bucketKey = `${this.prefix}${key}`;
    const now = Date.now() / 1000;
    
    const bucket = await this.redis.hgetall(bucketKey);
    
    if (!bucket || !bucket.tokens) {
      return {
        tokens: this.capacity,
        capacity: this.capacity,
        refillRate: this.refillRate,
        full: true
      };
    }
    
    // Calculate current tokens with refill
    const elapsed = now - parseFloat(bucket.lastRefill || now);
    const refillAmount = elapsed * this.refillRate;
    const currentTokens = Math.min(
      this.capacity,
      parseFloat(bucket.tokens) + refillAmount
    );
    
    return {
      tokens: currentTokens,
      capacity: this.capacity,
      refillRate: this.refillRate,
      full: currentTokens >= this.capacity,
      refillIn: currentTokens >= this.capacity ? 0 : 
                (this.capacity - currentTokens) / this.refillRate
    };
  }
  
  async refillTokens(key, amount) {
    const bucketKey = `${this.prefix}${key}`;
    const now = Date.now() / 1000;
    
    const pipeline = this.redis.pipeline();
    pipeline.hincrbyfloat(bucketKey, 'tokens', amount);
    pipeline.hset(bucketKey, 'lastRefill', now);
    
    await pipeline.exec();
  }
}
```

#### 4. Leaky Bucket Algorithm

```javascript
class LeakyBucketRateLimiter {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.capacity = options.capacity || 100;
    this.leakRate = options.leakRate || 10; // requests per second
    this.prefix = options.prefix || 'rate-limit:leaky-bucket:';
  }
  
  async isRateLimited(key) {
    const bucketKey = `${this.prefix}${key}`;
    const now = Date.now();
    
    const pipeline = this.redis.pipeline();
    
    // Get bucket state
    pipeline.hgetall(bucketKey);
    
    const results = await pipeline.exec();
    const bucket = results[0][1] || { 
      volume: 0, 
      lastLeak: now,
      lastRequest: now 
    };
    
    // Calculate leak
    const elapsed = (now - parseFloat(bucket.lastLeak)) / 1000; // seconds
    const leakAmount = elapsed * this.leakRate;
    const currentVolume = Math.max(
      0,
      parseFloat(bucket.volume || 0) - leakAmount
    );
    
    if (currentVolume >= this.capacity) {
      // Bucket overflow
      return {
        limited: true,
        retryAfter: Math.ceil((currentVolume - this.capacity) / this.leakRate),
        queueSize: Math.floor(currentVolume)
      };
    }
    
    // Add request to bucket
    const newVolume = currentVolume + 1;
    const processingTime = newVolume / this.leakRate;
    
    const updatePipeline = this.redis.pipeline();
    updatePipeline.hset(bucketKey, {
      volume: newVolume,
      lastLeak: now,
      lastRequest: now
    });
    updatePipeline.expire(bucketKey, Math.ceil(this.capacity / this.leakRate) * 2);
    
    await updatePipeline.exec();
    
    return {
      limited: false,
      queueSize: Math.floor(newVolume),
      estimatedWait: processingTime
    };
  }
  
  async processRequests(key, processFn) {
    const bucketKey = `${this.prefix}${key}`;
    
    // Use Lua script for atomic operations
    const luaScript = `
      local bucketKey = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local leakRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      
      local bucket = redis.call('HGETALL', bucketKey)
      local bucketMap = {}
      
      for i = 1, #bucket, 2 do
        bucketMap[bucket[i]] = bucket[i + 1]
      end
      
      local volume = tonumber(bucketMap['volume'] or 0)
      local lastLeak = tonumber(bucketMap['lastLeak'] or now)
      
      -- Calculate leak
      local elapsed = (now - lastLeak) / 1000
      local leakAmount = elapsed * leakRate
      volume = math.max(0, volume - leakAmount)
      
      if volume >= capacity then
        return {0, volume} -- Rate limited
      end
      
      -- Add request
      volume = volume + 1
      
      redis.call('HSET', bucketKey, 'volume', volume, 'lastLeak', now, 'lastRequest', now)
      redis.call('EXPIRE', bucketKey, math.ceil(capacity / leakRate) * 2)
      
      return {1, volume}
    `;
    
    const result = await this.redis.eval(
      luaScript,
      1,
      bucketKey,
      this.capacity,
      this.leakRate,
      Date.now()
    );
    
    const [allowed, volume] = result;
    
    if (allowed === 1) {
      // Process request
      await processFn();
      return { success: true, queuePosition: Math.floor(volume) };
    } else {
      return { 
        success: false, 
        retryAfter: Math.ceil((volume - this.capacity) / this.leakRate) 
      };
    }
  }
}
```

### Distributed Rate Limiting

```javascript
class DistributedRateLimiter {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.windowSize = options.windowSize || 60;
    this.maxRequests = options.maxRequests || 100;
    this.prefix = options.prefix || 'distributed-rate-limit:';
    this.syncInterval = options.syncInterval || 1000; // ms
    this.localCache = new Map();
    this.syncInProgress = false;
    
    // Start background sync
    this.startSync();
  }
  
  // Distributed sliding window with local caching
  async isRateLimited(key, cost = 1) {
    const now = Date.now();
    const windowStart = now - (this.windowSize * 1000);
    
    // Check local cache first
    const localKey = `${this.prefix}${key}`;
    if (this.localCache.has(localKey)) {
      const { count, timestamp } = this.localCache.get(localKey);
      
      if (timestamp > windowStart) {
        const localLimited = count + cost > this.maxRequests;
        
        if (!localLimited) {
          // Update local cache
          this.localCache.set(localKey, {
            count: count + cost,
            timestamp: now
          });
          return false;
        }
      }
    }
    
    // Check Redis
    const redisKey = `${this.prefix}${key}`;
    const limited = await this.checkRedisWindow(redisKey, cost, windowStart);
    
    if (!limited) {
      // Update local cache
      this.localCache.set(localKey, {
        count: cost,
        timestamp: now
      });
    }
    
    return limited;
  }
  
  async checkRedisWindow(key, cost, windowStart) {
    const pipeline = this.redis.pipeline();
    
    // Add current request
    pipeline.zadd(key, Date.now(), `${Date.now()}-${Math.random()}`);
    
    // Remove old requests
    pipeline.zremrangebyscore(key, 0, windowStart);
    
    // Get count
    pipeline.zcard(key);
    
    // Set expiry
    pipeline.expire(key, this.windowSize);
    
    const results = await pipeline.exec();
    const count = results[2][1];
    
    return count > this.maxRequests;
  }
  
  // Start background sync of local cache to Redis
  startSync() {
    setInterval(() => {
      this.syncLocalToRedis();
    }, this.syncInterval);
  }
  
  async syncLocalToRedis() {
    if (this.syncInProgress || this.localCache.size === 0) {
      return;
    }
    
    this.syncInProgress = true;
    
    try {
      const pipeline = this.redis.pipeline();
      const now = Date.now();
      const windowStart = now - (this.windowSize * 1000);
      
      for (const [key, { count, timestamp }] of this.localCache) {
        if (timestamp > windowStart) {
          // Add to Redis sorted set
          pipeline.zadd(key, timestamp, `${timestamp}-local-${Math.random()}`);
          pipeline.expire(key, this.windowSize);
        }
      }
      
      await pipeline.exec();
      
      // Clear local cache after sync
      this.localCache.clear();
      
    } catch (error) {
      console.error('Sync error:', error);
    } finally {
      this.syncInProgress = false;
    }
  }
  
  // Hierarchical rate limiting (user -> IP -> global)
  async hierarchicalRateLimit(userId, ip, endpoint, cost = 1) {
    const limits = {
      user: { window: 60, max: 100 },      // 100 requests per minute per user
      ip: { window: 60, max: 1000 },       // 1000 requests per minute per IP
      endpoint: { window: 60, max: 10000 } // 10000 requests per minute per endpoint
    };
    
    const checks = [
      this.checkLimit(`user:${userId}`, limits.user, cost),
      this.checkLimit(`ip:${ip}`, limits.ip, cost),
      this.checkLimit(`endpoint:${endpoint}`, limits.endpoint, cost)
    ];
    
    const results = await Promise.all(checks);
    
    const limitedResult = results.find(r => r.limited);
    
    if (limitedResult) {
      return {
        limited: true,
        level: limitedResult.level,
        retryAfter: limitedResult.retryAfter,
        remaining: limitedResult.remaining
      };
    }
    
    return { limited: false };
  }
  
  async checkLimit(key, limit, cost) {
    const windowKey = `${this.prefix}${key}:${Math.floor(Date.now() / 1000 / limit.window)}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.incrby(windowKey, cost);
    pipeline.expire(windowKey, limit.window);
    pipeline.get(windowKey);
    
    const results = await pipeline.exec();
    const current = parseInt(results[2][1] || 0);
    
    return {
      level: key.split(':')[0],
      limited: current > limit.max,
      remaining: Math.max(0, limit.max - current),
      retryAfter: limit.window - (Date.now() / 1000 % limit.window)
    };
  }
  
  // Rate limiting with burst allowance
  async rateLimitWithBurst(key, sustainedLimit, burstLimit, windowSize = 60) {
    const now = Math.floor(Date.now() / 1000);
    const burstKey = `${this.prefix}burst:${key}`;
    const sustainedKey = `${this.prefix}sustained:${key}`;
    
    // Check burst limit
    const burstCount = await this.redis.get(burstKey) || 0;
    
    if (parseInt(burstCount) >= burstLimit) {
      // Check sustained limit
      const sustainedCount = await this.redis.get(sustainedKey) || 0;
      
      if (parseInt(sustainedCount) >= sustainedLimit) {
        return {
          limited: true,
          type: 'sustained',
          retryAfter: windowSize - (now % windowSize)
        };
      }
      
      // Within sustained limit, increment sustained counter
      const pipeline = this.redis.pipeline();
      pipeline.incr(sustainedKey);
      if (parseInt(sustainedCount) === 0) {
        pipeline.expire(sustainedKey, windowSize);
      }
      await pipeline.exec();
    } else {
      // Within burst limit, increment burst counter
      const pipeline = this.redis.pipeline();
      pipeline.incr(burstKey);
      if (parseInt(burstCount) === 0) {
        pipeline.expire(burstKey, windowSize);
      }
      await pipeline.exec();
    }
    
    return { limited: false };
  }
  
  // Dynamic rate limiting based on system load
  async adaptiveRateLimit(key, baseLimit, options = {}) {
    const { minLimit = 10, maxLimit = 1000, loadThreshold = 0.8 } = options;
    
    // Get system load from Redis
    const load = await this.getSystemLoad();
    
    // Calculate dynamic limit based on load
    let dynamicLimit = baseLimit;
    
    if (load > loadThreshold) {
      // Reduce limit under high load
      dynamicLimit = Math.max(
        minLimit,
        Math.floor(baseLimit * (1 - (load - loadThreshold) / (1 - loadThreshold)))
      );
    } else {
      // Increase limit under low load
      dynamicLimit = Math.min(
        maxLimit,
        Math.floor(baseLimit * (1 + (loadThreshold - load) / loadThreshold))
      );
    }
    
    // Apply rate limiting with dynamic limit
    const windowKey = `${this.prefix}adaptive:${key}:${Math.floor(Date.now() / 1000 / 60)}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.incr(windowKey);
    pipeline.expire(windowKey, 60);
    pipeline.get(windowKey);
    
    const results = await pipeline.exec();
    const current = parseInt(results[2][1] || 0);
    
    return {
      limited: current > dynamicLimit,
      limit: dynamicLimit,
      current: current,
      remaining: Math.max(0, dynamicLimit - current),
      load: load
    };
  }
  
  async getSystemLoad() {
    try {
      // Get Redis memory usage as proxy for system load
      const info = await this.redis.info('memory');
      const usedMemory = parseInt(info.match(/used_memory:(\d+)/)[1]);
      const maxMemory = parseInt(info.match(/maxmemory:(\d+)/)[1]) || usedMemory * 2;
      
      return usedMemory / maxMemory;
    } catch (error) {
      return 0.5; // Default medium load
    }
  }
}
```

### Advanced Rate Limiting Patterns

```javascript
class AdvancedRateLimiting {
  constructor(redisClient) {
    this.redis = redisClient;
    this.prefix = 'advanced-rate-limit:';
  }
  
  // Rate limiting with cost-based tokens
  async costBasedRateLimit(key, cost, options = {}) {
    const {
      tokensPerSecond = 10,
      maxTokens = 100,
      burstTokens = 50
    } = options;
    
    const bucketKey = `${this.prefix}cost:${key}`;
    const now = Date.now() / 1000;
    
    // Lua script for atomic operations
    const luaScript = `
      local bucketKey = KEYS[1]
      local cost = tonumber(ARGV[1])
      local tokensPerSecond = tonumber(ARGV[2])
      local maxTokens = tonumber(ARGV[3])
      local burstTokens = tonumber(ARGV[4])
      local now = tonumber(ARGV[5])
      
      local bucket = redis.call('HGETALL', bucketKey)
      local bucketMap = {}
      
      for i = 1, #bucket, 2 do
        bucketMap[bucket[i]] = bucket[i + 1]
      end
      
      local tokens = tonumber(bucketMap['tokens'] or maxTokens)
      local lastUpdate = tonumber(bucketMap['lastUpdate'] or now)
      local burstUsed = tonumber(bucketMap['burstUsed'] or 0)
      
      -- Refill tokens
      local elapsed = now - lastUpdate
      local refill = elapsed * tokensPerSecond
      tokens = math.min(maxTokens, tokens + refill)
      
      -- Check burst allowance
      local availableBurst = burstTokens - burstUsed
      local totalAvailable = tokens + math.max(0, availableBurst)
      
      if totalAvailable < cost then
        -- Not enough tokens
        local needed = cost - totalAvailable
        local waitTime = needed / tokensPerSecond
        
        return {0, math.floor(waitTime), tokens, burstUsed}
      end
      
      -- Consume tokens
      local remainingCost = cost
      
      -- First use regular tokens
      local tokensToUse = math.min(tokens, remainingCost)
      tokens = tokens - tokensToUse
      remainingCost = remainingCost - tokensToUse
      
      -- Then use burst tokens if needed
      if remainingCost > 0 then
        burstUsed = burstUsed + remainingCost
        remainingCost = 0
      end
      
      -- Update bucket
      redis.call('HSET', bucketKey, 
        'tokens', tokens,
        'lastUpdate', now,
        'burstUsed', burstUsed
      )
      
      -- Set expiry
      local expiry = math.ceil(maxTokens / tokensPerSecond) * 2
      redis.call('EXPIRE', bucketKey, expiry)
      
      return {1, 0, tokens, burstUsed}
    `;
    
    const result = await this.redis.eval(
      luaScript,
      1,
      bucketKey,
      cost,
      tokensPerSecond,
      maxTokens,
      burstTokens,
      now
    );
    
    const [allowed, waitTime, tokens, burstUsed] = result;
    
    return {
      allowed: allowed === 1,
      waitTime,
      tokens,
      burstUsed,
      burstRemaining: burstTokens - burstUsed
    };
  }
  
  // Rate limiting with prioritization
  async prioritizedRateLimit(key, priority, options = {}) {
    const { 
      highLimit = 1000,
      mediumLimit = 100,
      lowLimit = 10,
      window = 60
    } = options;
    
    const limits = {
      high: highLimit,
      medium: mediumLimit,
      low: lowLimit
    };
    
    const limit = limits[priority] || lowLimit;
    const priorityKey = `${this.prefix}priority:${key}:${priority}`;
    const windowKey = `${priorityKey}:${Math.floor(Date.now() / 1000 / window)}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.incr(windowKey);
    pipeline.expire(windowKey, window);
    pipeline.get(windowKey);
    
    const results = await pipeline.exec();
    const current = parseInt(results[2][1] || 0);
    
    // Check if we should throttle lower priorities
    if (priority === 'low' && current > limit * 0.8) {
      // Check higher priority usage
      const highUsage = await this.getPriorityUsage(key, 'high');
      const mediumUsage = await this.getPriorityUsage(key, 'medium');
      
      if (highUsage > highLimit * 0.5 || mediumUsage > mediumLimit * 0.5) {
        // Throttle low priority
        return {
          allowed: false,
          reason: 'higher_priority_traffic',
          priority,
          current,
          limit
        };
      }
    }
    
    return {
      allowed: current <= limit,
      priority,
      current,
      limit,
      remaining: Math.max(0, limit - current)
    };
  }
  
  async getPriorityUsage(key, priority) {
    const priorityKey = `${this.prefix}priority:${key}:${priority}`;
    const windowKey = `${priorityKey}:${Math.floor(Date.now() / 1000 / 60)}`;
    const usage = await this.redis.get(windowKey) || 0;
    return parseInt(usage);
  }
  
  // Rate limiting with geographic distribution
  async geographicRateLimit(ip, country, options = {}) {
    const {
      globalLimit = 10000,
      countryLimits = {
        'US': 5000,
        'EU': 3000,
        'CN': 2000,
        'default': 1000
      }
    } = options;
    
    const countryLimit = countryLimits[country] || countryLimits.default;
    
    // Global check
    const globalKey = `${this.prefix}geo:global:${Math.floor(Date.now() / 1000 / 60)}`;
    const globalCount = await this.redis.incr(globalKey);
    if (globalCount === 1) {
      await this.redis.expire(globalKey, 60);
    }
    
    if (globalCount > globalLimit) {
      return {
        allowed: false,
        level: 'global',
        limit: globalLimit,
        current: globalCount
      };
    }
    
    // Country check
    const countryKey = `${this.prefix}geo:${country}:${Math.floor(Date.now() / 1000 / 60)}`;
    const countryCount = await this.redis.incr(countryKey);
    if (countryCount === 1) {
      await this.redis.expire(countryKey, 60);
    }
    
    if (countryCount > countryLimit) {
      return {
        allowed: false,
        level: 'country',
        limit: countryLimit,
        current: countryCount,
        country
      };
    }
    
    // IP check (more restrictive)
    const ipKey = `${this.prefix}geo:ip:${ip}:${Math.floor(Date.now() / 1000 / 60)}`;
    const ipCount = await this.redis.incr(ipKey);
    if (ipCount === 1) {
      await this.redis.expire(ipKey, 60);
    }
    
    // Dynamic IP limit based on country
    const ipLimit = Math.floor(countryLimit / 100); // 1% of country limit
    
    if (ipCount > ipLimit) {
      return {
        allowed: false,
        level: 'ip',
        limit: ipLimit,
        current: ipCount,
        ip
      };
    }
    
    return {
      allowed: true,
      levels: {
        global: { current: globalCount, limit: globalLimit },
        country: { current: countryCount, limit: countryLimit },
        ip: { current: ipCount, limit: ipLimit }
      }
    };
  }
  
  // Rate limiting for API endpoints with dependency tracking
  async endpointRateLimit(userId, endpoint, dependencies = []) {
    const endpointKey = `${this.prefix}endpoint:${endpoint}:${Math.floor(Date.now() / 1000 / 60)}`;
    const userKey = `${this.prefix}user:${userId}:${Math.floor(Date.now() / 1000 / 60)}`;
    
    // Check if any dependency is rate limited
    for (const dependency of dependencies) {
      const depKey = `${this.prefix}dependency:${dependency}:${Math.floor(Date.now() / 1000 / 60)}`;
      const depCount = await this.redis.get(depKey) || 0;
      
      if (parseInt(depCount) > 100) { // Dependency limit
        return {
          allowed: false,
          reason: 'dependency_rate_limited',
          dependency,
          retryAfter: 60 - (Date.now() / 1000 % 60)
        };
      }
    }
    
    // Check endpoint limit
    const endpointCount = await this.redis.incr(endpointKey);
    if (endpointCount === 1) {
      await this.redis.expire(endpointKey, 60);
    }
    
    if (endpointCount > 1000) { // Endpoint limit
      return {
        allowed: false,
        reason: 'endpoint_rate_limited',
        endpoint,
        current: endpointCount,
        limit: 1000
      };
    }
    
    // Check user limit
    const userCount = await this.redis.incr(userKey);
    if (userCount === 1) {
      await this.redis.expire(userKey, 60);
    }
    
    if (userCount > 100) { // User limit
      return {
        allowed: false,
        reason: 'user_rate_limited',
        userId,
        current: userCount,
        limit: 100
      };
    }
    
    // Increment dependency counters
    const pipeline = this.redis.pipeline();
    dependencies.forEach(dep => {
      const depKey = `${this.prefix}dependency:${dep}:${Math.floor(Date.now() / 1000 / 60)}`;
      pipeline.incr(depKey);
      pipeline.expire(depKey, 60);
    });
    
    await pipeline.exec();
    
    return {
      allowed: true,
      counts: {
        endpoint: endpointCount,
        user: userCount
      }
    };
  }
  
  // Rate limiting with circuit breaker pattern
  class CircuitBreakerRateLimiter {
    constructor(redisClient, options = {}) {
      this.redis = redisClient;
      this.prefix = 'circuit-breaker:';
      this.failureThreshold = options.failureThreshold || 5;
      this.resetTimeout = options.resetTimeout || 60000; // 1 minute
      this.halfOpenMaxRequests = options.halfOpenMaxRequests || 1;
    }
    
    async execute(key, operation) {
      const state = await this.getState(key);
      
      switch (state) {
        case 'open':
          throw new Error(`Circuit breaker open for ${key}`);
          
        case 'half-open':
          const halfOpenCount = await this.redis.incr(`${this.prefix}${key}:half-open`);
          if (halfOpenCount > this.halfOpenMaxRequests) {
            throw new Error(`Circuit breaker half-open limit reached for ${key}`);
          }
          break;
      }
      
      try {
        const result = await operation();
        await this.recordSuccess(key);
        return result;
      } catch (error) {
        await this.recordFailure(key);
        throw error;
      }
    }
    
    async getState(key) {
      const circuitKey = `${this.prefix}${key}`;
      const state = await this.redis.get(`${circuitKey}:state`);
      
      if (state === 'open') {
        const openedAt = await this.redis.get(`${circuitKey}:opened-at`);
        if (Date.now() - parseInt(openedAt) > this.resetTimeout) {
          await this.setHalfOpen(key);
          return 'half-open';
        }
        return 'open';
      }
      
      return state || 'closed';
    }
    
    async recordSuccess(key) {
      const circuitKey = `${this.prefix}${key}`;
      const pipeline = this.redis.pipeline();
      
      // Reset failure count
      pipeline.set(`${circuitKey}:failures`, 0);
      
      // Set state to closed
      pipeline.set(`${circuitKey}:state`, 'closed');
      
      // Reset half-open counter
      pipeline.del(`${circuitKey}:half-open`);
      
      await pipeline.exec();
    }
    
    async recordFailure(key) {
      const circuitKey = `${this.prefix}${key}`;
      const failures = await this.redis.incr(`${circuitKey}:failures`);
      
      if (failures >= this.failureThreshold) {
        await this.redis.set(`${circuitKey}:state`, 'open');
        await this.redis.set(`${circuitKey}:opened-at`, Date.now());
      }
    }
    
    async setHalfOpen(key) {
      const circuitKey = `${this.prefix}${key}`;
      await this.redis.set(`${circuitKey}:state`, 'half-open');
    }
    
    async getMetrics(key) {
      const circuitKey = `${this.prefix}${key}`;
      const pipeline = this.redis.pipeline();
      
      pipeline.get(`${circuitKey}:state`);
      pipeline.get(`${circuitKey}:failures`);
      pipeline.get(`${circuitKey}:opened-at`);
      pipeline.get(`${circuitKey}:half-open`);
      
      const results = await pipeline.exec();
      
      return {
        state: results[0][1] || 'closed',
        failures: parseInt(results[1][1] || 0),
        openedAt: results[2][1] ? new Date(parseInt(results[2][1])) : null,
        halfOpenCount: parseInt(results[3][1] || 0)
      };
    }
  }
}
```

---

## Blacklisting Tokens

### JWT Token Blacklisting

```javascript
class JWTTokenManager {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.prefix = options.prefix || 'jwt:';
    this.jwtSecret = options.jwtSecret || process.env.JWT_SECRET;
    this.tokenExpiry = options.tokenExpiry || '7d';
    this.refreshTokenExpiry = options.refreshTokenExpiry || '30d';
  }
  
  // Generate JWT token
  generateToken(user, options = {}) {
    const jwt = require('jsonwebtoken');
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      tokenId: this.generateTokenId(),
      ...options.extraPayload
    };
    
    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: options.expiresIn || this.tokenExpiry,
      issuer: options.issuer || 'your-app',
      audience: options.audience || 'your-app-users'
    });
  }
  
  generateTokenId() {
    return require('crypto').randomBytes(16).toString('hex');
  }
  
  // Verify and validate token
  async verifyToken(token) {
    const jwt = require('jsonwebtoken');
    
    try {
      // Verify JWT signature and expiry
      const decoded = jwt.verify(token, this.jwtSecret, {
        issuer: 'your-app',
        audience: 'your-app-users'
      });
      
      // Check if token is blacklisted
      const isBlacklisted = await this.isTokenBlacklisted(decoded.tokenId);
      
      if (isBlacklisted) {
        throw new Error('Token has been revoked');
      }
      
      // Check if user is still active
      const userActive = await this.isUserActive(decoded.userId);
      
      if (!userActive) {
        await this.blacklistToken(token);
        throw new Error('User account is inactive');
      }
      
      return {
        valid: true,
        decoded,
        requiresRefresh: this.shouldRefreshToken(decoded)
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
  
  async isTokenBlacklisted(tokenId) {
    const blacklistKey = `${this.prefix}blacklist:${tokenId}`;
    const exists = await this.redis.exists(blacklistKey);
    return exists === 1;
  }
  
  async isUserActive(userId) {
    // Check if user exists and is active
    const userKey = `${this.prefix}user:${userId}:status`;
    const status = await this.redis.get(userKey);
    
    if (status === 'inactive') {
      return false;
    }
    
    // You might also want to check database
    return true;
  }
  
  shouldRefreshToken(decoded) {
    const now = Math.floor(Date.now() / 1000);
    const tokenExpiry = decoded.exp;
    const refreshThreshold = 24 * 60 * 60; // 24 hours
    
    return tokenExpiry - now < refreshThreshold;
  }
  
  // Blacklist a token
  async blacklistToken(token, reason = 'manual_revocation') {
    const jwt = require('jsonwebtoken');
    
    try {
      const decoded = jwt.decode(token);
      
      if (!decoded || !decoded.tokenId || !decoded.exp) {
        throw new Error('Invalid token');
      }
      
      const tokenId = decoded.tokenId;
      const expiresAt = decoded.exp;
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(1, expiresAt - now);
      
      const blacklistKey = `${this.prefix}blacklist:${tokenId}`;
      
      await this.redis.setex(
        blacklistKey,
        ttl,
        JSON.stringify({
          userId: decoded.userId,
          reason,
          blacklistedAt: new Date().toISOString(),
          expiresAt: new Date(expiresAt * 1000).toISOString()
        })
      );
      
      // Add to user's blacklisted tokens set
      const userBlacklistKey = `${this.prefix}user:${decoded.userId}:blacklisted`;
      await this.redis.sadd(userBlacklistKey, tokenId);
      await this.redis.expire(userBlacklistKey, ttl);
      
      console.log(`Token ${tokenId} blacklisted for user ${decoded.userId}`);
      
      return {
        success: true,
        tokenId,
        expiresIn: ttl,
        reason
      };
    } catch (error) {
      console.error('Error blacklisting token:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Blacklist all tokens for a user
  async blacklistAllUserTokens(userId, reason = 'user_logout') {
    const userTokensKey = `${this.prefix}user:${userId}:tokens`;
    const userBlacklistKey = `${this.prefix}user:${userId}:blacklisted`;
    
    // Get all active tokens for user
    const tokenIds = await this.redis.smembers(userTokensKey);
    
    if (tokenIds.length === 0) {
      return { success: true, blacklistedCount: 0 };
    }
    
    const pipeline = this.redis.pipeline();
    
    // Blacklist each token
    tokenIds.forEach(tokenId => {
      const blacklistKey = `${this.prefix}blacklist:${tokenId}`;
      pipeline.setex(
        blacklistKey,
        86400, // 24 hours default
        JSON.stringify({
          userId,
          reason,
          blacklistedAt: new Date().toISOString()
        })
      );
      
      // Add to user's blacklisted set
      pipeline.sadd(userBlacklistKey, tokenId);
    });
    
    // Clear user's active tokens
    pipeline.del(userTokensKey);
    
    await pipeline.exec();
    
    console.log(`Blacklisted ${tokenIds.length} tokens for user ${userId}`);
    
    return {
      success: true,
      blacklistedCount: tokenIds.length,
      reason
    };
  }
  
  // Store token when issued
  async storeToken(userId, token) {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(token);
    
    if (!decoded || !decoded.tokenId || !decoded.exp) {
      throw new Error('Invalid token');
    }
    
    const tokenId = decoded.tokenId;
    const expiresAt = decoded.exp;
    const now = Math.floor(Date.now() / 1000);
    const ttl = expiresAt - now;
    
    const userTokensKey = `${this.prefix}user:${userId}:tokens`;
    const tokenInfoKey = `${this.prefix}token:${tokenId}`;
    
    const pipeline = this.redis.pipeline();
    
    // Add token to user's token set
    pipeline.sadd(userTokensKey, tokenId);
    pipeline.expire(userTokensKey, ttl);
    
    // Store token info
    pipeline.setex(
      tokenInfoKey,
      ttl,
      JSON.stringify({
        userId,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        lastUsed: new Date().toISOString()
      })
    );
    
    await pipeline.exec();
    
    return tokenId;
  }
  
  // Update token last used time
  async updateTokenUsage(tokenId) {
    const tokenInfoKey = `${this.prefix}token:${tokenId}`;
    const tokenInfo = await this.redis.get(tokenInfoKey);
    
    if (tokenInfo) {
      const info = JSON.parse(tokenInfo);
      info.lastUsed = new Date().toISOString();
      
      // Get remaining TTL
      const ttl = await this.redis.ttl(tokenInfoKey);
      
      if (ttl > 0) {
        await this.redis.setex(tokenInfoKey, ttl, JSON.stringify(info));
      }
    }
  }
  
  // Get all active tokens for a user
  async getUserTokens(userId) {
    const userTokensKey = `${this.prefix}user:${userId}:tokens`;
    const tokenIds = await this.redis.smembers(userTokensKey);
    
    const tokens = [];
    const pipeline = this.redis.pipeline();
    
    tokenIds.forEach(tokenId => {
      pipeline.get(`${this.prefix}token:${tokenId}`);
    });
    
    const results = await pipeline.exec();
    
    results.forEach(([error, data], index) => {
      if (!error && data) {
        const tokenInfo = JSON.parse(data);
        tokens.push({
          tokenId: tokenIds[index],
          ...tokenInfo
        });
      }
    });
    
    return tokens;
  }
  
  // Cleanup expired tokens
  async cleanupExpiredTokens() {
    console.log('Starting token cleanup...');
    
    let cursor = '0';
    let cleanedCount = 0;
    
    do {
      // Find all token info keys
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.prefix}token:*`,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      if (keys.length > 0) {
        const pipeline = this.redis.pipeline();
        
        keys.forEach(key => {
          pipeline.ttl(key);
        });
        
        const results = await pipeline.exec();
        
        // Check each token's TTL
        const deletePipeline = this.redis.pipeline();
        
        results.forEach(([error, ttl], index) => {
          if (!error && ttl <= 0) {
            const tokenId = keys[index].replace(`${this.prefix}token:`, '');
            
            // Delete token info
            deletePipeline.del(keys[index]);
            
            // Remove from user's token set
            // Need to find which user this token belongs to
            // This would be more efficient with a reverse index
          }
        });
        
        if (deletePipeline.length > 0) {
          await deletePipeline.exec();
          cleanedCount += deletePipeline.length / 2; // Divide by 2 as we have two operations per key
        }
      }
    } while (cursor !== '0');
    
    console.log(`Cleaned up ${cleanedCount} expired tokens`);
    return cleanedCount;
  }
  
  // Refresh token
  async refreshToken(refreshToken, user) {
    // Verify refresh token
    const refreshResult = await this.verifyToken(refreshToken);
    
    if (!refreshResult.valid) {
      throw new Error('Invalid refresh token');
    }
    
    // Check if refresh token is allowed for this user
    if (refreshResult.decoded.userId !== user.id) {
      throw new Error('Refresh token does not match user');
    }
    
    // Blacklist old refresh token
    await this.blacklistToken(refreshToken, 'refresh_rotation');
    
    // Generate new tokens
    const newAccessToken = this.generateToken(user, {
      expiresIn: '15m' // Shorter expiry for access token
    });
    
    const newRefreshToken = this.generateToken(user, {
      expiresIn: '7d',
      extraPayload: { isRefreshToken: true }
    });
    
    // Store new tokens
    await this.storeToken(user.id, newAccessToken);
    await this.storeToken(user.id, newRefreshToken);
    
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: 15 * 60 // 15 minutes in seconds
    };
  }
  
  // Security: Detect token anomalies
  async detectTokenAnomalies(token, requestInfo) {
    const verification = await this.verifyToken(token);
    
    if (!verification.valid) {
      return { anomaly: false }; // Token invalid anyway
    }
    
    const decoded = verification.decoded;
    const tokenInfoKey = `${this.prefix}token:${decoded.tokenId}`;
    const tokenInfo = await this.redis.get(tokenInfoKey);
    
    if (!tokenInfo) {
      return { anomaly: false };
    }
    
    const info = JSON.parse(tokenInfo);
    const anomalies = [];
    
    // Check location change
    if (requestInfo.ip && info.lastIp && requestInfo.ip !== info.lastIp) {
      anomalies.push({
        type: 'location_change',
        previous: info.lastIp,
        current: requestInfo.ip
      });
    }
    
    // Check user agent change
    if (requestInfo.userAgent && info.lastUserAgent && 
        requestInfo.userAgent !== info.lastUserAgent) {
      anomalies.push({
        type: 'user_agent_change',
        previous: info.lastUserAgent,
        current: requestInfo.userAgent
      });
    }
    
    // Check usage frequency
    const lastUsed = new Date(info.lastUsed);
    const now = new Date();
    const hoursSinceLastUse = (now - lastUsed) / (1000 * 60 * 60);
    
    if (hoursSinceLastUse > 24 && info.usageCount > 10) {
      anomalies.push({
        type: 'unusual_usage_pattern',
        hoursSinceLastUse,
        usageCount: info.usageCount
      });
    }
    
    // Update token info with current request
    info.lastIp = requestInfo.ip;
    info.lastUserAgent = requestInfo.userAgent;
    info.lastUsed = now.toISOString();
    info.usageCount = (info.usageCount || 0) + 1;
    
    const ttl = await this.redis.ttl(tokenInfoKey);
    if (ttl > 0) {
      await this.redis.setex(tokenInfoKey, ttl, JSON.stringify(info));
    }
    
    return {
      anomaly: anomalies.length > 0,
      anomalies
    };
  }
}
```

### Session Management

```javascript
class SessionManager {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.prefix = options.prefix || 'session:';
    this.sessionExpiry = options.sessionExpiry || 24 * 60 * 60; // 24 hours
    this.maxSessionsPerUser = options.maxSessionsPerUser || 5;
  }
  
  // Create new session
  async createSession(userId, sessionData = {}) {
    const sessionId = this.generateSessionId();
    const sessionKey = `${this.prefix}${sessionId}`;
    const userSessionsKey = `${this.prefix}user:${userId}:sessions`;
    
    const session = {
      id: sessionId,
      userId,
      createdAt: new Date().toISOString(),
      lastActiveAt: new Date().toISOString(),
      userAgent: sessionData.userAgent,
      ip: sessionData.ip,
      device: sessionData.device,
      location: sessionData.location,
      data: sessionData.data || {}
    };
    
    const pipeline = this.redis.pipeline();
    
    // Store session
    pipeline.setex(
      sessionKey,
      this.sessionExpiry,
      JSON.stringify(session)
    );
    
    // Add to user's sessions
    pipeline.sadd(userSessionsKey, sessionId);
    
    // Enforce max sessions per user
    pipeline.scard(userSessionsKey);
    
    const results = await pipeline.exec();
    const sessionCount = results[2][1];
    
    // If user has too many sessions, remove oldest ones
    if (sessionCount > this.maxSessionsPerUser) {
      await this.cleanupOldSessions(userId, sessionCount - this.maxSessionsPerUser);
    }
    
    return session;
  }
  
  generateSessionId() {
    return require('crypto').randomBytes(32).toString('hex');
  }
  
  // Get session
  async getSession(sessionId) {
    const sessionKey = `${this.prefix}${sessionId}`;
    const sessionData = await this.redis.get(sessionKey);
    
    if (!sessionData) {
      return null;
    }
    
    const session = JSON.parse(sessionData);
    
    // Update last active time
    session.lastActiveAt = new Date().toISOString();
    await this.redis.setex(sessionKey, this.sessionExpiry, JSON.stringify(session));
    
    return session;
  }
  
  // Update session
  async updateSession(sessionId, updates) {
    const sessionKey = `${this.prefix}${sessionId}`;
    const sessionData = await this.redis.get(sessionKey);
    
    if (!sessionData) {
      throw new Error('Session not found');
    }
    
    const session = JSON.parse(sessionData);
    const updatedSession = {
      ...session,
      ...updates,
      lastActiveAt: new Date().toISOString()
    };
    
    // Get remaining TTL
    const ttl = await this.redis.ttl(sessionKey);
    
    if (ttl > 0) {
      await this.redis.setex(sessionKey, ttl, JSON.stringify(updatedSession));
    }
    
    return updatedSession;
  }
  
  // Destroy session
  async destroySession(sessionId) {
    const sessionKey = `${this.prefix}${sessionId}`;
    const sessionData = await this.redis.get(sessionKey);
    
    if (!sessionData) {
      return false;
    }
    
    const session = JSON.parse(sessionData);
    const userSessionsKey = `${this.prefix}user:${session.userId}:sessions`;
    
    const pipeline = this.redis.pipeline();
    pipeline.del(sessionKey);
    pipeline.srem(userSessionsKey, sessionId);
    
    await pipeline.exec();
    
    return true;
  }
  
  // Destroy all sessions for user
  async destroyAllUserSessions(userId, exceptSessionId = null) {
    const userSessionsKey = `${this.prefix}user:${userId}:sessions`;
    const sessionIds = await this.redis.smembers(userSessionsKey);
    
    if (sessionIds.length === 0) {
      return 0;
    }
    
    const pipeline = this.redis.pipeline();
    let destroyedCount = 0;
    
    sessionIds.forEach(sessionId => {
      if (exceptSessionId && sessionId === exceptSessionId) {
        return; // Skip this session
      }
      
      pipeline.del(`${this.prefix}${sessionId}`);
      pipeline.srem(userSessionsKey, sessionId);
      destroyedCount++;
    });
    
    if (pipeline.length > 0) {
      await pipeline.exec();
    }
    
    return destroyedCount;
  }
  
  // Get all sessions for user
  async getUserSessions(userId) {
    const userSessionsKey = `${this.prefix}user:${userId}:sessions`;
    const sessionIds = await this.redis.smembers(userSessionsKey);
    
    const sessions = [];
    const pipeline = this.redis.pipeline();
    
    sessionIds.forEach(sessionId => {
      pipeline.get(`${this.prefix}${sessionId}`);
    });
    
    const results = await pipeline.exec();
    
    results.forEach(([error, data]) => {
      if (!error && data) {
        sessions.push(JSON.parse(data));
      }
    });
    
    // Sort by last active time (newest first)
    sessions.sort((a, b) => 
      new Date(b.lastActiveAt) - new Date(a.lastActiveAt)
    );
    
    return sessions;
  }
  
  // Cleanup old sessions for user
  async cleanupOldSessions(userId, countToRemove) {
    const userSessionsKey = `${this.prefix}user:${userId}:sessions`;
    const sessionIds = await this.redis.smembers(userSessionsKey);
    
    if (sessionIds.length === 0) {
      return 0;
    }
    
    // Get all sessions and sort by last active
    const sessions = await Promise.all(
      sessionIds.map(async sessionId => {
        const data = await this.redis.get(`${this.prefix}${sessionId}`);
        return data ? JSON.parse(data) : null;
      })
    );
    
    const validSessions = sessions.filter(s => s !== null);
    validSessions.sort((a, b) => 
      new Date(a.lastActiveAt) - new Date(b.lastActiveAt) // Oldest first
    );
    
    // Remove oldest sessions
    const sessionsToRemove = validSessions.slice(0, countToRemove);
    
    const pipeline = this.redis.pipeline();
    
    sessionsToRemove.forEach(session => {
      pipeline.del(`${this.prefix}${session.id}`);
      pipeline.srem(userSessionsKey, session.id);
    });
    
    if (pipeline.length > 0) {
      await pipeline.exec();
    }
    
    return sessionsToRemove.length;
  }
  
  // Session heartbeat
  async heartbeat(sessionId) {
    const sessionKey = `${this.prefix}${sessionId}`;
    const sessionData = await this.redis.get(sessionKey);
    
    if (!sessionData) {
      return false;
    }
    
    const session = JSON.parse(sessionData);
    session.lastActiveAt = new Date().toISOString();
    
    // Reset TTL
    await this.redis.setex(sessionKey, this.sessionExpiry, JSON.stringify(session));
    
    return true;
  }
  
  // Session validation with security checks
  async validateSession(sessionId, requestInfo) {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return { valid: false, reason: 'session_not_found' };
    }
    
    const checks = [];
    
    // Check if session is expired
    const lastActive = new Date(session.lastActiveAt);
    const now = new Date();
    const hoursInactive = (now - lastActive) / (1000 * 60 * 60);
    
    if (hoursInactive > 24) {
      checks.push({ check: 'inactivity', passed: false, hoursInactive });
    } else {
      checks.push({ check: 'inactivity', passed: true, hoursInactive });
    }
    
    // Check location (if IP provided)
    if (requestInfo.ip && session.ip) {
      const locationChanged = requestInfo.ip !== session.ip;
      checks.push({ 
        check: 'location', 
        passed: !locationChanged, 
        previous: session.ip,
        current: requestInfo.ip 
      });
    }
    
    // Check user agent (if provided)
    if (requestInfo.userAgent && session.userAgent) {
      const agentChanged = requestInfo.userAgent !== session.userAgent;
      checks.push({ 
        check: 'user_agent', 
        passed: !agentChanged,
        previous: session.userAgent,
        current: requestInfo.userAgent
      });
    }
    
    // Check if user account is still active
    const userActive = await this.isUserActive(session.userId);
    checks.push({ check: 'user_active', passed: userActive });
    
    // Determine if session is valid
    const criticalChecks = checks.filter(c => 
      ['inactivity', 'user_active'].includes(c.check)
    );
    
    const valid = criticalChecks.every(c => c.passed);
    
    return {
      valid,
      session: valid ? session : null,
      checks,
      requiresReauth: checks.some(c => !c.passed && c.check !== 'inactivity')
    };
  }
  
  async isUserActive(userId) {
    // Check if user exists and is active
    // This would typically check your database
    return true;
  }
  
  // Session analytics
  async getSessionStats() {
    const pattern = `${this.prefix}*`;
    let cursor = '0';
    let totalSessions = 0;
    let activeSessions = 0;
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      // Filter out user session sets
      const sessionKeys = keys.filter(key => 
        !key.includes(':sessions') && !key.startsWith(`${this.prefix}user:`)
      );
      
      totalSessions += sessionKeys.length;
      
      // Check which sessions are active (accessed in last hour)
      const now = Date.now();
      const pipeline = this.redis.pipeline();
      
      sessionKeys.forEach(key => {
        pipeline.get(key);
      });
      
      const results = await pipeline.exec();
      
      results.forEach(([error, data]) => {
        if (!error && data) {
          const session = JSON.parse(data);
          const lastActive = new Date(session.lastActiveAt);
          const hoursSinceActive = (now - lastActive) / (1000 * 60 * 60);
          
          if (hoursSinceActive < 1) {
            activeSessions++;
          }
        }
      });
      
    } while (cursor !== '0');
    
    return {
      totalSessions,
      activeSessions,
      inactiveSessions: totalSessions - activeSessions
    };
  }
}
```

### Token Rotation & Refresh

```javascript
class TokenRotationManager {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.prefix = options.prefix || 'token-rotation:';
    this.accessTokenExpiry = options.accessTokenExpiry || 15 * 60; // 15 minutes
    this.refreshTokenExpiry = options.refreshTokenExpiry || 7 * 24 * 60 * 60; // 7 days
    this.maxRefreshTokens = options.maxRefreshTokens || 5;
    this.rotationGracePeriod = options.rotationGracePeriod || 5 * 60; // 5 minutes
  }
  
  // Issue new tokens with rotation
  async issueTokens(userId, deviceInfo = {}) {
    const accessToken = this.generateToken(userId, 'access');
    const refreshToken = this.generateToken(userId, 'refresh');
    
    const tokenFamilyId = this.generateTokenFamilyId();
    
    // Store tokens
    await this.storeAccessToken(accessToken, userId, deviceInfo);
    await this.storeRefreshToken(refreshToken, userId, tokenFamilyId, deviceInfo);
    
    // Store token family
    await this.storeTokenFamily(tokenFamilyId, userId, refreshToken);
    
    return {
      accessToken,
      refreshToken,
      tokenFamilyId,
      expiresIn: this.accessTokenExpiry
    };
  }
  
  generateToken(userId, type) {
    const jwt = require('jsonwebtoken');
    const tokenId = require('crypto').randomBytes(16).toString('hex');
    
    const payload = {
      userId,
      tokenId,
      type,
      iat: Math.floor(Date.now() / 1000)
    };
    
    const expiresIn = type === 'access' ? this.accessTokenExpiry : this.refreshTokenExpiry;
    
    return jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn,
      issuer: 'your-app',
      audience: 'your-app-users'
    });
  }
  
  generateTokenFamilyId() {
    return require('crypto').randomBytes(8).toString('hex');
  }
  
  async storeAccessToken(token, userId, deviceInfo) {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(token);
    
    const tokenKey = `${this.prefix}access:${decoded.tokenId}`;
    const userAccessTokensKey = `${this.prefix}user:${userId}:access-tokens`;
    
    const tokenData = {
      tokenId: decoded.tokenId,
      userId,
      issuedAt: new Date(decoded.iat * 1000).toISOString(),
      expiresAt: new Date(decoded.exp * 1000).toISOString(),
      device: deviceInfo,
      lastUsed: null
    };
    
    const pipeline = this.redis.pipeline();
    
    // Store token
    pipeline.setex(
      tokenKey,
      this.accessTokenExpiry,
      JSON.stringify(tokenData)
    );
    
    // Add to user's access tokens
    pipeline.sadd(userAccessTokensKey, decoded.tokenId);
    pipeline.expire(userAccessTokensKey, this.accessTokenExpiry * 2);
    
    await pipeline.exec();
  }
  
  async storeRefreshToken(token, userId, familyId, deviceInfo) {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(token);
    
    const tokenKey = `${this.prefix}refresh:${decoded.tokenId}`;
    const userRefreshTokensKey = `${this.prefix}user:${userId}:refresh-tokens`;
    const familyKey = `${this.prefix}family:${familyId}`;
    
    const tokenData = {
      tokenId: decoded.tokenId,
      userId,
      familyId,
      issuedAt: new Date(decoded.iat * 1000).toISOString(),
      expiresAt: new Date(decoded.exp * 1000).toISOString(),
      device: deviceInfo,
      used: false
    };
    
    const pipeline = this.redis.pipeline();
    
    // Store refresh token
    pipeline.setex(
      tokenKey,
      this.refreshTokenExpiry,
      JSON.stringify(tokenData)
    );
    
    // Add to user's refresh tokens
    pipeline.sadd(userRefreshTokensKey, decoded.tokenId);
    
    // Add to token family
    pipeline.sadd(familyKey, decoded.tokenId);
    pipeline.expire(familyKey, this.refreshTokenExpiry);
    
    await pipeline.exec();
  }
  
  async storeTokenFamily(familyId, userId, currentToken) {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(currentToken);
    
    const familyKey = `${this.prefix}family:${familyId}`;
    const userFamiliesKey = `${this.prefix}user:${userId}:families`;
    
    const familyData = {
      familyId,
      userId,
      createdAt: new Date().toISOString(),
      currentTokenId: decoded.tokenId,
      previousTokens: []
    };
    
    const pipeline = this.redis.pipeline();
    
    pipeline.setex(
      familyKey,
      this.refreshTokenExpiry,
      JSON.stringify(familyData)
    );
    
    pipeline.sadd(userFamiliesKey, familyId);
    
    await pipeline.exec();
  }
  
  // Refresh tokens with rotation
  async refreshTokens(refreshToken, deviceInfo = {}) {
    const jwt = require('jsonwebtoken');
    
    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_SECRET, {
        issuer: 'your-app',
        audience: 'your-app-users'
      });
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
    
    if (decoded.type !== 'refresh') {
      throw new Error('Not a refresh token');
    }
    
    // Check if refresh token is valid and not used
    const tokenKey = `${this.prefix}refresh:${decoded.tokenId}`;
    const tokenData = await this.redis.get(tokenKey);
    
    if (!tokenData) {
      throw new Error('Refresh token not found or expired');
    }
    
    const tokenInfo = JSON.parse(tokenData);
    
    if (tokenInfo.used) {
      // Token reuse detected - possible attack!
      await this.handleTokenReuse(tokenInfo);
      throw new Error('Refresh token already used');
    }
    
    // Mark token as used
    tokenInfo.used = true;
    tokenInfo.usedAt = new Date().toISOString();
    await this.redis.setex(tokenKey, this.refreshTokenExpiry, JSON.stringify(tokenInfo));
    
    // Get token family
    const familyKey = `${this.prefix}family:${tokenInfo.familyId}`;
    const familyData = await this.redis.get(familyKey);
    
    if (!familyData) {
      throw new Error('Token family not found');
    }
    
    const familyInfo = JSON.parse(familyData);
    
    // Check if this is the current token in the family
    if (decoded.tokenId !== familyInfo.currentTokenId) {
      // Token is not the current one in family
      throw new Error('Refresh token is not current');
    }
    
    // Generate new tokens
    const newAccessToken = this.generateToken(decoded.userId, 'access');
    const newRefreshToken = this.generateToken(decoded.userId, 'refresh');
    
    // Store new refresh token in same family
    await this.storeRefreshToken(
      newRefreshToken,
      decoded.userId,
      tokenInfo.familyId,
      deviceInfo
    );
    
    // Update family with new current token
    familyInfo.previousTokens.push(familyInfo.currentTokenId);
    familyInfo.currentTokenId = jwt.decode(newRefreshToken).tokenId;
    familyInfo.updatedAt = new Date().toISOString();
    
    await this.redis.setex(familyKey, this.refreshTokenExpiry, JSON.stringify(familyInfo));
    
    // Store new access token
    await this.storeAccessToken(newAccessToken, decoded.userId, deviceInfo);
    
    // Cleanup old tokens in family if too many
    await this.cleanupTokenFamily(tokenInfo.familyId);
    
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      tokenFamilyId: tokenInfo.familyId,
      expiresIn: this.accessTokenExpiry
    };
  }
  
  async handleTokenReuse(tokenInfo) {
    console.warn(`Token reuse detected for user ${tokenInfo.userId}, token ${tokenInfo.tokenId}`);
    
    // Invalidate all tokens in the family
    const familyKey = `${this.prefix}family:${tokenInfo.familyId}`;
    const familyData = await this.redis.get(familyKey);
    
    if (familyData) {
      const familyInfo = JSON.parse(familyData);
      
      // Invalidate all tokens in family
      const pipeline = this.redis.pipeline();
      
      // Invalidate current token
      pipeline.del(`${this.prefix}refresh:${familyInfo.currentTokenId}`);
      
      // Invalidate previous tokens
      familyInfo.previousTokens.forEach(tokenId => {
        pipeline.del(`${this.prefix}refresh:${tokenId}`);
      });
      
      // Delete family
      pipeline.del(familyKey);
      
      // Remove family from user
      pipeline.srem(`${this.prefix}user:${tokenInfo.userId}:families`, tokenInfo.familyId);
      
      await pipeline.exec();
      
      // Log security event
      await this.logSecurityEvent({
        type: 'token_reuse',
        userId: tokenInfo.userId,
        familyId: tokenInfo.familyId,
        timestamp: new Date().toISOString(),
        details: tokenInfo
      });
    }
  }
  
  async cleanupTokenFamily(familyId) {
    const familyKey = `${this.prefix}family:${familyId}`;
    const familyData = await this.redis.get(familyKey);
    
    if (!familyData) {
      return;
    }
    
    const familyInfo = JSON.parse(familyData);
    
    // Keep only recent tokens
    if (familyInfo.previousTokens.length > this.maxRefreshTokens) {
      const tokensToRemove = familyInfo.previousTokens.slice(
        0,
        familyInfo.previousTokens.length - this.maxRefreshTokens
      );
      
      const pipeline = this.redis.pipeline();
      
      tokensToRemove.forEach(tokenId => {
        pipeline.del(`${this.prefix}refresh:${tokenId}`);
      });
      
      // Update family
      familyInfo.previousTokens = familyInfo.previousTokens.slice(
        familyInfo.previousTokens.length - this.maxRefreshTokens
      );
      
      pipeline.setex(familyKey, this.refreshTokenExpiry, JSON.stringify(familyInfo));
      
      await pipeline.exec();
    }
  }
  
  async logSecurityEvent(event) {
    const eventKey = `${this.prefix}security:events`;
    await this.redis.lpush(eventKey, JSON.stringify(event));
    await this.redis.ltrim(eventKey, 0, 1000); // Keep only last 1000 events
  }
  
  // Validate access token
  async validateAccessToken(token) {
    const jwt = require('jsonwebtoken');
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'your-app',
        audience: 'your-app-users'
      });
      
      if (decoded.type !== 'access') {
        return { valid: false, error: 'Not an access token' };
      }
      
      // Check if token is in Redis
      const tokenKey = `${this.prefix}access:${decoded.tokenId}`;
      const tokenData = await this.redis.get(tokenKey);
      
      if (!tokenData) {
        return { valid: false, error: 'Token not found' };
      }
      
      const tokenInfo = JSON.parse(tokenData);
      
      // Update last used time
      tokenInfo.lastUsed = new Date().toISOString();
      const ttl = await this.redis.ttl(tokenKey);
      
      if (ttl > 0) {
        await this.redis.setex(tokenKey, ttl, JSON.stringify(tokenInfo));
      }
      
      return {
        valid: true,
        decoded,
        tokenInfo
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
  
  // Revoke all tokens for user
  async revokeAllUserTokens(userId) {
    const pipeline = this.redis.pipeline();
    
    // Get all families for user
    const userFamiliesKey = `${this.prefix}user:${userId}:families`;
    const families = await this.redis.smembers(userFamiliesKey);
    
    // Invalidate each family
    families.forEach(familyId => {
      const familyKey = `${this.prefix}family:${familyId}`;
      pipeline.del(familyKey);
    });
    
    // Clear user families
    pipeline.del(userFamiliesKey);
    
    // Clear access tokens
    const userAccessTokensKey = `${this.prefix}user:${userId}:access-tokens`;
    const accessTokens = await this.redis.smembers(userAccessTokensKey);
    
    accessTokens.forEach(tokenId => {
      pipeline.del(`${this.prefix}access:${tokenId}`);
    });
    
    pipeline.del(userAccessTokensKey);
    
    // Clear refresh tokens
    const userRefreshTokensKey = `${this.prefix}user:${userId}:refresh-tokens`;
    const refreshTokens = await this.redis.smembers(userRefreshTokensKey);
    
    refreshTokens.forEach(tokenId => {
      pipeline.del(`${this.prefix}refresh:${tokenId}`);
    });
    
    pipeline.del(userRefreshTokensKey);
    
    await pipeline.exec();
    
    return {
      revoked: {
        families: families.length,
        accessTokens: accessTokens.length,
        refreshTokens: refreshTokens.length
      }
    };
  }
  
  // Get token usage statistics
  async getTokenStats(userId = null) {
    const stats = {
      totalAccessTokens: 0,
      activeAccessTokens: 0,
      totalRefreshTokens: 0,
      activeRefreshTokens: 0,
      totalFamilies: 0
    };
    
    if (userId) {
      // User-specific stats
      const userAccessTokensKey = `${this.prefix}user:${userId}:access-tokens`;
      const userRefreshTokensKey = `${this.prefix}user:${userId}:refresh-tokens`;
      const userFamiliesKey = `${this.prefix}user:${userId}:families`;
      
      const pipeline = this.redis.pipeline();
      pipeline.scard(userAccessTokensKey);
      pipeline.scard(userRefreshTokensKey);
      pipeline.scard(userFamiliesKey);
      
      const results = await pipeline.exec();
      
      stats.totalAccessTokens = results[0][1];
      stats.totalRefreshTokens = results[1][1];
      stats.totalFamilies = results[2][1];
      
    } else {
      // Global stats
      let cursor = '0';
      
      do {
        const [nextCursor, keys] = await this.redis.scan(
          cursor,
          'MATCH',
          `${this.prefix}*`,
          'COUNT',
          100
        );
        
        cursor = nextCursor;
        
        keys.forEach(key => {
          if (key.includes(':access:')) {
            stats.totalAccessTokens++;
          } else if (key.includes(':refresh:')) {
            stats.totalRefreshTokens++;
          } else if (key.includes(':family:')) {
            stats.totalFamilies++;
          }
        });
      } while (cursor !== '0');
    }
    
    return stats;
  }
}
```

---

## Pub/Sub for Notifications

### Real-time Communication

```javascript
class RealTimeNotificationSystem {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.publisher = redisClient.duplicate();
    this.subscribers = new Map(); // userId -> subscriber instance
    this.channels = new Map(); // channel -> Set of userIds
    this.prefix = options.prefix || 'notifications:';
    this.messageQueue = [];
    this.batchSize = options.batchSize || 100;
    this.flushInterval = options.flushInterval || 100; // ms
  }
  
  // Initialize the system
  async initialize() {
    // Start batch processing
    setInterval(() => {
      this.flushMessageQueue();
    }, this.flushInterval);
  }
  
  // Subscribe user to notifications
  async subscribe(userId, callback) {
    // Create subscriber if not exists
    if (!this.subscribers.has(userId)) {
      const subscriber = this.redis.duplicate();
      
      // Subscribe to user's personal channel
      const userChannel = `${this.prefix}user:${userId}`;
      await subscriber.subscribe(userChannel);
      
      // Handle messages
      subscriber.on('message', (channel, message) => {
        try {
          const notification = JSON.parse(message);
          callback(notification);
        } catch (error) {
          console.error('Error parsing notification:', error);
        }
      });
      
      // Handle errors
      subscriber.on('error', (error) => {
        console.error(`Subscriber error for user ${userId}:`, error);
      });
      
      this.subscribers.set(userId, subscriber);
      console.log(`User ${userId} subscribed to notifications`);
    }
    
    // Return unsubscribe function
    return () => this.unsubscribe(userId);
  }
  
  // Unsubscribe user
  async unsubscribe(userId) {
    const subscriber = this.subscribers.get(userId);
    
    if (subscriber) {
      const userChannel = `${this.prefix}user:${userId}`;
      await subscriber.unsubscribe(userChannel);
      subscriber.quit();
      this.subscribers.delete(userId);
      console.log(`User ${userId} unsubscribed from notifications`);
    }
  }
  
  // Send notification to single user
  async sendToUser(userId, notification) {
    const userChannel = `${this.prefix}user:${userId}`;
    const message = this.prepareNotification(notification);
    
    // Add to batch queue
    this.messageQueue.push({
      channel: userChannel,
      message: JSON.stringify(message)
    });
    
    // Flush if queue is large
    if (this.messageQueue.length >= this.batchSize) {
      await this.flushMessageQueue();
    }
  }
  
  // Send notification to multiple users
  async sendToUsers(userIds, notification) {
    const message = this.prepareNotification(notification);
    const messageStr = JSON.stringify(message);
    
    userIds.forEach(userId => {
      const userChannel = `${this.prefix}user:${userId}`;
      this.messageQueue.push({
        channel: userChannel,
        message: messageStr
      });
    });
    
    if (this.messageQueue.length >= this.batchSize) {
      await this.flushMessageQueue();
    }
  }
  
  // Send to channel (group of users)
  async sendToChannel(channelName, notification, options = {}) {
    const channel = `${this.prefix}channel:${channelName}`;
    const message = this.prepareNotification(notification);
    
    // Store channel membership if not already stored
    if (!this.channels.has(channel)) {
      await this.loadChannelMembers(channelName);
    }
    
    // Get channel members
    const members = this.channels.get(channel) || new Set();
    
    // Send to each member
    const promises = Array.from(members).map(userId => 
      this.sendToUser(userId, { ...message, channel: channelName })
    );
    
    await Promise.all(promises);
    
    // Also publish to channel for real-time updates
    if (options.broadcast) {
      await this.publisher.publish(channel, JSON.stringify(message));
    }
  }
  
  // Add user to channel
  async addToChannel(userId, channelName) {
    const channel = `${this.prefix}channel:${channelName}`;
    const channelMembersKey = `${channel}:members`;
    
    // Add to Redis set
    await this.redis.sadd(channelMembersKey, userId);
    
    // Update local cache
    if (!this.channels.has(channel)) {
      this.channels.set(channel, new Set());
    }
    this.channels.get(channel).add(userId);
    
    console.log(`User ${userId} added to channel ${channelName}`);
  }
  
  // Remove user from channel
  async removeFromChannel(userId, channelName) {
    const channel = `${this.prefix}channel:${channelName}`;
    const channelMembersKey = `${channel}:members`;
    
    // Remove from Redis set
    await this.redis.srem(channelMembersKey, userId);
    
    // Update local cache
    if (this.channels.has(channel)) {
      this.channels.get(channel).delete(userId);
    }
    
    console.log(`User ${userId} removed from channel ${channelName}`);
  }
  
  // Load channel members from Redis
  async loadChannelMembers(channelName) {
    const channel = `${this.prefix}channel:${channelName}`;
    const channelMembersKey = `${channel}:members`;
    
    const members = await this.redis.smembers(channelMembersKey);
    
    this.channels.set(channel, new Set(members));
    
    return members;
  }
  
  // Prepare notification object
  prepareNotification(data) {
    return {
      id: require('crypto').randomBytes(16).toString('hex'),
      type: data.type,
      title: data.title,
      body: data.body,
      data: data.data || {},
      timestamp: new Date().toISOString(),
      read: false,
      priority: data.priority || 'normal'
    };
  }
  
  // Flush message queue in batch
  async flushMessageQueue() {
    if (this.messageQueue.length === 0) {
      return;
    }
    
    const messages = this.messageQueue.splice(0, this.batchSize);
    const pipeline = this.publisher.pipeline();
    
    messages.forEach(({ channel, message }) => {
      pipeline.publish(channel, message);
    });
    
    try {
      await pipeline.exec();
      console.log(`Flushed ${messages.length} notifications`);
    } catch (error) {
      console.error('Error flushing message queue:', error);
      // Requeue failed messages
      this.messageQueue.unshift(...messages);
    }
  }
  
  // Store notification for offline users
  async storeOfflineNotification(userId, notification) {
    const notificationsKey = `${this.prefix}user:${userId}:stored`;
    
    await this.redis.lpush(
      notificationsKey,
      JSON.stringify(notification)
    );
    
    // Keep only last 100 notifications
    await this.redis.ltrim(notificationsKey, 0, 99);
    
    // Set expiry (7 days)
    await this.redis.expire(notificationsKey, 7 * 24 * 60 * 60);
    
    return notification.id;
  }
  
  // Get stored notifications for user
  async getStoredNotifications(userId, limit = 50) {
    const notificationsKey = `${this.prefix}user:${userId}:stored`;
    
    const notifications = await this.redis.lrange(
      notificationsKey,
      0,
      limit - 1
    );
    
    return notifications.map(n => JSON.parse(n));
  }
  
  // Mark notification as read
  async markAsRead(userId, notificationId) {
    const notificationsKey = `${this.prefix}user:${userId}:stored`;
    const notifications = await this.redis.lrange(notificationsKey, 0, -1);
    
    for (let i = 0; i < notifications.length; i++) {
      const notification = JSON.parse(notifications[i]);
      
      if (notification.id === notificationId) {
        notification.read = true;
        notification.readAt = new Date().toISOString();
        
        // Update in list
        await this.redis.lset(
          notificationsKey,
          i,
          JSON.stringify(notification)
        );
        
        return true;
      }
    }
    
    return false;
  }
  
  // Get notification statistics
  async getNotificationStats(userId = null) {
    const stats = {
      totalSent: 0,
      totalUnread: 0,
      byType: {},
      byChannel: {}
    };
    
    if (userId) {
      // User-specific stats
      const notificationsKey = `${this.prefix}user:${userId}:stored`;
      const notifications = await this.redis.lrange(notificationsKey, 0, -1);
      
      stats.totalSent = notifications.length;
      
      notifications.forEach(nStr => {
        const notification = JSON.parse(nStr);
        
        // Count by type
        stats.byType[notification.type] = (stats.byType[notification.type] || 0) + 1;
        
        // Count by channel
        if (notification.channel) {
          stats.byChannel[notification.channel] = (stats.byChannel[notification.channel] || 0) + 1;
        }
        
        // Count unread
        if (!notification.read) {
          stats.totalUnread++;
        }
      });
    }
    
    return stats;
  }
  
  // Typing indicators
  async setTypingIndicator(userId, channel, isTyping) {
    const typingKey = `${this.prefix}typing:${channel}`;
    
    if (isTyping) {
      // Add user to typing set
      await this.redis.zadd(typingKey, Date.now(), userId);
    } else {
      // Remove user from typing set
      await this.redis.zrem(typingKey, userId);
    }
    
    // Set expiry
    await this.redis.expire(typingKey, 30);
    
    // Notify channel about typing status
    await this.sendToChannel(channel, {
      type: 'typing',
      userId,
      isTyping,
      timestamp: new Date().toISOString()
    });
  }
  
  async getTypingUsers(channel) {
    const typingKey = `${this.prefix}typing:${channel}`;
    
    // Get users who typed in last 10 seconds
    const cutoff = Date.now() - 10000;
    const typingUsers = await this.redis.zrangebyscore(
      typingKey,
      cutoff,
      '+inf'
    );
    
    return typingUsers;
  }
  
  // Presence tracking
  async setUserPresence(userId, status, metadata = {}) {
    const presenceKey = `${this.prefix}presence:${userId}`;
    
    const presenceData = {
      userId,
      status,
      lastSeen: new Date().toISOString(),
      metadata
    };
    
    await this.redis.setex(
      presenceKey,
      300, // 5 minutes
      JSON.stringify(presenceData)
    );
    
    // Notify user's channels about presence change
    const userChannels = await this.getUserChannels(userId);
    
    userChannels.forEach(async channel => {
      await this.sendToChannel(channel, {
        type: 'presence',
        userId,
        status,
        timestamp: new Date().toISOString()
      });
    });
  }
  
  async getUserPresence(userId) {
    const presenceKey = `${this.prefix}presence:${userId}`;
    const presenceData = await this.redis.get(presenceKey);
    
    if (!presenceData) {
      return {
        userId,
        status: 'offline',
        lastSeen: null
      };
    }
    
    return JSON.parse(presenceData);
  }
  
  async getUserChannels(userId) {
    const pattern = `${this.prefix}channel:*:members`;
    let cursor = '0';
    const userChannels = [];
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      for (const key of keys) {
        const isMember = await this.redis.sismember(key, userId);
        
        if (isMember) {
          const channelName = key.match(/channel:(.*):members/)[1];
          userChannels.push(channelName);
        }
      }
    } while (cursor !== '0');
    
    return userChannels;
  }
  
  // Cleanup expired data
  async cleanup() {
    console.log('Starting notification system cleanup...');
    
    // Cleanup expired typing indicators
    const typingPattern = `${this.prefix}typing:*`;
    await this.cleanupExpiredKeys(typingPattern);
    
    // Cleanup old stored notifications (beyond 7 days)
    // This would require tracking creation time, which we're not currently doing
    
    console.log('Notification system cleanup completed');
  }
  
  async cleanupExpiredKeys(pattern) {
    let cursor = '0';
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      if (keys.length > 0) {
        const pipeline = this.redis.pipeline();
        
        keys.forEach(key => {
          pipeline.ttl(key);
        });
        
        const results = await pipeline.exec();
        const deletePipeline = this.redis.pipeline();
        
        results.forEach(([error, ttl], index) => {
          if (!error && ttl <= 0) {
            deletePipeline.del(keys[index]);
          }
        });
        
        if (deletePipeline.length > 0) {
          await deletePipeline.exec();
        }
      }
    } while (cursor !== '0');
  }
  
  // Graceful shutdown
  async shutdown() {
    console.log('Shutting down notification system...');
    
    // Unsubscribe all users
    const unsubscribePromises = Array.from(this.subscribers.keys()).map(
      userId => this.unsubscribe(userId)
    );
    
    await Promise.all(unsubscribePromises);
    
    // Flush remaining messages
    await this.flushMessageQueue();
    
    console.log('Notification system shut down');
  }
}
```

### Message Queue Patterns

```javascript
class RedisMessageQueue {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.queuePrefix = options.queuePrefix || 'mq:';
    this.deadLetterPrefix = options.deadLetterPrefix || 'dlq:';
    this.processingPrefix = options.processingPrefix || 'processing:';
    this.defaultVisibilityTimeout = options.visibilityTimeout || 30; // seconds
    this.maxRetries = options.maxRetries || 3;
    this.batchSize = options.batchSize || 10;
  }
  
  // Send message to queue
  async sendMessage(queueName, message, options = {}) {
    const queueKey = `${this.queuePrefix}${queueName}`;
    const messageId = this.generateMessageId();
    
    const messageData = {
      id: messageId,
      body: message,
      sentAt: new Date().toISOString(),
      attempts: 0,
      attributes: options.attributes || {},
      delay: options.delay || 0
    };
    
    if (options.delay > 0) {
      // Delayed message - use sorted set
      const score = Date.now() + (options.delay * 1000);
      await this.redis.zadd(
        `${queueKey}:delayed`,
        score,
        JSON.stringify(messageData)
      );
    } else {
      // Immediate message - use list
      await this.redis.lpush(queueKey, JSON.stringify(messageData));
    }
    
    return messageId;
  }
  
  generateMessageId() {
    return require('crypto').randomBytes(16).toString('hex');
  }
  
  // Receive messages from queue
  async receiveMessage(queueName, options = {}) {
    const queueKey = `${this.queuePrefix}${queueName}`;
    const processingKey = `${this.processingPrefix}${queueName}`;
    const visibilityTimeout = options.visibilityTimeout || this.defaultVisibilityTimeout;
    
    // Check for delayed messages that are ready
    await this.moveDelayedMessages(queueName);
    
    // Try to get a message
    const messageStr = await this.redis.rpoplpush(queueKey, processingKey);
    
    if (!messageStr) {
      return null;
    }
    
    const message = JSON.parse(messageStr);
    
    // Set visibility timeout
    await this.redis.expire(
      `${processingKey}:${message.id}`,
      visibilityTimeout
    );
    
    return {
      ...message,
      receiptHandle: `${processingKey}:${message.id}`,
      visibilityTimeout
    };
  }
  
  // Receive messages in batch
  async receiveMessages(queueName, maxMessages = 10, options = {}) {
    const messages = [];
    
    for (let i = 0; i < Math.min(maxMessages, this.batchSize); i++) {
      const message = await this.receiveMessage(queueName, options);
      
      if (!message) {
        break;
      }
      
      messages.push(message);
    }
    
    return messages;
  }
  
  // Move delayed messages that are ready
  async moveDelayedMessages(queueName) {
    const queueKey = `${this.queuePrefix}${queueName}`;
    const delayedKey = `${queueKey}:delayed`;
    
    const now = Date.now();
    const readyMessages = await this.redis.zrangebyscore(
      delayedKey,
      0,
      now,
      'WITHSCORES'
    );
    
    if (readyMessages.length === 0) {
      return 0;
    }
    
    const pipeline = this.redis.pipeline();
    
    // Add to main queue
    for (let i = 0; i < readyMessages.length; i += 2) {
      pipeline.lpush(queueKey, readyMessages[i]);
    }
    
    // Remove from delayed set
    pipeline.zremrangebyscore(delayedKey, 0, now);
    
    await pipeline.exec();
    
    return readyMessages.length / 2;
  }
  
  // Delete message (acknowledge)
  async deleteMessage(queueName, receiptHandle) {
    const processingKey = `${this.processingPrefix}${queueName}`;
    
    // Remove from processing
    const removed = await this.redis.lrem(processingKey, 1, receiptHandle);
    
    // Delete the message data
    await this.redis.del(receiptHandle);
    
    return removed > 0;
  }
  
  // Change message visibility
  async changeMessageVisibility(queueName, receiptHandle, visibilityTimeout) {
    await this.redis.expire(receiptHandle, visibilityTimeout);
    return true;
  }
  
  // Release message back to queue (on failure)
  async releaseMessage(queueName, receiptHandle, options = {}) {
    const processingKey = `${this.processingPrefix}${queueName}`;
    const queueKey = `${this.queuePrefix}${queueName}`;
    
    // Get message data
    const messageStr = await this.redis.get(receiptHandle);
    
    if (!messageStr) {
      throw new Error('Message not found');
    }
    
    const message = JSON.parse(messageStr);
    message.attempts++;
    
    // Check if max retries exceeded
    if (message.attempts >= this.maxRetries) {
      // Move to dead letter queue
      await this.moveToDeadLetterQueue(queueName, message);
      
      // Remove from processing
      await this.redis.lrem(processingKey, 1, receiptHandle);
      await this.redis.del(receiptHandle);
      
      return { movedToDLQ: true, messageId: message.id };
    }
    
    // Calculate delay for retry (exponential backoff)
    const delay = Math.min(
      900, // Max 15 minutes
      Math.pow(2, message.attempts) * 5 // Exponential backoff starting at 5 seconds
    );
    
    // Update message with new delay
    message.delay = delay;
    
    // Remove from processing
    await this.redis.lrem(processingKey, 1, receiptHandle);
    await this.redis.del(receiptHandle);
    
    // Requeue with delay
    if (delay > 0) {
      const score = Date.now() + (delay * 1000);
      await this.redis.zadd(
        `${queueKey}:delayed`,
        score,
        JSON.stringify(message)
      );
    } else {
      await this.redis.lpush(queueKey, JSON.stringify(message));
    }
    
    return { requeued: true, delay, attempts: message.attempts };
  }
  
  async moveToDeadLetterQueue(queueName, message) {
    const deadLetterKey = `${this.deadLetterPrefix}${queueName}`;
    
    message.deadLetteredAt = new Date().toISOString();
    message.deadLetterReason = 'max_retries_exceeded';
    
    await this.redis.lpush(deadLetterKey, JSON.stringify(message));
    
    // Keep only last 1000 DLQ messages
    await this.redis.ltrim(deadLetterKey, 0, 999);
  }
  
  // Get queue statistics
  async getQueueStats(queueName) {
    const queueKey = `${this.queuePrefix}${queueName}`;
    const processingKey = `${this.processingPrefix}${queueName}`;
    const delayedKey = `${queueKey}:delayed`;
    const deadLetterKey = `${this.deadLetterPrefix}${queueName}`;
    
    const pipeline = this.redis.pipeline();
    
    pipeline.llen(queueKey);
    pipeline.llen(processingKey);
    pipeline.zcard(delayedKey);
    pipeline.llen(deadLetterKey);
    
    const results = await pipeline.exec();
    
    return {
      visible: results[0][1],
      processing: results[1][1],
      delayed: results[2][1],
      deadLetter: results[3][1],
      total: results[0][1] + results[1][1] + results[2][1] + results[3][1]
    };
  }
  
  // Purge queue
  async purgeQueue(queueName) {
    const queueKey = `${this.queuePrefix}${queueName}`;
    const processingKey = `${this.processingPrefix}${queueName}`;
    const delayedKey = `${queueKey}:delayed`;
    
    const pipeline = this.redis.pipeline();
    
    pipeline.del(queueKey);
    pipeline.del(processingKey);
    pipeline.del(delayedKey);
    
    await pipeline.exec();
    
    return true;
  }
  
  // Worker pattern
  createWorker(queueName, processor, options = {}) {
    const worker = {
      queueName,
      processor,
      options,
      running: false,
      stopRequested: false
    };
    
    worker.start = async () => {
      worker.running = true;
      worker.stopRequested = false;
      
      console.log(`Worker started for queue: ${queueName}`);
      
      while (worker.running && !worker.stopRequested) {
        try {
          const messages = await this.receiveMessages(
            queueName,
            options.batchSize || 10,
            { visibilityTimeout: options.visibilityTimeout }
          );
          
          if (messages.length === 0) {
            // No messages, wait before checking again
            await new Promise(resolve => 
              setTimeout(resolve, options.pollInterval || 1000)
            );
            continue;
          }
          
          // Process messages
          const processingPromises = messages.map(async (message) => {
            try {
              await processor(message.body, message);
              
              // Delete message on success
              await this.deleteMessage(queueName, message.receiptHandle);
              
              return { success: true, messageId: message.id };
            } catch (error) {
              console.error(`Error processing message ${message.id}:`, error);
              
              // Release message for retry
              await this.releaseMessage(queueName, message.receiptHandle, {
                delay: options.retryDelay
              });
              
              return { success: false, messageId: message.id, error: error.message };
            }
          });
          
          await Promise.all(processingPromises);
          
        } catch (error) {
          console.error(`Worker error for queue ${queueName}:`, error);
          
          if (options.stopOnError) {
            worker.stop();
            break;
          }
        }
      }
      
      worker.running = false;
      console.log(`Worker stopped for queue: ${queueName}`);
    };
    
    worker.stop = () => {
      worker.stopRequested = true;
    };
    
    return worker;
  }
  
  // FIFO queue implementation
  async sendFIFOMessage(queueName, message, options = {}) {
    const queueKey = `${this.queuePrefix}fifo:${queueName}`;
    const messageId = this.generateMessageId();
    const messageGroupId = options.messageGroupId || 'default';
    
    const messageData = {
      id: messageId,
      body: message,
      sentAt: new Date().toISOString(),
      messageGroupId,
      sequenceNumber: await this.getNextSequenceNumber(queueName, messageGroupId),
      attributes: options.attributes || {}
    };
    
    // Use sorted set with sequence number as score for ordering
    await this.redis.zadd(
      queueKey,
      messageData.sequenceNumber,
      JSON.stringify(messageData)
    );
    
    return messageId;
  }
  
  async getNextSequenceNumber(queueName, messageGroupId) {
    const sequenceKey = `${this.queuePrefix}fifo:${queueName}:seq:${messageGroupId}`;
    return await this.redis.incr(sequenceKey);
  }
  
  async receiveFIFOMessage(queueName, options = {}) {
    const queueKey = `${this.queuePrefix}fifo:${queueName}`;
    const processingKey = `${this.processingPrefix}fifo:${queueName}`;
    
    // Get messages by sequence number
    const messages = await this.redis.zrange(queueKey, 0, 0, 'WITHSCORES');
    
    if (messages.length === 0) {
      return null;
    }
    
    const message = JSON.parse(messages[0]);
    const score = parseFloat(messages[1]);
    
    // Remove from queue
    await this.redis.zrem(queueKey, messages[0]);
    
    // Store in processing
    await this.redis.setex(
      `${processingKey}:${message.id}`,
      options.visibilityTimeout || this.defaultVisibilityTimeout,
      JSON.stringify(message)
    );
    
    return {
      ...message,
      receiptHandle: `${processingKey}:${message.id}`,
      sequenceNumber: score
    };
  }
}
```

### Event Sourcing with Redis Streams

```javascript
class EventSourcingSystem {
  constructor(redisClient, options = {}) {
    this.redis = redisClient;
    this.streamPrefix = options.streamPrefix || 'events:';
    this.consumerGroupPrefix = options.consumerGroupPrefix || 'consumers:';
    this.maxStreamLength = options.maxStreamLength || 10000;
    this.blockTime = options.blockTime || 5000; // ms
  }
  
  // Publish event to stream
  async publishEvent(streamName, eventType, data, options = {}) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    const event = {
      id: this.generateEventId(),
      type: eventType,
      data,
      timestamp: new Date().toISOString(),
      metadata: {
        source: options.source || 'system',
        correlationId: options.correlationId,
        causationId: options.causationId
      }
    };
    
    // Add to stream
    const messageId = await this.redis.xadd(
      streamKey,
      '*',
      'event',
      JSON.stringify(event)
    );
    
    // Trim stream if too long
    await this.redis.xtrim(streamKey, 'MAXLEN', '~', this.maxStreamLength);
    
    return {
      eventId: event.id,
      messageId,
      event
    };
  }
  
  generateEventId() {
    return require('crypto').randomBytes(16).toString('hex');
  }
  
  // Create consumer group
  async createConsumerGroup(streamName, groupName, options = {}) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    try {
      await this.redis.xgroup(
        'CREATE',
        streamKey,
        groupName,
        options.startId || '0',
        'MKSTREAM'
      );
    } catch (error) {
      if (!error.message.includes('BUSYGROUP')) {
        throw error;
      }
      // Group already exists
    }
    
    console.log(`Consumer group ${groupName} created for stream ${streamName}`);
  }
  
  // Read events as consumer
  async readEvents(streamName, groupName, consumerName, options = {}) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    const count = options.count || 10;
    const block = options.block || this.blockTime;
    
    try {
      // Read events
      const events = await this.redis.xreadgroup(
        'GROUP',
        groupName,
        consumerName,
        'COUNT',
        count,
        'BLOCK',
        block,
        'STREAMS',
        streamKey,
        options.startId || '>'
      );
      
      if (!events) {
        return [];
      }
      
      const parsedEvents = [];
      
      for (const [stream, messages] of events) {
        for (const [messageId, fields] of messages) {
          if (fields[0] === 'event') {
            const event = JSON.parse(fields[1]);
            parsedEvents.push({
              messageId,
              stream: stream.replace(this.streamPrefix, ''),
              event
            });
          }
        }
      }
      
      return parsedEvents;
    } catch (error) {
      console.error('Error reading events:', error);
      return [];
    }
  }
  
  // Acknowledge event processing
  async acknowledgeEvent(streamName, groupName, messageId) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    await this.redis.xack(streamKey, groupName, messageId);
  }
  
  // Claim pending events (for stalled consumers)
  async claimPendingEvents(streamName, groupName, consumerName, options = {}) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    const minIdleTime = options.minIdleTime || 60000; // 1 minute
    const count = options.count || 10;
    
    // Get pending events
    const pending = await this.redis.xpending(
      streamKey,
      groupName,
      '-',
      '+',
      count,
      consumerName
    );
    
    if (!pending || pending.length === 0) {
      return [];
    }
    
    const messageIds = pending.map(p => p[0]);
    
    // Claim events
    const claimed = await this.redis.xclaim(
      streamKey,
      groupName,
      consumerName,
      minIdleTime,
      messageIds
    );
    
    const parsedEvents = [];
    
    for (const [messageId, fields] of claimed) {
      if (fields[0] === 'event') {
        const event = JSON.parse(fields[1]);
        parsedEvents.push({
          messageId,
          event,
          claimed: true
        });
      }
    }
    
    return parsedEvents;
  }
  
  // Get stream information
  async getStreamInfo(streamName) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    const info = await this.redis.xinfo('STREAM', streamKey);
    
    // Parse info into object
    const result = {};
    for (let i = 0; i < info.length; i += 2) {
      result[info[i]] = info[i + 1];
    }
    
    return result;
  }
  
  // Get consumer groups for stream
  async getConsumerGroups(streamName) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    try {
      const groups = await this.redis.xinfo('GROUPS', streamKey);
      return groups;
    } catch (error) {
      return [];
    }
  }
  
  // Replay events from specific point
  async replayEvents(streamName, startId, endId = '+', count = 100) {
    const streamKey = `${this.streamPrefix}${streamName}`;
    
    const events = await this.redis.xrange(streamKey, startId, endId, 'COUNT', count);
    
    const parsedEvents = [];
    
    for (const [messageId, fields] of events) {
      if (fields[0] === 'event') {
        const event = JSON.parse(fields[1]);
        parsedEvents.push({
          messageId,
          event
        });
      }
    }
    
    return parsedEvents;
  }
  
  // Project events to create read models
  async projectEvents(streamName, projector, options = {}) {
    const projectionKey = options.projectionKey || `${streamName}:projection`;
    const startId = options.startId || '0';
    
    console.log(`Starting projection for ${streamName} from ${startId}`);
    
    let lastProcessedId = startId;
    let processedCount = 0;
    
    while (true) {
      // Read events
      const events = await this.replayEvents(
        streamName,
        lastProcessedId,
        '+',
        options.batchSize || 100
      );
      
      if (events.length === 0) {
        // No more events
        break;
      }
      
      // Process events
      for (const eventData of events) {
        try {
          await projector(eventData.event, projectionKey);
          lastProcessedId = eventData.messageId;
          processedCount++;
        } catch (error) {
          console.error(`Error projecting event ${eventData.messageId}:`, error);
          throw error;
        }
      }
      
      // Store last processed ID
      await this.redis.set(
        `${projectionKey}:last-id`,
        lastProcessedId
      );
      
      // If we got fewer events than batch size, we're done
      if (events.length < (options.batchSize || 100)) {
        break;
      }
    }
    
    console.log(`Projection completed. Processed ${processedCount} events.`);
    
    return {
      processedCount,
      lastProcessedId
    };
  }
  
  // Example projector function
  createUserProjector() {
    return async (event, projectionKey) => {
      switch (event.type) {
        case 'UserCreated':
          await this.redis.hset(
            `${projectionKey}:users`,
            event.data.userId,
            JSON.stringify({
              ...event.data,
              createdAt: event.timestamp
            })
          );
          break;
          
        case 'UserUpdated':
          const userKey = `${projectionKey}:users`;
          const existingUser = await this.redis.hget(userKey, event.data.userId);
          
          if (existingUser) {
            const user = JSON.parse(existingUser);
            const updatedUser = {
              ...user,
              ...event.data,
              updatedAt: event.timestamp
            };
            
            await this.redis.hset(
              userKey,
              event.data.userId,
              JSON.stringify(updatedUser)
            );
          }
          break;
          
        case 'UserDeleted':
          await this.redis.hdel(
            `${projectionKey}:users`,
            event.data.userId
          );
          break;
      }
    };
  }
  
  // Event handler pattern
  createEventHandler(streamName, groupName, consumerName, handler) {
    const eventHandler = {
      streamName,
      groupName,
      consumerName,
      handler,
      running: false,
      stopRequested: false
    };
    
    eventHandler.start = async () => {
      eventHandler.running = true;
      eventHandler.stopRequested = false;
      
      console.log(`EventHandler started for ${streamName} in group ${groupName}`);
      
      // Ensure consumer group exists
      await this.createConsumerGroup(streamName, groupName);
      
      while (eventHandler.running && !eventHandler.stopRequested) {
        try {
          // Read events
          const events = await this.readEvents(
            streamName,
            groupName,
            consumerName,
            { count: 10, block: 5000 }
          );
          
          // Process events
          for (const eventData of events) {
            try {
              await handler(eventData.event);
              
              // Acknowledge successful processing
              await this.acknowledgeEvent(
                streamName,
                groupName,
                eventData.messageId
              );
            } catch (error) {
              console.error(`Error handling event ${eventData.messageId}:`, error);
              
              // Event will remain pending and can be claimed by another consumer
            }
          }
          
          // Check for pending events that might be stalled
          if (events.length === 0) {
            const claimedEvents = await this.claimPendingEvents(
              streamName,
              groupName,
              consumerName,
              { minIdleTime: 30000 }
            );
            
            for (const eventData of claimedEvents) {
              try {
                await handler(eventData.event);
                await this.acknowledgeEvent(
                  streamName,
                  groupName,
                  eventData.messageId
                );
              } catch (error) {
                console.error(`Error handling claimed event ${eventData.messageId}:`, error);
              }
            }
          }
        } catch (error) {
          console.error(`EventHandler error for ${streamName}:`, error);
          
          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, 5000));
        }
      }
      
      eventHandler.running = false;
      console.log(`EventHandler stopped for ${streamName}`);
    };
    
    eventHandler.stop = () => {
      eventHandler.stopRequested = true;
    };
    
    return eventHandler;
  }
  
  // Get event store statistics
  async getEventStoreStats() {
    const pattern = `${this.streamPrefix}*`;
    let cursor = '0';
    const stats = {
      streams: 0,
      totalEvents: 0,
      streamSizes: {}
    };
    
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      
      cursor = nextCursor;
      
      stats.streams += keys.length;
      
      // Get size of each stream
      const pipeline = this.redis.pipeline();
      keys.forEach(key => pipeline.xlen(key));
      
      const results = await pipeline.exec();
      
      results.forEach(([error, size], index) => {
        if (!error) {
          const streamName = keys[index].replace(this.streamPrefix, '');
          stats.streamSizes[streamName] = size;
          stats.totalEvents += size;
        }
      });
    } while (cursor !== '0');
    
    return stats;
  }
  
  // Backup events to another stream or storage
  async backupEvents(streamName, targetStream, startId = '0', endId = '+') {
    console.log(`Backing up events from ${streamName} to ${targetStream}`);
    
    let lastProcessedId = startId;
    let backedUpCount = 0;
    
    while (true) {
      // Read events
      const events = await this.replayEvents(
        streamName,
        lastProcessedId,
        endId,
        100
      );
      
      if (events.length === 0) {
        break;
      }
      
      // Copy events to target stream
      const pipeline = this.redis.pipeline();
      
      events.forEach(eventData => {
        pipeline.xadd(
          `${this.streamPrefix}${targetStream}`,
          '*',
          'event',
          JSON.stringify(eventData.event)
        );
        
        lastProcessedId = eventData.messageId;
        backedUpCount++;
      });
      
      await pipeline.exec();
      
      // If we got fewer events than batch size, we're done
      if (events.length < 100) {
        break;
      }
    }
    
    console.log(`Backup completed. Copied ${backedUpCount} events.`);
    
    return {
      backedUpCount,
      lastProcessedId
    };
  }
}
```

---

## Advanced Redis Patterns

### Redis Data Structures

```javascript
class RedisDataStructures {
  constructor(redisClient) {
    this.redis = redisClient;
  }
  
  // HyperLogLog for approximate counting
  async hyperLogLogExample() {
    // Add elements to HyperLogLog
    await this.redis.pfadd('hll:visits', 'user1', 'user2', 'user3');
    
    // Get approximate count
    const count = await this.redis.pfcount('hll:visits');
    console.log(`Approximate unique visits: ${count}`);
    
    // Merge multiple HyperLogLogs
    await this.redis.pfadd('hll:visits:day1', 'user1', 'user2', 'user4');
    await this.redis.pfadd('hll:visits:day2', 'user2', 'user3', 'user5');
    
    await this.redis.pfmerge('hll:visits:total', 'hll:visits:day1', 'hll:visits:day2');
    const totalCount = await this.redis.pfcount('hll:visits:total');
    console.log(`Total approximate unique visits: ${totalCount}`);
  }
  
  // Bitmaps for feature flags and analytics
  async bitmapExample() {
    const userId = 12345;
    const dayOffset = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
    
    // Set bit for user activity
    await this.redis.setbit('user:active', userId, 1);
    await this.redis.setbit(`activity:day:${dayOffset}`, userId, 1);
    
    // Check if user is active
    const isActive = await this.redis.getbit('user:active', userId);
    console.log(`User ${userId} active: ${isActive}`);
    
    // Count active users
    const activeCount = await this.redis.bitcount('user:active');
    console.log(`Active users: ${activeCount}`);
    
    // Find users active on multiple days
    await this.redis.bitop('AND', 'active:both:days', 
      `activity:day:${dayOffset}`, 
      `activity:day:${dayOffset - 1}`
    );
    
    const activeBothDays = await this.redis.bitcount('active:both:days');
    console.log(`Users active both days: ${activeBothDays}`);
  }
  
  // Geospatial indexing
  async geospatialExample() {
    // Add locations
    await this.redis.geoadd('locations', 
      13.361389, 38.115556, 'Palermo',
      15.087269, 37.502669, 'Catania'
    );
    
    // Find locations within radius
    const nearby = await this.redis.georadius(
      'locations',
      15, 37, 100, 'km',
      'WITHDIST', 'WITHCOORD', 'ASC'
    );
    
    console.log('Locations within 100km:', nearby);
    
    // Get distance between two locations
    const distance = await this.redis.geodist('locations', 'Palermo', 'Catania', 'km');
    console.log(`Distance: ${distance}km`);
  }
  
  // Sorted sets for leaderboards
  async leaderboardExample() {
    // Add scores
    await this.redis.zadd('leaderboard',
      100, 'player1',
      200, 'player2',
      150, 'player3',
      300, 'player4'
    );
    
    // Get top 3 players
    const topPlayers = await this.redis.zrevrange('leaderboard', 0, 2, 'WITHSCORES');
    console.log('Top 3 players:', topPlayers);
    
    // Get player rank
    const rank = await this.redis.zrevrank('leaderboard', 'player3');
    console.log(`Player3 rank: ${rank + 1}`); // Convert 0-based to 1-based
    
    // Increment score
    await this.redis.zincrby('leaderboard', 50, 'player3');
    
    // Get players in score range
    const playersInRange = await this.redis.zrangebyscore('leaderboard', 150, 250);
    console.log('Players with scores 150-250:', playersInRange);
  }
  
  // Bloom filter (approximate membership)
  async bloomFilterExample() {
    // Using RedisBloom module if available
    // Otherwise, implement with bitmaps
    
    class BloomFilter {
      constructor(redis, key, size, hashFunctions) {
        this.redis = redis;
        this.key = key;
        this.size = size;
        this.hashFunctions = hashFunctions;
      }
      
      async add(item) {
        const hashes = this.getHashes(item);
        const pipeline = this.redis.pipeline();
        
        hashes.forEach(hash => {
          pipeline.setbit(this.key, hash % this.size, 1);
        });
        
        await pipeline.exec();
      }
      
      async mightContain(item) {
        const hashes = this.getHashes(item);
        const pipeline = this.redis.pipeline();
        
        hashes.forEach(hash => {
          pipeline.getbit(this.key, hash % this.size);
        });
        
        const results = await pipeline.exec();
        return results.every(([error, bit]) => bit === 1);
      }
      
      getHashes(item) {
        const hashes = [];
        for (let i = 0; i < this.hashFunctions; i++) {
          const hash = this.hash(`${item}:${i}`);
          hashes.push(hash);
        }
        return hashes;
      }
      
      hash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          hash = ((hash << 5) - hash) + str.charCodeAt(i);
          hash |= 0; // Convert to 32bit integer
        }
        return Math.abs(hash);
      }
    }
    
    const bloomFilter = new BloomFilter(this.redis, 'bloom:users', 10000, 3);
    
    await bloomFilter.add('user123');
    await bloomFilter.add('user456');
    
    const mightExist = await bloomFilter.mightContain('user123');
    console.log(`User123 might exist: ${mightExist}`);
    
    const mightNotExist = await bloomFilter.mightContain('user999');
    console.log(`User999 might exist: ${mightNotExist}`);
  }
}
```

### Redis Cluster & Sentinel

```javascript
class RedisClusterManager {
  constructor() {
    this.cluster = null;
    this.sentinel = null;
    this.monitoring = false;
  }
  
  // Connect to Redis Cluster
  async connectToCluster(nodes) {
    const Redis = require('ioredis');
    
    this.cluster = new Redis.Cluster(nodes, {
      scaleReads: 'slave', // Read from slaves
      clusterRetryStrategy: (times) => {
        const delay = Math.min(100 + times * 2, 2000);
        return delay;
      },
      redisOptions: {
        password: process.env.REDIS_PASSWORD,
        retryStrategy: (times) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        }
      }
    });
    
    this.cluster.on('connect', () => {
      console.log('Connected to Redis Cluster');
    });
    
    this.cluster.on('error', (error) => {
      console.error('Redis Cluster error:', error);
    });
    
    this.cluster.on('node error', (error, node) => {
      console.error(`Node ${node} error:`, error);
    });
    
    return this.cluster;
  }
  
  // Connect via Sentinel
  async connectViaSentinel(sentinels, options = {}) {
    const Redis = require('ioredis');
    
    this.sentinel = new Redis({
      sentinels,
      name: options.masterName || 'mymaster',
      password: options.password,
      role: options.role || 'master', // 'master', 'slave', or 'all'
      sentinelPassword: options.sentinelPassword,
      enableReadyCheck: true,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      }
    });
    
    this.sentinel.on('connect', () => {
      console.log('Connected via Sentinel');
    });
    
    this.sentinel.on('error', (error) => {
      console.error('Sentinel connection error:', error);
    });
    
    return this.sentinel;
  }
  
  // Monitor cluster health
  async monitorClusterHealth() {
    if (!this.cluster) {
      throw new Error('Not connected to cluster');
    }
    
    this.monitoring = true;
    
    const healthCheck = async () => {
      if (!this.monitoring) return;
      
      try {
        const nodes = this.cluster.nodes();
        const health = {
          timestamp: new Date().toISOString(),
          nodes: [],
          overall: 'healthy'
        };
        
        for (const node of nodes) {
          try {
            await node.ping();
            health.nodes.push({
              host: node.options.host,
              port: node.options.port,
              role: node.options.role,
              status: 'healthy'
            });
          } catch (error) {
            health.nodes.push({
              host: node.options.host,
              port: node.options.port,
              role: node.options.role,
              status: 'unhealthy',
              error: error.message
            });
            health.overall = 'degraded';
          }
        }
        
        console.log('Cluster health:', health);
        
        // Alert if degraded
        if (health.overall === 'degraded') {
          await this.alertDegradedCluster(health);
        }
        
      } catch (error) {
        console.error('Health check error:', error);
      }
      
      // Schedule next check
      if (this.monitoring) {
        setTimeout(healthCheck, 30000); // Check every 30 seconds
      }
    };
    
    await healthCheck();
  }
  
  async alertDegradedCluster(health) {
    // Implement alerting (email, Slack, etc.)
    console.warn('Cluster is degraded:', health);
  }
  
  stopMonitoring() {
    this.monitoring = false;
  }
  
  // Get cluster info
  async getClusterInfo() {
    if (!this.cluster) {
      throw new Error('Not connected to cluster');
    }
    
    const info = await this.cluster.info();
    const nodes = this.cluster.nodes();
    
    return {
      clusterState: info.cluster_state,
      clusterSlotsAssigned: info.cluster_slots_assigned,
      clusterSlotsOk: info.cluster_slots_ok,
      clusterSlotsPfail: info.cluster_slots_pfail,
      clusterSlotsFail: info.cluster_slots_fail,
      clusterKnownNodes: info.cluster_known_nodes,
      clusterSize: info.cluster_size,
      currentNodeEpoch: info.cluster_current_epoch,
      myEpoch: info.cluster_my_epoch,
      nodes: nodes.map(node => ({
        host: node.options.host,
        port: node.options.port,
        role: node.options.role
      }))
    };
  }
  
  // Reshard cluster (simplified example)
  async reshardCluster(slots, targetNode) {
    // Note: This is a simplified example
    // Real resharding would use Redis Cluster commands
    
    console.log(`Resharding ${slots} slots to ${targetNode}`);
    
    // This would typically use:
    // CLUSTER SETSLOT <slot> IMPORTING <source-node-id>
    // CLUSTER SETSLOT <slot> MIGRATING <target-node-id>
    // MIGRATE commands to move keys
    // CLUSTER SETSLOT <slot> NODE <target-node-id>
    
    // For now, just log the intent
    return { success: true, message: 'Resharding started' };
  }
  
  // Failover simulation
  async simulateFailover() {
    if (!this.sentinel) {
      throw new Error('Not connected via Sentinel');
    }
    
    console.log('Simulating failover...');
    
    // Force failover through Sentinel
    // Note: This requires proper Sentinel configuration
    // await this.sentinel.sentinel('failover', 'mymaster');
    
    return { success: true, message: 'Failover simulated' };
  }
  
  // Key distribution analysis
  async analyzeKeyDistribution() {
    if (!this.cluster) {
      throw new Error('Not connected to cluster');
    }
    
    const nodes = this.cluster.nodes('master');
    const distribution = {};
    
    for (const node of nodes) {
      try {
        // Get keys from node (this is expensive, use with caution)
        const keys = await node.keys('*');
        distribution[`${node.options.host}:${node.options.port}`] = keys.length;
      } catch (error) {
        console.error(`Error getting keys from ${node.options.host}:`, error);
        distribution[`${node.options.host}:${node.options.port}`] = 'error';
      }
    }
    
    return distribution;
  }
  
  // Slot migration helper
  async migrateSlots(sourceNode, targetNode, slots) {
    // Simplified slot migration helper
    console.log(`Migrating slots ${slots.join(',')} from ${sourceNode} to ${targetNode}`);
    
    // In reality, this would involve:
    // 1. Setting slots to migrating/importing state
    // 2. Migrating keys one by one
    // 3. Updating slot ownership
    
    return { success: true, migratedSlots: slots.length };
  }
}
```

### Performance Monitoring

```javascript
class RedisPerformanceMonitor {
  constructor(redisClient) {
    this.redis = redisClient;
    this.metrics = {
      commands: {},
      latency: [],
      memory: [],
      connections: []
    };
    this.samplingInterval = 10000; // 10 seconds
    this.isMonitoring = false;
  }
  
  // Start monitoring
  startMonitoring() {
    if (this.isMonitoring) {
      return;
    }
    
    this.isMonitoring = true;
    console.log('Starting Redis performance monitoring');
    
    // Collect metrics periodically
    this.monitoringInterval = setInterval(() => {
      this.collectMetrics();
    }, this.samplingInterval);
    
    // Initial collection
    this.collectMetrics();
  }
  
  // Stop monitoring
  stopMonitoring() {
    if (!this.isMonitoring) {
      return;
    }
    
    this.isMonitoring = false;
    clearInterval(this.monitoringInterval);
    console.log('Stopped Redis performance monitoring');
  }
  
  // Collect metrics
  async collectMetrics() {
    try {
      // Get INFO command output
      const info = await this.redis.info();
      const infoLines = info.split('\n');
      
      // Parse INFO
      const parsedInfo = {};
      infoLines.forEach(line => {
        if (line.includes(':')) {
          const [key, value] = line.split(':');
          parsedInfo[key.trim()] = value.trim();
        }
      });
      
      // Collect command stats
      await this.collectCommandStats(parsedInfo);
      
      // Collect memory stats
      this.collectMemoryStats(parsedInfo);
      
      // Collect connection stats
      this.collectConnectionStats(parsedInfo);
      
      // Collect latency sample
      await this.collectLatencySample();
      
      // Check for anomalies
      await this.checkForAnomalies();
      
    } catch (error) {
      console.error('Error collecting metrics:', error);
    }
  }
  
  async collectCommandStats(info) {
    // Parse commandstats
    const commandStats = {};
    
    Object.keys(info).forEach(key => {
      if (key.startsWith('cmdstat_')) {
        const command = key.replace('cmdstat_', '');
        const stats = info[key].split(',');
        
        commandStats[command] = {
          calls: parseInt(stats[0].split('=')[1]),
          usec: parseInt(stats[1].split('=')[1]),
          usec_per_call: parseFloat(stats[2].split('=')[1])
        };
      }
    });
    
    // Update metrics
    this.metrics.commands = commandStats;
  }
  
  collectMemoryStats(info) {
    const memorySample = {
      timestamp: new Date().toISOString(),
      used_memory: parseInt(info.used_memory),
      used_memory_rss: parseInt(info.used_memory_rss),
      used_memory_peak: parseInt(info.used_memory_peak),
      mem_fragmentation_ratio: parseFloat(info.mem_fragmentation_ratio),
      maxmemory: parseInt(info.maxmemory) || 0
    };
    
    this.metrics.memory.push(memorySample);
    
    // Keep only last 100 samples
    if (this.metrics.memory.length > 100) {
      this.metrics.memory.shift();
    }
  }
  
  collectConnectionStats(info) {
    const connectionSample = {
      timestamp: new Date().toISOString(),
      connected_clients: parseInt(info.connected_clients),
      connected_slaves: parseInt(info.connected_slaves || 0),
      blocked_clients: parseInt(info.blocked_clients),
      total_connections_received: parseInt(info.total_connections_received),
      total_commands_processed: parseInt(info.total_commands_processed)
    };
    
    this.metrics.connections.push(connectionSample);
    
    if (this.metrics.connections.length > 100) {
      this.metrics.connections.shift();
    }
  }
  
  async collectLatencySample() {
    try {
      const start = Date.now();
      await this.redis.ping();
      const end = Date.now();
      
      const latency = end - start;
      
      this.metrics.latency.push({
        timestamp: new Date().toISOString(),
        latency
      });
      
      if (this.metrics.latency.length > 100) {
        this.metrics.latency.shift();
      }
    } catch (error) {
      console.error('Error measuring latency:', error);
    }
  }
  
  async checkForAnomalies() {
    const anomalies = [];
    
    // Check memory usage
    const currentMemory = this.metrics.memory[this.metrics.memory.length - 1];
    if (currentMemory && currentMemory.maxmemory > 0) {
      const memoryUsage = (currentMemory.used_memory / currentMemory.maxmemory) * 100;
      
      if (memoryUsage > 90) {
        anomalies.push({
          type: 'high_memory_usage',
          severity: 'high',
          message: `Memory usage is ${memoryUsage.toFixed(2)}%`,
          value: memoryUsage,
          threshold: 90
        });
      }
    }
    
    // Check fragmentation
    if (currentMemory && currentMemory.mem_fragmentation_ratio > 1.5) {
      anomalies.push({
        type: 'high_fragmentation',
        severity: 'medium',
        message: `Memory fragmentation ratio is ${currentMemory.mem_fragmentation_ratio}`,
        value: currentMemory.mem_fragmentation_ratio,
        threshold: 1.5
      });
    }
    
    // Check latency
    const recentLatencies = this.metrics.latency.slice(-10);
    if (recentLatencies.length > 0) {
      const avgLatency = recentLatencies.reduce((sum, l) => sum + l.latency, 0) / recentLatencies.length;
      
      if (avgLatency > 100) { // 100ms threshold
        anomalies.push({
          type: 'high_latency',
          severity: 'high',
          message: `Average latency is ${avgLatency.toFixed(2)}ms`,
          value: avgLatency,
          threshold: 100
        });
      }
    }
    
    // Check slow commands
    Object.entries(this.metrics.commands).forEach(([command, stats]) => {
      if (stats.usec_per_call > 1000) { // 1ms per call threshold
        anomalies.push({
          type: 'slow_command',
          severity: 'medium',
          message: `Command ${command} is slow: ${stats.usec_per_call}μs per call`,
          command,
          usec_per_call: stats.usec_per_call,
          calls: stats.calls
        });
      }
    });
    
    // Alert if anomalies found
    if (anomalies.length > 0) {
      await this.alertAnomalies(anomalies);
    }
  }
  
  async alertAnomalies(anomalies) {
    // Implement alerting logic
    console.warn('Redis performance anomalies detected:', anomalies);
    
    // Could send to monitoring system, email, Slack, etc.
  }
  
  // Get performance report
  getPerformanceReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalCommands: Object.values(this.metrics.commands).reduce((sum, stats) => sum + stats.calls, 0),
        avgLatency: this.calculateAverageLatency(),
        memoryUsage: this.calculateMemoryUsage(),
        connectionCount: this.metrics.connections.length > 0 
          ? this.metrics.connections[this.metrics.connections.length - 1].connected_clients 
          : 0
      },
      topCommands: this.getTopCommands(5),
      trends: {
        memory: this.calculateMemoryTrend(),
        latency: this.calculateLatencyTrend(),
        connections: this.calculateConnectionTrend()
      },
      recommendations: this.generateRecommendations()
    };
    
    return report;
  }
  
  calculateAverageLatency() {
    if (this.metrics.latency.length === 0) return 0;
    
    const sum = this.metrics.latency.reduce((total, sample) => total + sample.latency, 0);
    return sum / this.metrics.latency.length;
  }
  
  calculateMemoryUsage() {
    if (this.metrics.memory.length === 0) return 0;
    
    const latest = this.metrics.memory[this.metrics.memory.length - 1];
    if (latest.maxmemory === 0) return 0;
    
    return (latest.used_memory / latest.maxmemory) * 100;
  }
  
  getTopCommands(limit) {
    return Object.entries(this.metrics.commands)
      .sort(([, a], [, b]) => b.calls - a.calls)
      .slice(0, limit)
      .map(([command, stats]) => ({
        command,
        calls: stats.calls,
        avg_usec: stats.usec_per_call
      }));
  }
  
  calculateMemoryTrend() {
    if (this.metrics.memory.length < 2) return 'stable';
    
    const recent = this.metrics.memory.slice(-5);
    const first = recent[0].used_memory;
    const last = recent[recent.length - 1].used_memory;
    
    const change = ((last - first) / first) * 100;
    
    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  }
  
  calculateLatencyTrend() {
    if (this.metrics.latency.length < 2) return 'stable';
    
    const recent = this.metrics.latency.slice(-10);
    const first = recent[0].latency;
    const last = recent[recent.length - 1].latency;
    
    const change = ((last - first) / first) * 100;
    
    if (change > 20) return 'increasing';
    if (change < -20) return 'decreasing';
    return 'stable';
  }
  
  calculateConnectionTrend() {
    if (this.metrics.connections.length < 2) return 'stable';
    
    const recent = this.metrics.connections.slice(-5);
    const first = recent[0].connected_clients;
    const last = recent[recent.length - 1].connected_clients;
    
    const change = ((last - first) / first) * 100;
    
    if (change > 20) return 'increasing';
    if (change < -20) return 'decreasing';
    return 'stable';
  }
  
  generateRecommendations() {
    const recommendations = [];
    
    // Memory recommendations
    const memoryUsage = this.calculateMemoryUsage();
    if (memoryUsage > 80) {
      recommendations.push({
        type: 'memory',
        priority: 'high',
        message: 'Consider increasing maxmemory or implementing eviction policy',
        action: 'Increase Redis maxmemory or review data retention'
      });
    }
    
    // Latency recommendations
    const avgLatency = this.calculateAverageLatency();
    if (avgLatency > 50) {
      recommendations.push({
        type: 'latency',
        priority: 'medium',
        message: 'Consider optimizing slow commands or scaling Redis',
        action: 'Review command patterns and consider Redis Cluster'
      });
    }
    
    // Command recommendations
    const slowCommands = Object.entries(this.metrics.commands)
      .filter(([, stats]) => stats.usec_per_call > 1000);
    
    if (slowCommands.length > 0) {
      recommendations.push({
        type: 'commands',
        priority: 'medium',
        message: `${slowCommands.length} commands are executing slowly`,
        action: 'Optimize slow commands or implement caching'
      });
    }
    
    return recommendations;
  }
  
  // Export metrics for external monitoring
  exportMetrics() {
    return {
      metrics: this.metrics,
      report: this.getPerformanceReport()
    };
  }
  
  // Clear old metrics
  clearOldMetrics() {
    // Keep only last hour of metrics (assuming 10-second sampling)
    const maxSamples = 360; // 1 hour / 10 seconds
    
    ['memory', 'latency', 'connections'].forEach(metricType => {
      if (this.metrics[metricType].length > maxSamples) {
        this.metrics[metricType] = this.metrics[metricType].slice(-maxSamples);
      }
    });
  }
}
```

---

## Interview Questions

### Junior to Mid-Level

**Caching:**
1. What is caching and why is it important?
2. Explain the difference between cache-aside and write-through patterns.
3. What is cache invalidation and what strategies do you know?
4. How would you handle cache stampede (cache miss storm)?
5. What are the trade-offs between TTL-based and explicit cache invalidation?

**Rate Limiting:**
1. What is rate limiting and why is it important?
2. Explain the difference between fixed window and sliding window algorithms.
3. How would you implement rate limiting for an API endpoint?
4. What is the token bucket algorithm and when would you use it?
5. How can you prevent a single user from bypassing rate limits?

**Blacklisting Tokens:**
1. Why would you need to blacklist JWT tokens?
2. How would you implement token blacklisting in a distributed system?
3. What are the security implications of not blacklisting tokens?
4. How would you handle token rotation and refresh tokens?
5. What strategies would you use for session management?

**Pub/Sub:**
1. What is Redis Pub/Sub and how does it work?
2. How would you implement real-time notifications using Redis?
3. What are the limitations of Redis Pub/Sub?
4. How would you ensure message delivery in a Pub/Sub system?
5. What is the difference between Pub/Sub and message queues?

### Senior Level

**Architecture & Design:**
1. How would you design a distributed caching layer for a microservices architecture?
2. What strategies would you use for cache consistency across multiple services?
3. How would you implement a real-time notification system at scale?
4. What are the considerations for implementing rate limiting in a distributed system?
5. How would you design a token management system for a large-scale application?

**Performance & Scaling:**
1. How would you optimize Redis memory usage for a large cache?
2. What strategies would you use for Redis cluster sharding?
3. How would you handle Redis failover and high availability?
4. What monitoring would you implement for a Redis-based system?
5. How would you optimize Redis for low-latency requirements?

**Security:**
1. How would you secure Redis in a production environment?
2. What are common Redis security vulnerabilities and how would you mitigate them?
3. How would you implement secure token management with Redis?
4. What strategies would you use for preventing Redis-based attacks?
5. How would you implement audit logging for token operations?

**Advanced Patterns:**
1. How would you implement event sourcing with Redis Streams?
2. What are the trade-offs between Redis Pub/Sub and Redis Streams?
3. How would you implement a distributed lock using Redis?
4. What are Redis data structures you would use for specific use cases?
5. How would you implement a leaderboard system with real-time updates?

### Real-World Scenarios

**Scenario 1: E-commerce Platform**
You're building an e-commerce platform that needs:
- Product catalog caching for 10M+ products
- Real-time inventory updates during flash sales
- Rate limiting for API endpoints during peak traffic
- Session management for millions of users
- Real-time notifications for order updates

**Questions:**
1. How would you design the caching strategy for the product catalog?
2. How would you handle cache invalidation for inventory updates?
3. What rate limiting strategy would you use for the checkout API?
4. How would you implement distributed session management?
5. How would you ensure real-time notifications are delivered reliably?

**Scenario 2: Social Media Application**
You're building a social media app that needs:
- Real-time feed updates for millions of users
- Rate limiting for post creation and API calls
- Token management for mobile and web clients
- Real-time notifications for likes, comments, and follows
- Trending topics with real-time updates

**Questions:**
1. How would you implement real-time feed updates using Redis?
2. What rate limiting strategy would you use for post creation?
3. How would you handle token refresh for mobile clients?
4. How would you implement real-time notifications at scale?
5. How would you calculate trending topics in real-time?

**Scenario 3: Financial Trading Platform**
You're building a trading platform that needs:
- Real-time price updates with sub-millisecond latency
- Rate limiting for trade execution
- Session management with strict security requirements
- Audit logging for all token operations
- Market data caching and distribution

**Questions:**
1. How would you optimize Redis for sub-millisecond latency?
2. What rate limiting algorithm would you use for trade execution?
3. How would you implement secure session management?
4. How would you audit token operations for compliance?
5. How would you distribute market data in real-time?

**Scenario 4: IoT Platform**
You're building an IoT platform that needs:
- Real-time device telemetry processing
- Rate limiting for device connections
- Command queuing for device management
- Real-time alerts and notifications
- Device state caching

**Questions:**
1. How would you process real-time telemetry data using Redis?
2. What rate limiting strategy would you use for device connections?
3. How would you implement command queuing for devices?
4. How would you send real-time alerts for device anomalies?
5. How would you cache and update device state?

**Scenario 5: Multi-tenant SaaS Application**
You're building a SaaS platform that needs:
- Tenant-specific caching with isolation
- Rate limiting per tenant and per user
- Token management with tenant context
- Real-time notifications for tenant users
- Analytics caching for dashboards

**Questions:**
1. How would you implement tenant-isolated caching?
2. What hierarchical rate limiting would you implement?
3. How would you manage tokens in a multi-tenant environment?
4. How would you send notifications to specific tenant users?
5. How would you cache analytics data for dashboard performance?

**Scenario 6: Gaming Platform**
You're building a gaming platform that needs:
- Real-time game state updates
- Leaderboards with real-time ranking
- Rate limiting for game actions
- Session management for game connections
- Real-time chat and notifications

**Questions:**
1. How would you implement real-time game state using Redis?
2. How would you maintain leaderboards with real-time updates?
3. What rate limiting would you use for game actions?
4. How would you manage game sessions?
5. How would you implement real-time chat using Redis?

**Scenario 7: Healthcare Application**
You're building a healthcare app that needs:
- HIPAA-compliant session management
- Rate limiting for sensitive operations
- Audit logging for all access tokens
- Real-time notifications for critical alerts
- Patient data caching with strict invalidation

**Questions:**
1. How would you implement HIPAA-compliant session management?
2. What rate limiting would you use for sensitive healthcare operations?
3. How would you audit token access for compliance?
4. How would you ensure reliable delivery of critical alerts?
5. How would you cache patient data with proper invalidation?

These scenarios and questions cover the depth and breadth of knowledge expected from senior developers working with Redis in production environments.