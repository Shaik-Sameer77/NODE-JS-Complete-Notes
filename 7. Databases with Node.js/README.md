# Node.js Databases: Comprehensive Guide

## Table of Contents
- [MongoDB with Mongoose](#mongodb-with-mongoose)
- [PostgreSQL with Prisma/Sequelize/Knex](#postgresql-with-prisma-sequelize-knex)
- [Redis](#redis)
- [Interview Questions](#interview-questions)
- [Real-World Scenarios](#real-world-scenarios)

---

## MongoDB with Mongoose

### Schemas
Schemas in Mongoose define the structure of documents within a MongoDB collection. They specify field types, default values, validators, and other metadata.

```javascript
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  age: { type: Number, min: 18, max: 100 },
  createdAt: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['active', 'inactive', 'suspended'],
    default: 'active'
  }
});
```

**Key Points:**
- Schemas are blueprint for documents
- Support nested schemas for complex structures
- Can define virtual properties (not stored in DB)
- Enable middleware (pre/post hooks)

### Models
Models are constructors compiled from Schema definitions. They represent MongoDB collections and provide an interface for CRUD operations.

```javascript
const User = mongoose.model('User', userSchema);

// Create document
const newUser = new User({ username: 'john_doe', email: 'john@example.com' });
await newUser.save();

// Find documents
const users = await User.find({ status: 'active' });
```

**Key Points:**
- Models map to MongoDB collections
- Provide static and instance methods
- Support query building with chaining
- Enable data population across collections

### Validators
Mongoose provides built-in and custom validators to ensure data integrity.

```javascript
const productSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  price: {
    type: Number,
    required: true,
    min: [0, 'Price cannot be negative'],
    validate: {
      validator: function(v) {
        return v % 0.01 === 0; // Validate two decimal places
      },
      message: 'Price must have at most two decimal places'
    }
  },
  category: {
    type: String,
    enum: {
      values: ['electronics', 'clothing', 'books'],
      message: '{VALUE} is not a valid category'
    }
  }
});
```

**Validation Types:**
1. **Built-in validators:** required, min, max, enum, match, maxlength, minlength
2. **Custom validators:** Synchronous and asynchronous
3. **Schema-level validation:** validate() method on schemas

### Indexing
Indexes improve query performance by creating efficient data structures for lookups.

```javascript
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  orderDate: { type: Date, index: true },
  totalAmount: Number,
  status: String
});

// Compound index
orderSchema.index({ userId: 1, orderDate: -1 });

// Text index for search
orderSchema.index({ productName: 'text', description: 'text' });

// Unique compound index
orderSchema.index({ email: 1, companyId: 1 }, { unique: true });
```

**Index Types:**
- **Single field:** Index on one field
- **Compound:** Index on multiple fields
- **Multikey:** Index on array fields
- **Text:** For text search
- **Geospatial:** For location-based queries
- **Hashed:** For hash-based sharding

### Aggregation
Aggregation pipeline processes data records and returns computed results.

```javascript
const salesReport = await Order.aggregate([
  // Stage 1: Match documents
  { $match: { 
    orderDate: { $gte: startDate, $lte: endDate },
    status: 'completed'
  }},
  
  // Stage 2: Unwind array (flatten order items)
  { $unwind: '$items' },
  
  // Stage 3: Group by product
  { $group: {
    _id: '$items.productId',
    totalQuantity: { $sum: '$items.quantity' },
    totalRevenue: { $sum: { $multiply: ['$items.price', '$items.quantity'] } },
    avgPrice: { $avg: '$items.price' }
  }},
  
  // Stage 4: Lookup product details
  { $lookup: {
    from: 'products',
    localField: '_id',
    foreignField: '_id',
    as: 'productDetails'
  }},
  
  // Stage 5: Sort by revenue
  { $sort: { totalRevenue: -1 } },
  
  // Stage 6: Limit results
  { $limit: 10 }
]);
```

**Common Aggregation Stages:**
- `$match`: Filter documents
- `$group`: Group by specified key
- `$sort`: Sort documents
- `$project`: Reshape documents
- `$lookup`: Join collections
- `$unwind`: Flatten array fields
- `$facet`: Multiple pipelines

### Transactions
MongoDB transactions ensure ACID properties across multiple operations.

```javascript
const session = await mongoose.startSession();

try {
  session.startTransaction();
  
  // Transfer money between accounts
  const fromAccount = await Account.findOneAndUpdate(
    { _id: fromId, balance: { $gte: amount } },
    { $inc: { balance: -amount } },
    { session, new: true }
  );
  
  if (!fromAccount) {
    throw new Error('Insufficient funds');
  }
  
  await Account.findOneAndUpdate(
    { _id: toId },
    { $inc: { balance: amount } },
    { session }
  );
  
  // Create transaction record
  await Transaction.create([{
    from: fromId,
    to: toId,
    amount,
    type: 'transfer',
    timestamp: new Date()
  }], { session });
  
  await session.commitTransaction();
} catch (error) {
  await session.abortTransaction();
  throw error;
} finally {
  session.endSession();
}
```

**Key Considerations:**
- Transactions require replica set deployment
- Maximum transaction lifetime: 60 seconds
- Operations must be on the same session
- Use retry logic for transient errors

### Populating Relations
Population replaces specified paths with documents from other collections.

```javascript
const blogPostSchema = new mongoose.Schema({
  title: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
  tags: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Tag' }]
});

// Single population
const post = await Post.findById(postId)
  .populate('author', 'name email avatar') // Only select specific fields
  .populate({
    path: 'comments',
    options: { sort: { createdAt: -1 }, limit: 10 },
    populate: {
      path: 'author',
      select: 'name avatar'
    }
  })
  .populate('tags');

// Virtual populate (for reverse relationships)
blogPostSchema.virtual('likes', {
  ref: 'Like',
  localField: '_id',
  foreignField: 'postId',
  count: true // Returns count instead of documents
});

// Multiple path population
const posts = await Post.find()
  .populate([
    { path: 'author', select: 'name' },
    { path: 'comments', populate: { path: 'author' } }
  ]);
```

### Optimizing Queries
Performance optimization techniques for MongoDB queries.

```javascript
// 1. Use Projection to Select Only Needed Fields
const users = await User.find({ status: 'active' }, 'name email');

// 2. Use Lean for Read-Only Operations (returns plain JS objects)
const posts = await Post.find().lean();

// 3. Implement Pagination
const page = 1;
const limit = 20;
const skip = (page - 1) * limit;
const results = await Product.find()
  .skip(skip)
  .limit(limit)
  .sort({ createdAt: -1 });

// 4. Use Covered Queries (queries satisfied entirely by indexes)
// Create compound index covering query
productSchema.index({ category: 1, price: 1, name: 1 });

// 5. Batch Operations
await Product.bulkWrite([
  { updateOne: { filter: { _id: id1 }, update: { $set: { price: 99 } } } },
  { updateOne: { filter: { _id: id2 }, update: { $set: { price: 149 } } } }
]);

// 6. Use Explain() to Analyze Queries
const explanation = await User.find({ email: 'test@example.com' })
  .explain('executionStats');
```

---

## PostgreSQL with Prisma/Sequelize/Knex

### Prisma Schema
Prisma Schema Language (PSL) defines database models and relations.

```prisma
// schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String?
  posts     Post[]
  profile   Profile?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  @@index([email])
  @@map("users")
}

model Post {
  id        Int      @id @default(autoincrement())
  title     String
  content   String?
  published Boolean  @default(false)
  author    User     @relation(fields: [authorId], references: [id])
  authorId  Int
  categories Category[]
  comments  Comment[]
  
  @@unique([title, authorId])
}

model Profile {
  id     Int    @id @default(autoincrement())
  bio    String?
  user   User   @relation(fields: [userId], references: [id])
  userId Int    @unique
  
  @@map("profiles")
}
```

### Relations, Enums, Middlewares
**Relations:**
- **1:1:** User ↔ Profile
- **1:N:** User ↔ Post
- **N:M:** Post ↔ Category (via join table)

**Enums:**
```prisma
enum UserRole {
  USER
  ADMIN
  MODERATOR
}

enum PostStatus {
  DRAFT
  PUBLISHED
  ARCHIVED
}

model User {
  id   Int      @id @default(autoincrement())
  role UserRole @default(USER)
}
```

**Middlewares (Prisma):**
```typescript
// Prisma Client Extensions
const prisma = new PrismaClient().$extends({
  query: {
    user: {
      async create({ args, query }) {
        // Validate before create
        if (!isValidEmail(args.data.email)) {
          throw new Error('Invalid email');
        }
        return query(args);
      },
      async findMany({ args, query }) {
        // Add soft delete filter
        args.where = { ...args.where, deletedAt: null };
        return query(args);
      }
    }
  }
});

// Soft delete middleware
prisma.$use(async (params, next) => {
  if (params.action === 'delete') {
    params.action = 'update';
    params.args['data'] = { deletedAt: new Date() };
  }
  return next(params);
});
```

### Joins
**Prisma (Implicit joins via relations):**
```typescript
// Include related data
const userWithPosts = await prisma.user.findUnique({
  where: { id: 1 },
  include: {
    posts: {
      where: { published: true },
      include: {
        categories: true,
        comments: {
          include: {
            author: true
          }
        }
      }
    },
    profile: true
  }
});

// Multiple relations with filtering
const postsWithComments = await prisma.post.findMany({
  include: {
    author: {
      select: { name: true, email: true }
    },
    comments: {
      where: { approved: true },
      orderBy: { createdAt: 'desc' },
      take: 5
    },
    _count: {
      select: { comments: true, likes: true }
    }
  }
});
```

**Sequelize (Explicit joins):**
```javascript
const users = await User.findAll({
  include: [
    {
      model: Post,
      include: [
        {
          model: Comment,
          include: [User]
        },
        Category
      ]
    },
    Profile
  ],
  where: {
    '$Posts.comments.approved$': true
  }
});
```

**Knex (Raw SQL joins):**
```javascript
const results = await knex('users')
  .join('posts', 'users.id', 'posts.user_id')
  .leftJoin('comments', 'posts.id', 'comments.post_id')
  .select(
    'users.name',
    'posts.title',
    knex.raw('COUNT(comments.id) as comment_count')
  )
  .groupBy('users.id', 'posts.id')
  .where('posts.published', true);
```

### Transactions
**Prisma Transactions:**
```typescript
// Interactive transactions
const result = await prisma.$transaction(async (tx) => {
  // 1. Debit from account
  const fromAccount = await tx.account.update({
    where: { id: fromId, balance: { gte: amount } },
    data: { balance: { decrement: amount } }
  });
  
  if (fromAccount.balance < 0) {
    throw new Error('Insufficient funds');
  }
  
  // 2. Credit to account
  await tx.account.update({
    where: { id: toId },
    data: { balance: { increment: amount } }
  });
  
  // 3. Create transaction record
  return tx.transaction.create({
    data: {
      fromAccountId: fromId,
      toAccountId: toId,
      amount,
      type: 'TRANSFER'
    }
  });
}, {
  maxWait: 5000,
  timeout: 10000
});

// Batch transactions
const [updateUser, createPost] = await prisma.$transaction([
  prisma.user.update({
    where: { id: 1 },
    data: { name: 'Updated' }
  }),
  prisma.post.create({
    data: {
      title: 'New Post',
      authorId: 1
    }
  })
]);
```

**Sequelize Transactions:**
```javascript
const transaction = await sequelize.transaction();

try {
  const user = await User.create({
    username: 'john',
    email: 'john@example.com'
  }, { transaction });
  
  await Profile.create({
    userId: user.id,
    bio: 'Developer'
  }, { transaction });
  
  await transaction.commit();
} catch (error) {
  await transaction.rollback();
  throw error;
}
```

### Raw SQL Queries
**Prisma Raw Queries:**
```typescript
// Parameterized queries (safe from SQL injection)
const users = await prisma.$queryRaw`
  SELECT u.*, COUNT(p.id) as post_count
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id
  WHERE u.created_at > ${startDate}
  GROUP BY u.id
  HAVING COUNT(p.id) > 5
  ORDER BY post_count DESC
`;

// Dynamic raw queries
const searchTerm = 'john';
const results = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE name LIKE ${'%' + searchTerm + '%'}`
);

// Execute stored procedures
await prisma.$executeRaw`CALL cleanup_old_records(${days})`;
```

**Knex Raw Queries:**
```javascript
// Complex queries with Knex
const report = await knex.raw(`
  WITH monthly_sales AS (
    SELECT 
      DATE_TRUNC('month', order_date) as month,
      product_id,
      SUM(quantity) as total_quantity,
      SUM(quantity * price) as total_revenue
    FROM orders
    WHERE order_date >= ? AND order_date <= ?
    GROUP BY DATE_TRUNC('month', order_date), product_id
  )
  SELECT 
    ms.month,
    p.name as product_name,
    ms.total_quantity,
    ms.total_revenue,
    RANK() OVER (PARTITION BY ms.month ORDER BY ms.total_revenue DESC) as rank
  FROM monthly_sales ms
  JOIN products p ON ms.product_id = p.id
  ORDER BY ms.month DESC, rank ASC
`, [startDate, endDate]);
```

### Connection Pooling
**Prisma Connection Pooling:**
```env
# .env
DATABASE_URL="postgresql://user:password@localhost:5432/dbname?connection_limit=20&pool_timeout=10"
```

**Pool Configuration:**
```typescript
// Custom Prisma client with pool settings
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
  datasources: {
    db: {
      url: process.env.DATABASE_URL + '&connection_limit=25&pool_timeout=5'
    }
  }
});

// Connection pool monitoring
prisma.$on('query', (e) => {
  console.log('Query: ', e.query);
  console.log('Duration: ', e.duration, 'ms');
});
```

**Knex Pool Configuration:**
```javascript
const knex = require('knex')({
  client: 'pg',
  connection: {
    host: '127.0.0.1',
    user: 'your_database_user',
    password: 'your_database_password',
    database: 'myapp_test'
  },
  pool: {
    min: 2,
    max: 20,
    acquireTimeoutMillis: 30000,
    createTimeoutMillis: 30000,
    destroyTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 100
  }
});
```

---

## Redis

### Caching
Redis as a caching layer to reduce database load.

```javascript
const redis = require('redis');
const client = redis.createClient({
  url: 'redis://localhost:6379',
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 50, 2000)
  }
});

// Cache patterns
class CacheService {
  async getUser(userId) {
    const cacheKey = `user:${userId}`;
    
    // Try cache first
    const cached = await client.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Cache miss - get from DB
    const user = await db.user.findUnique({ where: { id: userId } });
    
    // Set cache with TTL
    if (user) {
      await client.setEx(cacheKey, 3600, JSON.stringify(user));
    }
    
    return user;
  }
  
  async getProductsWithCache(category, page = 1, limit = 20) {
    const cacheKey = `products:${category}:${page}:${limit}`;
    
    // Using Redlock for distributed lock
    const lock = await redlock.acquire([`lock:${cacheKey}`], 1000);
    
    try {
      const cached = await client.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
      
      // Cache stampede protection
      const products = await db.product.findMany({
        where: { category },
        skip: (page - 1) * limit,
        take: limit
      });
      
      // Set cache with shorter TTL for paginated data
      await client.setEx(cacheKey, 300, JSON.stringify(products));
      
      // Also cache individual products
      products.forEach(product => {
        client.setEx(`product:${product.id}`, 3600, JSON.stringify(product));
      });
      
      return products;
    } finally {
      await lock.release();
    }
  }
}
```

**Cache Strategies:**
1. **Cache-Aside (Lazy Loading):** Load on miss
2. **Write-Through:** Write to cache and DB simultaneously
3. **Write-Behind:** Write to cache, async to DB
4. **Refresh-Ahead:** Proactively refresh before expiry

### Rate Limiting
Implement rate limiting using Redis.

```javascript
class RateLimiter {
  constructor(redisClient) {
    this.client = redisClient;
  }
  
  async isRateLimited(key, limit, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Use sorted set for sliding window
    const pipeline = this.client.multi();
    
    // Remove old entries
    pipeline.zremrangebyscore(key, 0, windowStart);
    
    // Count current requests
    pipeline.zcard(key);
    
    // Add current request
    pipeline.zadd(key, now, `${now}-${Math.random()}`);
    
    // Set expiry
    pipeline.expire(key, Math.ceil(windowMs / 1000));
    
    const results = await pipeline.exec();
    const currentCount = results[1][1]; // zcard result
    
    return currentCount >= limit;
  }
  
  async fixedWindowRateLimit(key, limit, windowSeconds) {
    const current = await this.client.incr(key);
    
    if (current === 1) {
      await this.client.expire(key, windowSeconds);
    }
    
    return current > limit;
  }
  
  async tokenBucketRateLimit(key, capacity, refillRate, tokens = 1) {
    const now = Date.now() / 1000;
    const bucketKey = `${key}:bucket`;
    
    const pipeline = this.client.multi();
    
    // Get current bucket state
    pipeline.hgetall(bucketKey);
    
    const results = await pipeline.exec();
    const bucket = results[0][1] || { tokens: capacity, lastRefill: now };
    
    const elapsed = now - parseFloat(bucket.lastRefill);
    const refillAmount = elapsed * refillRate;
    const currentTokens = Math.min(
      capacity,
      parseFloat(bucket.tokens) + refillAmount
    );
    
    if (currentTokens < tokens) {
      return true; // Rate limited
    }
    
    // Consume tokens
    await this.client.hset(bucketKey, {
      tokens: currentTokens - tokens,
      lastRefill: now
    });
    
    return false;
  }
}
```

### Blacklisting Tokens
Blacklist JWT tokens using Redis for immediate invalidation.

```javascript
class TokenBlacklist {
  constructor(redisClient) {
    this.client = redisClient;
  }
  
  async blacklistToken(token, expiresIn) {
    const tokenId = this.extractTokenId(token);
    const expiry = Math.ceil(expiresIn / 1000);
    
    await this.client.setEx(`blacklist:${tokenId}`, expiry, '1');
    
    // Also store in set for user-specific blacklisting
    const userId = this.extractUserId(token);
    await this.client.sAdd(`user:${userId}:blacklisted_tokens`, tokenId);
  }
  
  async isBlacklisted(token) {
    const tokenId = this.extractTokenId(token);
    const result = await this.client.exists(`blacklist:${tokenId}`);
    return result === 1;
  }
  
  async blacklistAllUserTokens(userId) {
    const tokensKey = `user:${userId}:tokens`;
    const blacklistKey = `user:${userId}:blacklisted_tokens`;
    
    const tokens = await this.client.sMembers(tokensKey);
    
    const pipeline = this.client.multi();
    
    tokens.forEach(tokenId => {
      pipeline.setEx(`blacklist:${tokenId}`, 86400, '1');
      pipeline.sAdd(blacklistKey, tokenId);
    });
    
    await pipeline.exec();
  }
  
  async cleanupExpiredBlacklists() {
    // Use Redis SCAN to find and delete expired blacklists
    let cursor = '0';
    do {
      const result = await this.client.scan(
        cursor,
        'MATCH', 'blacklist:*',
        'COUNT', 100
      );
      cursor = result[0];
      const keys = result[1];
      
      for (const key of keys) {
        const ttl = await this.client.ttl(key);
        if (ttl < 0) {
          await this.client.del(key);
        }
      }
    } while (cursor !== '0');
  }
}
```

### Pub/Sub for Notifications
Redis Pub/Sub for real-time notifications and messaging.

```javascript
class NotificationSystem {
  constructor() {
    this.publisher = redis.createClient({ url: 'redis://localhost:6379' });
    this.subscriber = redis.createClient({ url: 'redis://localhost:6379' });
    
    this.publisher.connect();
    this.subscriber.connect();
    
    this.channels = new Map();
  }
  
  async subscribe(userId, callback) {
    const channel = `notifications:${userId}`;
    
    if (!this.channels.has(channel)) {
      await this.subscriber.subscribe(channel, (message) => {
        const handlers = this.channels.get(channel) || [];
        handlers.forEach(handler => handler(JSON.parse(message)));
      });
      this.channels.set(channel, []);
    }
    
    this.channels.get(channel).push(callback);
    
    return () => {
      const handlers = this.channels.get(channel);
      const index = handlers.indexOf(callback);
      if (index > -1) {
        handlers.splice(index, 1);
      }
      if (handlers.length === 0) {
        this.subscriber.unsubscribe(channel);
        this.channels.delete(channel);
      }
    };
  }
  
  async publish(userId, notification) {
    const channel = `notifications:${userId}`;
    await this.publisher.publish(channel, JSON.stringify({
      id: uuidv4(),
      type: notification.type,
      data: notification.data,
      timestamp: new Date().toISOString(),
      read: false
    }));
  }
  
  async publishToMultiple(userIds, notification) {
    const pipeline = this.publisher.multi();
    
    userIds.forEach(userId => {
      const channel = `notifications:${userId}`;
      pipeline.publish(channel, JSON.stringify({
        id: uuidv4(),
        type: notification.type,
        data: notification.data,
        timestamp: new Date().toISOString()
      }));
    });
    
    await pipeline.exec();
  }
  
  async publishToPattern(pattern, notification) {
    // Using Redis PSUBSCRIBE for pattern-based subscriptions
    const patternChannel = `notifications:${pattern}`;
    await this.publisher.publish(patternChannel, JSON.stringify(notification));
  }
}
```

---

## Interview Questions

### MongoDB/Mongoose Questions

**Junior to Mid-Level:**
1. What's the difference between MongoDB and SQL databases?
2. How do you define a schema in Mongoose?
3. What are Mongoose middleware and types?
4. How do you perform basic CRUD operations?
5. What is population and when would you use it?

**Senior Level:**
1. How would you design a schema for a social media platform with users, posts, comments, and likes?
2. Explain the difference between embedding and referencing in MongoDB. When would you choose each?
3. How do you handle database migrations in MongoDB?
4. Describe how you would optimize a slow aggregation pipeline.
5. How would you implement full-text search in MongoDB?

**Architect Level:**
1. How would you design a sharding strategy for a multi-tenant SaaS application?
2. Explain how you would handle schema evolution in a microservices architecture.
3. Describe your approach to implementing ACID transactions in a distributed MongoDB cluster.
4. How would you design a change data capture system using MongoDB change streams?
5. Explain how to implement data archiving and retention policies.

### PostgreSQL/Prisma Questions

**Junior to Mid-Level:**
1. What are the differences between Prisma, Sequelize, and Knex?
2. How do you define relationships in Prisma schema?
3. What is connection pooling and why is it important?
4. How do you handle database migrations?
5. What are prepared statements and why use them?

**Senior Level:**
1. How would you design a database schema for an e-commerce platform with products, orders, and inventory?
2. Explain how you would implement row-level security in PostgreSQL.
3. Describe your approach to database performance tuning.
4. How would you handle database failover and replication?
5. Explain the trade-offs between different isolation levels in transactions.

**Architect Level:**
1. Design a data partitioning strategy for a table with billions of rows.
2. How would you implement zero-downtime database migrations?
3. Describe your approach to database monitoring and alerting.
4. How would you design a multi-region database architecture?
5. Explain how to implement GDPR compliance in database design.

### Redis Questions

**Junior to Mid-Level:**
1. What are common use cases for Redis?
2. Explain Redis data types and when to use each.
3. How do you implement caching with Redis?
4. What is Redis persistence and different methods?
5. How do you handle Redis connection failures?

**Senior Level:**
1. Design a distributed caching strategy using Redis Cluster.
2. How would you implement leaderboard functionality with real-time updates?
3. Explain Redis memory optimization techniques.
4. How would you implement session clustering with Redis?
5. Describe Redis Sentinel vs Redis Cluster for high availability.

**Architect Level:**
1. Design a real-time analytics system using Redis Streams.
2. How would you implement a distributed rate limiter across multiple services?
3. Explain Redis as a primary database vs cache-only.
4. Design a message queue system using Redis.
5. How would you implement disaster recovery for Redis?

---

## Real-World Scenarios

### Scenario 1: E-commerce Platform

**Problem:** An e-commerce site experiences slow performance during flash sales. The database struggles with:
- High concurrent orders
- Real-time inventory updates
- Personalized recommendations
- Order tracking updates

**Solution:**
```javascript
// 1. Redis caching for product catalog
const getProductWithCache = async (productId) => {
  const cacheKey = `product:${productId}`;
  const cached = await redis.get(cacheKey);
  
  if (cached) return JSON.parse(cached);
  
  const product = await prisma.product.findUnique({
    where: { id: productId },
    include: { inventory: true }
  });
  
  // Cache with 5-minute TTL, shorter during flash sales
  const ttl = isFlashSale ? 30 : 300;
  await redis.setEx(cacheKey, ttl, JSON.stringify(product));
  
  return product;
};

// 2. Redis for inventory reservation
const reserveInventory = async (productId, quantity) => {
  const lockKey = `lock:inventory:${productId}`;
  const inventoryKey = `inventory:${productId}`;
  
  // Use Redlock for distributed lock
  const lock = await redlock.acquire([lockKey], 5000);
  
  try {
    const current = await redis.get(inventoryKey);
    const available = current ? parseInt(current) : await getDbInventory(productId);
    
    if (available < quantity) {
      throw new Error('Insufficient inventory');
    }
    
    // Update Redis cache
    await redis.set(inventoryKey, available - quantity);
    
    // Async update to database
    queue.inventoryUpdate.add({
      productId,
      quantity: -quantity
    });
    
    return true;
  } finally {
    await lock.release();
  }
};

// 3. MongoDB for order history (schema)
const orderSchema = new mongoose.Schema({
  orderId: { type: String, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  items: [{
    productId: mongoose.Schema.Types.ObjectId,
    quantity: Number,
    price: Number,
    variant: String
  }],
  total: Number,
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    index: true
  },
  paymentStatus: String,
  shippingAddress: {
    type: mongoose.Schema.Types.Mixed // Flexible schema for addresses
  },
  timeline: [{
    status: String,
    timestamp: Date,
    description: String
  }],
  metadata: mongoose.Schema.Types.Mixed // For additional data
}, { timestamps: true });

// Create compound indexes
orderSchema.index({ userId: 1, createdAt: -1 });
orderSchema.index({ status: 1, createdAt: -1 });
orderSchema.index({ 'items.productId': 1 });

// 4. PostgreSQL for transactional data
model Order {
  id        String   @id @default(cuid())
  userId    String
  total     Decimal  @db.Decimal(10, 2)
  status    OrderStatus
  createdAt DateTime @default(now())
  
  @@index([userId])
  @@index([createdAt])
}

model OrderItem {
  id        String  @id @default(cuid())
  orderId   String
  productId String
  quantity  Int
  price     Decimal @db.Decimal(10, 2)
  
  @@unique([orderId, productId])
  @@index([productId])
}
```

### Scenario 2: Real-time Analytics Dashboard

**Problem:** Building a dashboard that shows real-time metrics for a SaaS platform with:
- 100K concurrent users
- Sub-second latency requirements
- Historical data analysis
- Custom segmentation

**Solution:**
```javascript
// 1. Redis for real-time counters
class RealTimeMetrics {
  async trackEvent(userId, eventType, metadata = {}) {
    const timestamp = Date.now();
    const pipeline = redis.pipeline();
    
    // Real-time counters
    pipeline.incr(`stats:${eventType}:total`);
    pipeline.incr(`stats:${eventType}:${this.getMinuteKey()}`);
    
    // User session tracking
    pipeline.sAdd(`user:${userId}:events`, `${timestamp}:${eventType}`);
    pipeline.expire(`user:${userId}:events`, 86400);
    
    // Time-series data
    pipeline.zAdd(`timeseries:${eventType}`, {
      score: timestamp,
      value: JSON.stringify({ userId, ...metadata })
    });
    
    // Trim old data
    pipeline.zRemRangeByScore(
      `timeseries:${eventType}`,
      0,
      timestamp - (7 * 24 * 60 * 60 * 1000)
    );
    
    await pipeline.exec();
    
    // Send to analytics queue for processing
    await analyticsQueue.add({
      userId,
      eventType,
      timestamp,
      metadata
    });
  }
  
  async getMetrics(eventType, duration = 'hour') {
    const now = Date.now();
    let windowStart;
    
    switch(duration) {
      case 'minute': windowStart = now - 60000; break;
      case 'hour': windowStart = now - 3600000; break;
      case 'day': windowStart = now - 86400000; break;
    }
    
    // Get from Redis sorted set
    const events = await redis.zRangeByScore(
      `timeseries:${eventType}`,
      windowStart,
      now
    );
    
    return {
      total: events.length,
      events: events.map(e => JSON.parse(e))
    };
  }
}

// 2. MongoDB for aggregated analytics
const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true, index: true },
  metric: { type: String, required: true, index: true },
  dimensions: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  values: {
    count: Number,
    sum: Number,
    avg: Number,
    min: Number,
    max: Number,
    // Percentiles for performance metrics
    p50: Number,
    p95: Number,
    p99: Number
  },
  // Pre-aggregated for common queries
  breakdowns: [{
    dimension: String,
    value: String,
    count: Number
  }]
}, {
  // Time series collection options
  timeseries: {
    timeField: 'date',
    metaField: 'metric',
    granularity: 'hours'
  }
});

// 3. PostgreSQL for user segmentation
const createSegment = async (segmentRules) => {
  // Use materialized view for complex segments
  await prisma.$executeRaw`
    CREATE MATERIALIZED VIEW IF NOT EXISTS user_segments AS
    SELECT 
      u.id,
      u.created_at,
      COUNT(DISTINCT o.id) as order_count,
      SUM(o.total) as lifetime_value,
      MAX(o.created_at) as last_order_date
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    GROUP BY u.id
  `;
  
  // Refresh materialized view
  await prisma.$executeRaw`REFRESH MATERIALIZED VIEW CONCURRENTLY user_segments`;
  
  // Query segment
  const segmentUsers = await prisma.$queryRaw`
    SELECT us.* 
    FROM user_segments us
    WHERE 
      us.order_count >= ${segmentRules.minOrders}
      AND us.lifetime_value >= ${segmentRules.minLTV}
      AND us.last_order_date >= NOW() - INTERVAL '${segmentRules.recencyDays} days'
  `;
  
  return segmentUsers;
};
```

### Scenario 3: Multi-tenant SaaS Application

**Problem:** Building a SaaS platform that needs:
- Data isolation between tenants
- Scalable database architecture
- Tenant-specific customizations
- Cross-tenant analytics (for admin)

**Solution:**
```javascript
// 1. PostgreSQL with tenant isolation
// Option A: Schema per tenant
const getTenantSchema = (tenantId) => {
  return prisma.$extends({
    name: `tenant-${tenantId}`,
    query: {
      $allModels: {
        async findMany({ args, query }) {
          args.where = { ...args.where, tenantId };
          return query(args);
        },
        async create({ args, query }) {
          args.data = { ...args.data, tenantId };
          return query(args);
        }
      }
    }
  });
};

// Option B: Row-level security
await prisma.$executeRaw`
  CREATE POLICY tenant_isolation_policy ON accounts
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
  
  ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
`;

// 2. MongoDB for tenant-specific flexible data
const tenantSchema = new mongoose.Schema({
  tenantId: { type: String, required: true, index: true },
  collectionName: String,
  data: mongoose.Schema.Types.Mixed,
  // Support for custom fields
  customFields: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
}, {
  // Dynamic schema based on tenant
  strict: false
});

// Create tenant-specific indexes
tenantSchema.index({ tenantId: 1, 'data.status': 1 });
tenantSchema.index({ tenantId: 1, 'data.createdAt': -1 });

// 3. Redis for tenant caching with isolation
class TenantAwareCache {
  constructor(tenantId) {
    this.tenantId = tenantId;
    this.prefix = `tenant:${tenantId}:`;
  }
  
  async get(key) {
    return redis.get(this.prefix + key);
  }
  
  async set(key, value, ttl) {
    return redis.setEx(this.prefix + key, ttl, value);
  }
  
  async clear() {
    // Delete all keys for this tenant
    const pattern = this.prefix + '*';
    let cursor = '0';
    
    do {
      const result = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = result[0];
      const keys = result[1];
      
      if (keys.length > 0) {
        await redis.del(keys);
      }
    } while (cursor !== '0');
  }
}

// 4. Connection pooling with tenant context
class TenantConnectionPool {
  constructor() {
    this.pools = new Map();
  }
  
  getPool(tenantId) {
    if (!this.pools.has(tenantId)) {
      const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        // Tenant-specific connection settings
        application_name: `tenant-${tenantId}`
      });
      
      // Set tenant context on connection
      pool.on('connect', (client) => {
        client.query(`SET app.current_tenant = '${tenantId}'`);
      });
      
      this.pools.set(tenantId, pool);
    }
    
    return this.pools.get(tenantId);
  }
}
```

### Scenario 4: Financial Trading Platform

**Problem:** High-frequency trading platform requiring:
- Sub-millisecond latency
- ACID compliance for transactions
- Real-time order matching
- Audit trail and compliance logging

**Solution:**
```javascript
// 1. PostgreSQL for transactional integrity
class TradingEngine {
  async placeOrder(order) {
    // Use serializable isolation level for highest consistency
    return prisma.$transaction(async (tx) => {
      // Check account balance
      const account = await tx.account.findUnique({
        where: { id: order.accountId },
        select: { balance: true, creditLimit: true }
      });
      
      const requiredAmount = order.quantity * order.price;
      if (account.balance + account.creditLimit < requiredAmount) {
        throw new Error('Insufficient funds');
      }
      
      // Create order with unique constraint
      const createdOrder = await tx.order.create({
        data: {
          ...order,
          status: 'PENDING',
          version: 1
        }
      });
      
      // Reserve funds
      await tx.account.update({
        where: { id: order.accountId },
        data: {
          balance: { decrement: requiredAmount },
          reservedBalance: { increment: requiredAmount }
        }
      });
      
      // Publish to order matching engine
      await redis.publish('orders:new', JSON.stringify(createdOrder));
      
      return createdOrder;
    }, {
      isolationLevel: 'Serializable',
      timeout: 10000
    });
  }
}

// 2. Redis for real-time order book
class OrderBook {
  constructor(symbol) {
    this.bidsKey = `orderbook:${symbol}:bids`;
    this.asksKey = `orderbook:${symbol}:asks`;
  }
  
  async addOrder(order) {
    const score = order.price;
    const value = JSON.stringify(order);
    
    if (order.side === 'BUY') {
      await redis.zAdd(this.bidsKey, { score, value });
    } else {
      await redis.zAdd(this.asksKey, { score, value });
    }
    
    // Trigger matching
    this.matchOrders();
  }
  
  async matchOrders() {
    // Get best bid and ask
    const [bestBid] = await redis.zRange(this.bidsKey, -1, -1, { WITHSCORES: true });
    const [bestAsk] = await redis.zRange(this.asksKey, 0, 0, { WITHSCORES: true });
    
    if (!bestBid || !bestAsk) return;
    
    const bid = JSON.parse(bestBid[0]);
    const ask = JSON.parse(bestAsk[0]);
    
    if (bid.price >= ask.price) {
      // Execute trade
      await this.executeTrade(bid, ask);
      
      // Remove matched orders
      await redis.zRem(this.bidsKey, JSON.stringify(bid));
      await redis.zRem(this.asksKey, JSON.stringify(ask));
    }
  }
}

// 3. MongoDB for audit logging
const auditLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now, index: true },
  userId: { type: String, index: true },
  action: String,
  entityType: String,
  entityId: String,
  changes: [{
    field: String,
    oldValue: mongoose.Schema.Types.Mixed,
    newValue: mongoose.Schema.Types.Mixed
  }],
  ipAddress: String,
  userAgent: String,
  metadata: mongoose.Schema.Types.Mixed
}, {
  // Capped collection for audit logs
  capped: { size: 1000000000, max: 10000000 } // 1GB, 10M documents max
});

// 4. Redis for real-time market data
class MarketDataService {
  constructor() {
    this.streams = new Map();
  }
  
  async publishQuote(symbol, quote) {
    const streamKey = `marketdata:${symbol}:quotes`;
    
    // Add to Redis stream
    await redis.xAdd(streamKey, '*', {
      bid: quote.bid,
      ask: quote.ask,
      volume: quote.volume,
      timestamp: Date.now()
    });
    
    // Trim old entries
    await redis.xTrim(streamKey, 'MAXLEN', '~', 1000);
    
    // Publish to WebSocket clients
    await redis.publish(`quotes:${symbol}`, JSON.stringify(quote));
  }
  
  async getHistoricalQuotes(symbol, start, end) {
    const streamKey = `marketdata:${symbol}:quotes`;
    return redis.xRange(streamKey, start, end);
  }
}
```

This comprehensive guide covers the essential aspects of working with databases in Node.js applications, from basic concepts to advanced architectures suitable for senior developers and architects.