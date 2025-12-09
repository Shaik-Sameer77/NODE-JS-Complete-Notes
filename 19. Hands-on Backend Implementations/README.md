# Backend Implementation Guide

## Table of Contents
1. [Authentication System](#authentication-system)
2. [Role-based Permissions](#role-based-permissions)
3. [CRUD with PostgreSQL & MongoDB](#crud-with-postgresql--mongodb)
4. [File Uploads](#file-uploads)
5. [Real-time Chat](#real-time-chat)
6. [Online/Offline Status Tracker](#onlineoffline-status-tracker)
7. [Payment Gateway](#payment-gateway)
8. [Email Service](#email-service)
9. [Refresh Token Rotation](#refresh-token-rotation)
10. [Background Jobs](#background-jobs)
11. [Cloud Storage System](#cloud-storage-system)
12. [Multi-tenant Architecture](#multi-tenant-architecture)

---

## 1. Authentication System <a name="authentication-system"></a>

### Implementation
```javascript
// JWT-based authentication with bcrypt hashing
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

class AuthService {
  async register(userData) {
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    const user = await User.create({
      ...userData,
      password: hashedPassword
    });
    
    const tokens = this.generateTokens(user);
    await this.storeRefreshToken(user.id, tokens.refreshToken);
    
    return { user, tokens };
  }

  async login(email, password) {
    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error('Invalid credentials');
    
    const tokens = this.generateTokens(user);
    await this.storeRefreshToken(user.id, tokens.refreshToken);
    
    return { user, tokens };
  }

  generateTokens(user) {
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );
    
    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );
    
    return { accessToken, refreshToken };
  }

  async verifyToken(token, isRefresh = false) {
    const secret = isRefresh 
      ? process.env.JWT_REFRESH_SECRET 
      : process.env.JWT_ACCESS_SECRET;
    
    return jwt.verify(token, secret);
  }
}
```

### Interview Questions
**Technical:**
1. Explain the difference between session-based and token-based authentication.
2. How do you securely store passwords in a database?
3. What are JWT tokens and what are their advantages/disadvantages?
4. How would you implement rate limiting on authentication endpoints?
5. Explain OAuth 2.0 flow and when to use it.

**Scenario-based:**
1. Your authentication system is experiencing a high rate of failed login attempts. How would you investigate and mitigate this?
2. How would you handle authentication in a microservices architecture?
3. A user reports their account was hacked. What steps would you take?
4. How would you implement single sign-on (SSO) across multiple applications?
5. Your JWT tokens are being stolen via XSS. What mitigation strategies would you implement?

---

## 2. Role-based Permissions <a name="role-based-permissions"></a>

### Implementation
```javascript
// RBAC with permission hierarchy
class RBACService {
  constructor() {
    this.roles = {
      super_admin: ['*'],
      admin: ['users:read', 'users:write', 'content:*'],
      editor: ['content:read', 'content:write'],
      user: ['profile:read', 'profile:write']
    };
    
    this.permissions = new Map();
    Object.entries(this.roles).forEach(([role, perms]) => {
      this.permissions.set(role, new Set(perms));
    });
  }

  hasPermission(userRole, requiredPermission) {
    if (userRole === 'super_admin') return true;
    
    const userPermissions = this.permissions.get(userRole);
    if (!userPermissions) return false;
    
    // Check exact permission
    if (userPermissions.has(requiredPermission)) return true;
    
    // Check wildcard permissions
    const [resource, action] = requiredPermission.split(':');
    return userPermissions.has(`${resource}:*`) || 
           userPermissions.has('*');
  }

  // Dynamic role assignment with scopes
  async assignRole(userId, role, resourceScope = null) {
    await UserRole.create({
      userId,
      role,
      resourceScope, // e.g., 'team:123' or 'project:456'
      createdAt: new Date()
    });
  }

  // Permission check with resource scope
  async can(userId, action, resource, resourceId = null) {
    const userRoles = await UserRole.findAll({ where: { userId } });
    
    return userRoles.some(userRole => {
      const permission = resourceId 
        ? `${resource}:${action}:${resourceId}`
        : `${resource}:${action}`;
      
      return this.hasPermission(userRole.role, permission) &&
             (!userRole.resourceScope || 
              this.checkScope(userRole.resourceScope, resource, resourceId));
    });
  }
}

// Middleware
const authorize = (action, resource) => {
  return async (req, res, next) => {
    const canAccess = await rbacService.can(
      req.user.id, 
      action, 
      resource, 
      req.params.id
    );
    
    if (!canAccess) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
};
```

### Interview Questions
**Technical:**
1. What's the difference between RBAC and ABAC?
2. How would you implement hierarchical roles?
3. How do you handle permission caching?
4. What are the security considerations when implementing RBAC?
5. How would you audit permission changes?

**Scenario-based:**
1. A user needs temporary elevated permissions for a specific task. How would you implement this?
2. Your permission system is slowing down API responses. How would you optimize it?
3. How would you migrate from a simple admin/user system to a full RBAC system?
4. Describe how you would implement department-based permissions in an organization.
5. How would you handle permission inheritance in nested resources (e.g., folder-file structure)?

---

## 3. CRUD with PostgreSQL & MongoDB <a name="crud-with-postgresql--mongodb"></a>

### PostgreSQL Implementation
```javascript
// Using Sequelize ORM
const { Sequelize, DataTypes, Op } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
    validate: {
      isEmail: true
    }
  },
  // Complex query examples
  async findActiveUsersWithOrders(startDate, endDate) {
    return await User.findAll({
      where: {
        status: 'active',
        createdAt: {
          [Op.between]: [startDate, endDate]
        }
      },
      include: [{
        model: Order,
        where: {
          status: 'completed',
          total: {
            [Op.gt]: 100
          }
        },
        required: true
      }],
      order: [['createdAt', 'DESC']],
      limit: 100,
      offset: 0
    });
  },

  // Transaction example
  async transferBalance(senderId, receiverId, amount) {
    const transaction = await sequelize.transaction();
    
    try {
      const sender = await User.findByPk(senderId, { transaction });
      const receiver = await User.findByPk(receiverId, { transaction });
      
      if (sender.balance < amount) {
        throw new Error('Insufficient balance');
      }
      
      sender.balance -= amount;
      receiver.balance += amount;
      
      await sender.save({ transaction });
      await receiver.save({ transaction });
      
      await transaction.commit();
      return { success: true };
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  }
});
```

### MongoDB Implementation
```javascript
// Using Mongoose ODM
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  profile: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  tags: [String],
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Complex aggregation example
userSchema.statics.getUserAnalytics = async function(period) {
  return await this.aggregate([
    {
      $match: {
        createdAt: {
          $gte: new Date(Date.now() - period * 24 * 60 * 60 * 1000)
        }
      }
    },
    {
      $group: {
        _id: {
          $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
        },
        count: { $sum: 1 },
        uniqueEmails: { $addToSet: "$email" }
      }
    },
    {
      $project: {
        date: "$_id",
        count: 1,
        uniqueCount: { $size: "$uniqueEmails" }
      }
    },
    { $sort: { date: 1 } }
  ]);
};

// Text search with indexing
userSchema.index({ 
  email: 'text', 
  'profile.name': 'text',
  tags: 'text' 
});

const User = mongoose.model('User', userSchema);

// Usage
const results = await User.find({
  $text: { $search: "john doe" },
  tags: { $in: ["premium", "active"] }
})
.sort({ score: { $meta: "textScore" } })
.limit(10);
```

### Interview Questions
**Technical:**
1. When would you choose PostgreSQL over MongoDB and vice versa?
2. Explain ACID properties and how PostgreSQL implements them.
3. How do you handle database migrations in production?
4. What are database indexes and when should you use them?
5. Explain the N+1 query problem and how to solve it.

**Scenario-based:**
1. Your PostgreSQL database is experiencing deadlocks. How would you debug and resolve this?
2. How would you design a schema for a social media platform with posts, comments, and likes?
3. Your MongoDB queries are slow despite proper indexing. What would you investigate?
4. How would you implement full-text search across multiple fields in both databases?
5. Describe how you would handle database sharding for a multi-tenant application.

---

## 4. File Uploads <a name="file-uploads"></a>

### Implementation
```javascript
// Comprehensive file upload service
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const { S3 } = require('@aws-sdk/client-s3');

class FileUploadService {
  constructor() {
    this.s3 = new S3({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY
      }
    });
    
    this.storage = multer.memoryStorage();
    this.upload = multer({
      storage: this.storage,
      limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
        files: 10
      },
      fileFilter: this.fileFilter.bind(this)
    });
  }

  fileFilter(req, file, cb) {
    const allowedTypes = {
      'image/jpeg': true,
      'image/png': true,
      'image/webp': true,
      'application/pdf': true
    };
    
    const maxSize = {
      'image/jpeg': 10 * 1024 * 1024,
      'image/png': 5 * 1024 * 1024,
      'application/pdf': 20 * 1024 * 1024
    };
    
    if (!allowedTypes[file.mimetype]) {
      return cb(new Error('Invalid file type'));
    }
    
    if (file.size > (maxSize[file.mimetype] || 5 * 1024 * 1024)) {
      return cb(new Error('File too large'));
    }
    
    cb(null, true);
  }

  async processImage(buffer, options = {}) {
    const processor = sharp(buffer);
    
    if (options.resize) {
      processor.resize(options.resize.width, options.resize.height, {
        fit: options.resize.fit || 'cover'
      });
    }
    
    if (options.format) {
      processor.toFormat(options.format, {
        quality: options.quality || 80
      });
    }
    
    if (options.watermark) {
      processor.composite([{
        input: options.watermark,
        gravity: 'southeast'
      }]);
    }
    
    return processor.toBuffer();
  }

  async uploadToS3(fileBuffer, fileName, options = {}) {
    const fileKey = `${options.folder || 'uploads'}/${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${fileName}`;
    
    const uploadParams = {
      Bucket: process.env.S3_BUCKET,
      Key: fileKey,
      Body: fileBuffer,
      ContentType: options.contentType,
      ACL: options.isPublic ? 'public-read' : 'private',
      Metadata: options.metadata || {}
    };
    
    if (options.contentType?.startsWith('image/')) {
      uploadParams.ContentDisposition = 'inline';
    }
    
    const result = await this.s3.putObject(uploadParams);
    
    return {
      key: fileKey,
      url: `https://${process.env.S3_BUCKET}.s3.amazonaws.com/${fileKey}`,
      etag: result.ETag,
      size: fileBuffer.length
    };
  }

  async handleChunkedUpload(fileId, chunkIndex, totalChunks, chunkData) {
    const redisKey = `upload:${fileId}`;
    
    // Store chunk in Redis
    await redis.hset(redisKey, chunkIndex, chunkData.toString('base64'));
    
    const uploadedChunks = await redis.hlen(redisKey);
    
    if (uploadedChunks === totalChunks) {
      // Reassemble file
      const chunks = [];
      for (let i = 0; i < totalChunks; i++) {
        const chunkBase64 = await redis.hget(redisKey, i);
        chunks.push(Buffer.from(chunkBase64, 'base64'));
      }
      
      const fileBuffer = Buffer.concat(chunks);
      await redis.del(redisKey);
      
      return this.uploadToS3(fileBuffer, fileId);
    }
    
    return { status: 'chunk_received', chunkIndex };
  }
}

// Express middleware
const fileService = new FileUploadService();
router.post('/upload', 
  fileService.upload.array('files', 10),
  async (req, res) => {
    try {
      const results = await Promise.all(
        req.files.map(async (file) => {
          let processedBuffer = file.buffer;
          
          if (file.mimetype.startsWith('image/')) {
            processedBuffer = await fileService.processImage(file.buffer, {
              resize: { width: 1200, height: 800 },
              format: 'webp',
              quality: 75
            });
          }
          
          return fileService.uploadToS3(
            processedBuffer,
            file.originalname,
            {
              contentType: file.mimetype,
              folder: 'user-uploads',
              isPublic: true
            }
          );
        })
      );
      
      res.json({ success: true, files: results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);
```

### Interview Questions
**Technical:**
1. How do you prevent malicious file uploads?
2. Explain different file storage strategies (local, S3, CDN).
3. How would you implement resumable file uploads?
4. What are the considerations for handling large file uploads?
5. How do you optimize image uploads for web delivery?

**Scenario-based:**
1. Users are uploading copyrighted material. How would you detect and prevent this?
2. Your file upload endpoint is being DDoS attacked with large files. What would you do?
3. How would you implement a file versioning system?
4. Describe how you would migrate from local file storage to cloud storage without downtime.
5. Users need to upload 10GB video files. How would you design this system?

---

## 5. Real-time Chat <a name="real-time-chat"></a>

### Implementation
```javascript
// WebSocket server with Socket.IO and Redis for scaling
const { Server } = require('socket.io');
const Redis = require('ioredis');
const { createAdapter } = require('@socket.io/redis-adapter');

class ChatService {
  constructor(server) {
    this.io = new Server(server, {
      cors: {
        origin: process.env.CLIENT_URL,
        credentials: true
      },
      transports: ['websocket', 'polling'],
      pingTimeout: 60000,
      pingInterval: 25000
    });
    
    this.setupRedisAdapter();
    this.setupMiddleware();
    this.setupEventHandlers();
  }

  setupRedisAdapter() {
    const pubClient = new Redis(process.env.REDIS_URL);
    const subClient = pubClient.duplicate();
    
    this.io.adapter(createAdapter(pubClient, subClient));
  }

  setupMiddleware() {
    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token;
        const user = await this.verifyToken(token);
        
        if (!user) {
          return next(new Error('Authentication error'));
        }
        
        socket.user = user;
        socket.join(`user:${user.id}`);
        next();
      } catch (error) {
        next(new Error('Authentication error'));
      }
    });
  }

  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      console.log(`User ${socket.user.id} connected`);
      
      // Notify user is online
      socket.broadcast.emit('user:online', { userId: socket.user.id });
      
      // Join room
      socket.on('join:room', async (roomId) => {
        await this.joinRoom(socket, roomId);
      });
      
      // Send message
      socket.on('send:message', async (data) => {
        await this.handleMessage(socket, data);
      });
      
      // Typing indicator
      socket.on('typing', (data) => {
        socket.to(data.roomId).emit('user:typing', {
          userId: socket.user.id,
          roomId: data.roomId
        });
      });
      
      // Read receipt
      socket.on('message:read', async (messageId) => {
        await this.markMessageAsRead(socket.user.id, messageId);
      });
      
      // Disconnect
      socket.on('disconnect', async (reason) => {
        await this.handleDisconnect(socket, reason);
      });
    });
  }

  async joinRoom(socket, roomId) {
    // Check if user can join room
    const canJoin = await this.canAccessRoom(socket.user.id, roomId);
    
    if (!canJoin) {
      socket.emit('error', { message: 'Access denied' });
      return;
    }
    
    const previousRoom = Array.from(socket.rooms)
      .find(room => room.startsWith('room:'));
    
    if (previousRoom) {
      socket.leave(previousRoom);
      socket.to(previousRoom).emit('user:left', {
        userId: socket.user.id,
        roomId: previousRoom.replace('room:', '')
      });
    }
    
    socket.join(`room:${roomId}`);
    
    // Load previous messages
    const messages = await this.loadMessages(roomId, 50);
    socket.emit('room:messages', { roomId, messages });
    
    // Notify others
    socket.to(`room:${roomId}`).emit('user:joined', {
      userId: socket.user.id,
      roomId
    });
  }

  async handleMessage(socket, data) {
    const { roomId, content, type = 'text', metadata = {} } = data;
    
    // Validate message
    if (!content || content.trim().length === 0) {
      return;
    }
    
    // Save to database
    const message = await Message.create({
      roomId,
      senderId: socket.user.id,
      content,
      type,
      metadata,
      status: 'sent'
    });
    
    // Emit to room
    const messageData = {
      ...message.toJSON(),
      sender: socket.user
    };
    
    this.io.to(`room:${roomId}`).emit('new:message', messageData);
    
    // Store in Redis for offline users
    const offlineUsers = await this.getOfflineUsersInRoom(roomId);
    
    offlineUsers.forEach(userId => {
      redis.lpush(`offline:messages:${userId}`, JSON.stringify(messageData));
    });
    
    // Update last activity
    await this.updateRoomActivity(roomId);
  }

  async handleDisconnect(socket, reason) {
    console.log(`User ${socket.user.id} disconnected: ${reason}`);
    
    // Mark as offline after delay
    setTimeout(async () => {
      const sockets = await this.io.in(`user:${socket.user.id}`).allSockets();
      
      if (sockets.size === 0) {
        // User is truly offline
        await User.update(
          { online: false, lastSeen: new Date() },
          { where: { id: socket.user.id } }
        );
        
        socket.broadcast.emit('user:offline', { userId: socket.user.id });
      }
    }, 5000);
  }

  async deliverOfflineMessages(userId) {
    const messageKey = `offline:messages:${userId}`;
    const messages = await redis.lrange(messageKey, 0, -1);
    
    if (messages.length > 0) {
      this.io.to(`user:${userId}`).emit('offline:messages', {
        messages: messages.map(msg => JSON.parse(msg))
      });
      
      await redis.del(messageKey);
    }
  }
}
```

### Interview Questions
**Technical:**
1. Compare WebSocket, SSE, and long-polling for real-time communication.
2. How do you scale WebSocket servers horizontally?
3. Explain the difference between Socket.IO rooms and namespaces.
4. How would you implement message persistence and delivery guarantees?
5. What are the security considerations for WebSocket connections?

**Scenario-based:**
1. Your chat service needs to handle 1 million concurrent connections. How would you architect this?
2. How would you implement typing indicators without flooding the server?
3. Describe how you would add video/voice call functionality to the chat system.
4. Messages are being delivered out of order. How would you solve this?
5. How would you implement end-to-end encryption for private messages?

---

## 6. Online/Offline Status Tracker <a name="onlineoffline-status-tracker"></a>

### Implementation
```javascript
// Real-time status tracking with Redis and WebSockets
class StatusTracker {
  constructor() {
    this.redis = new Redis(process.env.REDIS_URL);
    this.pubsub = this.redis.duplicate();
    this.statusExpiry = 30; // seconds
  }

  async userConnected(userId, socketId) {
    const pipeline = this.redis.pipeline();
    
    // Set online status
    pipeline.hset(`user:status:${userId}`, {
      status: 'online',
      lastSeen: Date.now(),
      socketId
    });
    
    // Add to online users set
    pipeline.sadd('online:users', userId);
    
    // Publish status change
    pipeline.publish('status:changes', JSON.stringify({
      userId,
      status: 'online',
      timestamp: Date.now()
    }));
    
    // Set expiry
    pipeline.expire(`user:status:${userId}`, this.statusExpiry);
    
    await pipeline.exec();
    
    // Subscribe to user's status channel
    this.pubsub.subscribe(`user:${userId}:status`);
  }

  async userDisconnected(userId) {
    const pipeline = this.redis.pipeline();
    
    // Update status to offline
    pipeline.hset(`user:status:${userId}`, {
      status: 'offline',
      lastSeen: Date.now()
    });
    
    // Remove from online set
    pipeline.srem('online:users', userId);
    
    // Publish status change
    pipeline.publish('status:changes', JSON.stringify({
      userId,
      status: 'offline',
      timestamp: Date.now()
    }));
    
    // Don't expire the key immediately
    pipeline.persist(`user:status:${userId}`);
    
    await pipeline.exec();
  }

  async updateLastSeen(userId) {
    await this.redis.hset(`user:status:${userId}`, {
      lastSeen: Date.now()
    });
    
    // Reset expiry for online users
    await this.redis.expire(`user:status:${userId}`, this.statusExpiry);
  }

  async getUserStatus(userId) {
    const status = await this.redis.hgetall(`user:status:${userId}`);
    
    if (!status || !status.status) {
      return { status: 'offline', lastSeen: null };
    }
    
    // Check if user is actually online
    const isOnline = await this.redis.sismember('online:users', userId);
    
    return {
      status: isOnline ? 'online' : status.status,
      lastSeen: status.lastSeen,
      socketId: status.socketId
    };
  }

  async getBatchStatus(userIds) {
    const pipeline = this.redis.pipeline();
    
    userIds.forEach(userId => {
      pipeline.hgetall(`user:status:${userId}`);
    });
    
    const results = await pipeline.exec();
    
    return results.map(([error, status], index) => {
      if (error || !status || !status.status) {
        return {
          userId: userIds[index],
          status: 'offline',
          lastSeen: null
        };
      }
      
      return {
        userId: userIds[index],
        status: status.status,
        lastSeen: status.lastSeen
      };
    });
  }

  async cleanupStaleConnections() {
    // Find users whose status hasn't been updated
    const onlineUsers = await this.redis.smembers('online:users');
    
    const pipeline = this.redis.pipeline();
    const now = Date.now();
    const staleThreshold = 5 * 60 * 1000; // 5 minutes
    
    onlineUsers.forEach(userId => {
      pipeline.hgetall(`user:status:${userId}`);
    });
    
    const results = await pipeline.exec();
    
    const staleUsers = results
      .map(([error, status], index) => {
        if (error || !status || !status.lastSeen) return null;
        
        const lastSeen = parseInt(status.lastSeen);
        if (now - lastSeen > staleThreshold) {
          return onlineUsers[index];
        }
        return null;
      })
      .filter(Boolean);
    
    // Mark stale users as offline
    if (staleUsers.length > 0) {
      const updatePipeline = this.redis.pipeline();
      
      staleUsers.forEach(userId => {
        updatePipeline.hset(`user:status:${userId}`, {
          status: 'offline',
          lastSeen: now
        });
        updatePipeline.srem('online:users', userId);
      });
      
      await updatePipeline.exec();
    }
  }

  startCleanupInterval() {
    setInterval(() => {
      this.cleanupStaleConnections();
    }, 60000); // Every minute
  }
}
```

### Interview Questions
**Technical:**
1. How do you distinguish between a disconnected user and an idle user?
2. What are the trade-offs between polling and WebSockets for status updates?
3. How would you handle network partitions in status tracking?
4. Explain how you would implement "last seen" functionality.
5. How do you scale status tracking for millions of users?

**Scenario-based:**
1. Users are showing as online when they're actually offline. How would you debug this?
2. How would you implement "typing..." status across multiple devices?
3. Describe how you would add "away", "busy", and "do not disturb" statuses.
4. Your status service is consuming too much memory. How would you optimize it?
5. How would you implement status privacy (who can see your online status)?

---

## 7. Payment Gateway Integration <a name="payment-gateway"></a>

### Stripe Implementation
```javascript
// Comprehensive payment service with Stripe
const Stripe = require('stripe');

class PaymentService {
  constructor() {
    this.stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: '2023-10-16',
      timeout: 10000,
      maxNetworkRetries: 3
    });
  }

  async createPaymentIntent(amount, currency, metadata = {}) {
    try {
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency: currency.toLowerCase(),
        metadata,
        automatic_payment_methods: {
          enabled: true,
          allow_redirects: 'never'
        },
        capture_method: 'automatic'
      });

      return {
        clientSecret: paymentIntent.client_secret,
        paymentIntentId: paymentIntent.id,
        status: paymentIntent.status
      };
    } catch (error) {
      this.handleStripeError(error);
    }
  }

  async handleWebhookEvent(payload, signature) {
    const event = this.stripe.webhooks.constructEvent(
      payload,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    switch (event.type) {
      case 'payment_intent.succeeded':
        await this.handlePaymentSuccess(event.data.object);
        break;
      
      case 'payment_intent.payment_failed':
        await this.handlePaymentFailure(event.data.object);
        break;
      
      case 'charge.refunded':
        await this.handleRefund(event.data.object);
        break;
      
      case 'invoice.payment_succeeded':
        await this.handleSubscriptionPayment(event.data.object);
        break;
    }

    return { processed: true, event: event.type };
  }

  async createSubscription(customerId, priceId, trialDays = 0) {
    const subscription = await this.stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: priceId }],
      payment_behavior: 'default_incomplete',
      expand: ['latest_invoice.payment_intent'],
      trial_period_days: trialDays,
      metadata: {
        created_at: new Date().toISOString()
      }
    });

    return {
      subscriptionId: subscription.id,
      status: subscription.status,
      clientSecret: subscription.latest_invoice.payment_intent?.client_secret,
      currentPeriodEnd: new Date(subscription.current_period_end * 1000)
    };
  }

  async handle3DSAuthentication(paymentIntentId) {
    const paymentIntent = await this.stripe.paymentIntents.retrieve(
      paymentIntentId,
      { expand: ['payment_method'] }
    );

    if (paymentIntent.status === 'requires_action' ||
        paymentIntent.status === 'requires_confirmation') {
      
      // Check if 3DS authentication is required
      if (paymentIntent.next_action?.type === 'redirect_to_url') {
        return {
          requiresAction: true,
          redirectUrl: paymentIntent.next_action.redirect_to_url.url
        };
      }
    }

    return { requiresAction: false };
  }

  async createRefund(chargeId, amount, reason = 'requested_by_customer') {
    const refund = await this.stripe.refunds.create({
      charge: chargeId,
      amount: Math.round(amount * 100),
      reason,
      metadata: {
        refunded_at: new Date().toISOString()
      }
    });

    // Update order status in database
    await Order.update(
      { status: 'refunded', refundId: refund.id },
      { where: { stripeChargeId: chargeId } }
    );

    return {
      refundId: refund.id,
      status: refund.status,
      amount: refund.amount / 100
    };
  }

  async handlePaymentDispute(disputeId) {
    const dispute = await this.stripe.disputes.retrieve(disputeId);
    
    // Gather evidence
    const evidence = await this.gatherDisputeEvidence(dispute.charge);
    
    await this.stripe.disputes.update(disputeId, {
      evidence: {
        product_description: evidence.productDescription,
        customer_purchase_ip: evidence.customerIp,
        shipping_address: evidence.shippingAddress,
        shipping_carrier: evidence.shippingCarrier,
        shipping_tracking_number: evidence.trackingNumber
      },
      metadata: {
        handled_at: new Date().toISOString()
      }
    });

    // Notify internal team
    await this.notifyTeamOfDispute(dispute);
  }

  async generatePaymentReport(startDate, endDate) {
    const charges = await this.stripe.charges.list({
      created: {
        gte: Math.floor(startDate.getTime() / 1000),
        lte: Math.floor(endDate.getTime() / 1000)
      },
      limit: 100
    });

    const report = {
      totalAmount: 0,
      successfulPayments: 0,
      failedPayments: 0,
      refunds: 0,
      currencyBreakdown: {},
      dailyBreakdown: {}
    };

    for (const charge of charges.data) {
      const amount = charge.amount / 100;
      const date = new Date(charge.created * 1000).toISOString().split('T')[0];
      
      if (charge.refunded) {
        report.refunds += amount;
      } else if (charge.status === 'succeeded') {
        report.totalAmount += amount;
        report.successfulPayments++;
        
        // Currency breakdown
        report.currencyBreakdown[charge.currency] = 
          (report.currencyBreakdown[charge.currency] || 0) + amount;
        
        // Daily breakdown
        report.dailyBreakdown[date] = 
          (report.dailyBreakdown[date] || 0) + amount;
      } else {
        report.failedPayments++;
      }
    }

    return report;
  }

  handleStripeError(error) {
    switch (error.type) {
      case 'StripeCardError':
        throw new Error(`Card declined: ${error.message}`);
      
      case 'StripeRateLimitError':
        throw new Error('Too many requests. Please try again later.');
      
      case 'StripeInvalidRequestError':
        throw new Error(`Invalid request: ${error.message}`);
      
      case 'StripeAPIError':
        throw new Error('Payment service error. Please try again.');
      
      case 'StripeConnectionError':
        throw new Error('Network error. Please check your connection.');
      
      default:
        throw new Error('Payment processing failed. Please try again.');
    }
  }
}

// Express routes
router.post('/create-payment-intent', async (req, res) => {
  try {
    const { amount, currency, orderId } = req.body;
    
    const paymentIntent = await paymentService.createPaymentIntent(
      amount,
      currency,
      { orderId, userId: req.user.id }
    );
    
    res.json(paymentIntent);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post('/webhook', bodyParser.raw({ type: 'application/json' }), 
  async (req, res) => {
    const signature = req.headers['stripe-signature'];
    
    try {
      const result = await paymentService.handleWebhookEvent(
        req.body,
        signature
      );
      
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }
);
```

### Razorpay Implementation (Alternative)
```javascript
const Razorpay = require('razorpay');

class RazorpayPaymentService {
  constructor() {
    this.razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    });
  }

  async createOrder(amount, currency, receipt, notes = {}) {
    const options = {
      amount: Math.round(amount * 100), // Convert to paise
      currency: currency.toUpperCase(),
      receipt: receipt,
      notes,
      payment_capture: 1 // Auto capture
    };

    const order = await this.razorpay.orders.create(options);
    
    return {
      orderId: order.id,
      amount: order.amount / 100,
      currency: order.currency,
      status: order.status
    };
  }

  async verifyPayment(orderId, paymentId, signature) {
    const crypto = require('crypto');
    const body = orderId + '|' + paymentId;
    
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');
    
    return expectedSignature === signature;
  }

  async createPaymentLink(amount, customer, notes = {}) {
    const paymentLink = await this.razorpay.paymentLink.create({
      amount: Math.round(amount * 100),
      currency: 'INR',
      description: 'Payment for order',
      customer: {
        name: customer.name,
        email: customer.email,
        contact: customer.phone
      },
      notify: {
        sms: true,
        email: true
      },
      reminder_enable: true,
      notes,
      callback_url: process.env.PAYMENT_SUCCESS_URL,
      callback_method: 'get'
    });

    return {
      paymentLinkId: paymentLink.id,
      short_url: paymentLink.short_url,
      status: paymentLink.status
    };
  }
}
```

### Interview Questions
**Technical:**
1. Explain PCI DSS compliance requirements for payment processing.
2. How do you handle webhook security and idempotency?
3. What are the different payment methods you've integrated?
4. How would you implement a retry mechanism for failed payments?
5. Explain 3D Secure authentication flow.

**Scenario-based:**
1. A customer reports being charged twice. How would you investigate and resolve this?
2. How would you implement a subscription system with trial periods and upgrades?
3. Your payment gateway is down. What fallback strategies would you implement?
4. Describe how you would handle currency conversion and international payments.
5. How would you implement fraud detection in payment processing?

---

## 8. Email Service <a name="email-service"></a>

### Implementation
```javascript
// Advanced email service with templates, queues, and analytics
const nodemailer = require('nodemailer');
const { createTransport } = require('nodemailer');
const EmailTemplate = require('email-templates');
const path = require('path');

class EmailService {
  constructor() {
    this.transporter = createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 5
    });

    this.templateEngine = new EmailTemplate({
      views: {
        root: path.join(__dirname, 'email-templates'),
        options: {
          extension: 'ejs'
        }
      },
      juice: true,
      juiceResources: {
        preserveImportant: true,
        webResources: {
          relativeTo: path.join(__dirname, 'email-templates')
        }
      }
    });

    this.setupEventListeners();
  }

  setupEventListeners() {
    this.transporter.on('idle', () => {
      while (this.transporter.isIdle()) {
        // Process queued emails
        this.processQueue();
      }
    });
  }

  async sendEmail(options) {
    const {
      to,
      subject,
      template,
      data = {},
      attachments = [],
      cc = [],
      bcc = [],
      replyTo,
      priority = 'normal'
    } = options;

    try {
      // Render template
      const html = await this.templateEngine.render(template, data);
      const text = this.generateTextVersion(html);

      const mailOptions = {
        from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
        to: Array.isArray(to) ? to : [to],
        subject,
        html,
        text,
        cc,
        bcc,
        replyTo,
        priority,
        attachments,
        headers: {
          'X-Priority': priority === 'high' ? '1' : '3',
          'X-Mailer': 'OurApp 1.0',
          'List-Unsubscribe': `<${process.env.UNSUBSCRIBE_URL}>`,
          'Message-ID': this.generateMessageId()
        }
      };

      // Add tracking pixel for analytics
      if (template !== 'marketing') {
        mailOptions.html = this.addTrackingPixel(mailOptions.html, options);
      }

      const info = await this.transporter.sendMail(mailOptions);
      
      // Log email sent
      await this.logEmail({
        ...options,
        messageId: info.messageId,
        response: info.response
      });

      return {
        success: true,
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info)
      };
    } catch (error) {
      await this.logError(options, error);
      throw error;
    }
  }

  async sendWelcomeEmail(user) {
    return this.sendEmail({
      to: user.email,
      subject: 'Welcome to OurApp!',
      template: 'welcome',
      data: {
        name: user.name,
        verificationLink: `${process.env.APP_URL}/verify/${user.verificationToken}`,
        features: ['Feature 1', 'Feature 2', 'Feature 3']
      },
      category: 'welcome'
    });
  }

  async sendPasswordResetEmail(user, resetToken) {
    return this.sendEmail({
      to: user.email,
      subject: 'Reset Your Password',
      template: 'password-reset',
      data: {
        name: user.name,
        resetLink: `${process.env.APP_URL}/reset-password/${resetToken}`,
        expiryHours: 24
      },
      priority: 'high'
    });
  }

  async sendTransactionalEmail(type, data) {
    const templates = {
      order_confirmation: {
        subject: 'Your Order Confirmation',
        template: 'order-confirmation',
        priority: 'high'
      },
      invoice: {
        subject: 'Invoice for Your Purchase',
        template: 'invoice',
        attachments: [{
          filename: 'invoice.pdf',
          content: data.invoicePdf
        }]
      },
      support_reply: {
        subject: 'Re: Your Support Request',
        template: 'support-reply',
        replyTo: process.env.SUPPORT_EMAIL
      }
    };

    const templateConfig = templates[type];
    if (!templateConfig) {
      throw new Error(`Unknown email type: ${type}`);
    }

    return this.sendEmail({
      ...templateConfig,
      to: data.email,
      data: {
        ...data,
        appUrl: process.env.APP_URL,
        supportEmail: process.env.SUPPORT_EMAIL
      }
    });
  }

  async sendBulkEmails(recipients, template, data) {
    const batchSize = 50;
    const results = [];
    
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      const batchPromises = batch.map(recipient =>
        this.sendEmail({
          to: recipient.email,
          subject: data.subject,
          template,
          data: {
            ...data,
            name: recipient.name,
            unsubscribeLink: `${process.env.APP_URL}/unsubscribe/${recipient.unsubscribeToken}`
          },
          category: 'bulk'
        }).catch(error => ({
          success: false,
          email: recipient.email,
          error: error.message
        }))
      );
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return results;
  }

  async logEmail(emailData) {
    await EmailLog.create({
      messageId: emailData.messageId,
      recipient: emailData.to,
      subject: emailData.subject,
      template: emailData.template,
      status: 'sent',
      sentAt: new Date(),
      metadata: {
        category: emailData.category,
        priority: emailData.priority
      }
    });
  }

  async handleBounce(notification) {
    const { email, bounceType, bounceSubType } = notification;
    
    await EmailLog.update(
      { status: 'bounced', bounceType, bounceSubType },
      { where: { recipient: email, status: 'sent' } }
    );
    
    // Update user email status
    await User.update(
      { emailStatus: 'bounced' },
      { where: { email } }
    );
    
    // Notify admin if hard bounce
    if (bounceType === 'Permanent') {
      await this.sendEmail({
        to: process.env.ADMIN_EMAIL,
        subject: 'Email Bounce Alert',
        template: 'bounce-alert',
        data: { email, bounceType, bounceSubType },
        priority: 'high'
      });
    }
  }

  async handleComplaint(notification) {
    const { email, complaintFeedbackType } = notification;
    
    await User.update(
      { emailStatus: 'complained' },
      { where: { email } }
    );
    
    // Add to suppression list
    await SuppressionList.create({
      email,
      reason: 'complaint',
      feedbackType: complaintFeedbackType,
      reportedAt: new Date()
    });
  }

  async getEmailAnalytics(startDate, endDate) {
    const analytics = await EmailLog.findAll({
      where: {
        sentAt: {
          [Op.between]: [startDate, endDate]
        }
      },
      attributes: [
        'template',
        'status',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
        [sequelize.fn('DATE', sequelize.col('sentAt')), 'date']
      ],
      group: ['template', 'status', 'date'],
      order: [['date', 'DESC']]
    });
    
    return this.formatAnalytics(analytics);
  }

  generateTextVersion(html) {
    // Simple HTML to text conversion
    return html
      .replace(/<[^>]*>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  addTrackingPixel(html, options) {
    const trackingId = uuid.v4();
    const pixelUrl = `${process.env.API_URL}/track/email/${trackingId}/pixel.gif`;
    
    return html.replace(
      '</body>',
      `<img src="${pixelUrl}" width="1" height="1" style="display:none" alt=""/>
      </body>`
    );
  }

  generateMessageId() {
    return `<${Date.now()}.${Math.random().toString(36).substr(2)}@${process.env.EMAIL_DOMAIN}>`;
  }
}
```

### Interview Questions
**Technical:**
1. How do you handle email deliverability and improve inbox placement?
2. Explain SPF, DKIM, and DMARC records.
3. How would you implement email template versioning?
4. What are the considerations for sending bulk emails?
5. How do you track email opens and clicks?

**Scenario-based:**
1. Your emails are going to spam. How would you investigate and fix this?
2. How would you implement an email unsubscribe system that complies with regulations?
3. Describe how you would handle email bounces and complaints.
4. Your email sending is being rate-limited. How would you implement queuing and retries?
5. How would you A/B test different email templates and subject lines?

---

## 9. Refresh Token Rotation <a name="refresh-token-rotation"></a>

### Implementation
```javascript
// Secure refresh token rotation with reuse detection
class TokenService {
  constructor() {
    this.tokenFamilySize = 5;
    this.refreshTokenExpiry = '7d';
    this.accessTokenExpiry = '15m';
  }

  async generateTokenPair(user) {
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: 'access'
      },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: this.accessTokenExpiry }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const refreshTokenHash = this.hashToken(refreshToken);
    
    // Create token family
    const tokenFamily = await this.createTokenFamily(
      user.id, 
      refreshTokenHash
    );

    return {
      accessToken,
      refreshToken,
      tokenFamilyId: tokenFamily.id
    };
  }

  async refreshAccessToken(refreshToken, tokenFamilyId) {
    // 1. Verify token family exists and is not revoked
    const tokenFamily = await TokenFamily.findByPk(tokenFamilyId);
    
    if (!tokenFamily || tokenFamily.revoked) {
      throw new Error('Invalid refresh token');
    }

    // 2. Verify the refresh token
    const refreshTokenHash = this.hashToken(refreshToken);
    const isValid = await this.verifyTokenInFamily(
      tokenFamily.id, 
      refreshTokenHash
    );

    if (!isValid) {
      // Possible token reuse - revoke entire family
      await this.revokeTokenFamily(tokenFamily.id);
      throw new Error('Token reuse detected');
    }

    // 3. Get user
    const user = await User.findByPk(tokenFamily.userId);
    if (!user) {
      throw new Error('User not found');
    }

    // 4. Generate new token pair
    const newRefreshToken = crypto.randomBytes(40).toString('hex');
    const newRefreshTokenHash = this.hashToken(newRefreshToken);

    // 5. Rotate tokens
    await this.rotateTokens(
      tokenFamily.id,
      refreshTokenHash,
      newRefreshTokenHash
    );

    // 6. Generate new access token
    const newAccessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: 'access'
      },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: this.accessTokenExpiry }
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      tokenFamilyId: tokenFamily.id
    };
  }

  async createTokenFamily(userId, initialTokenHash) {
    const transaction = await sequelize.transaction();
    
    try {
      // Check if user has too many active token families
      const activeFamilies = await TokenFamily.count({
        where: {
          userId,
          revoked: false
        },
        transaction
      });

      if (activeFamilies >= 5) {
        // Revoke oldest family
        const oldestFamily = await TokenFamily.findOne({
          where: { userId, revoked: false },
          order: [['createdAt', 'ASC']],
          transaction
        });

        if (oldestFamily) {
          await oldestFamily.update({ revoked: true }, { transaction });
        }
      }

      // Create new token family
      const tokenFamily = await TokenFamily.create({
        userId,
        createdAt: new Date(),
        revoked: false
      }, { transaction });

      // Add initial token to family
      await TokenFamilyMember.create({
        familyId: tokenFamily.id,
        tokenHash: initialTokenHash,
        used: false,
        createdAt: new Date()
      }, { transaction });

      await transaction.commit();
      return tokenFamily;
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  }

  async rotateTokens(familyId, oldTokenHash, newTokenHash) {
    const transaction = await sequelize.transaction();
    
    try {
      // Mark old token as used
      await TokenFamilyMember.update(
        { used: true, usedAt: new Date() },
        {
          where: {
            familyId,
            tokenHash: oldTokenHash,
            used: false
          },
          transaction
        }
      );

      // Check family size
      const familySize = await TokenFamilyMember.count({
        where: { familyId },
        transaction
      });

      // Remove oldest token if family size exceeds limit
      if (familySize >= this.tokenFamilySize) {
        const oldestToken = await TokenFamilyMember.findOne({
          where: { familyId },
          order: [['createdAt', 'ASC']],
          transaction
        });

        if (oldestToken) {
          await oldestToken.destroy({ transaction });
        }
      }

      // Add new token
      await TokenFamilyMember.create({
        familyId,
        tokenHash: newTokenHash,
        used: false,
        createdAt: new Date()
      }, { transaction });

      await transaction.commit();
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  }

  async verifyTokenInFamily(familyId, tokenHash) {
    const tokenMember = await TokenFamilyMember.findOne({
      where: {
        familyId,
        tokenHash,
        used: false
      }
    });

    return !!tokenMember;
  }

  async revokeTokenFamily(familyId) {
    await TokenFamily.update(
      { revoked: true, revokedAt: new Date() },
      { where: { id: familyId } }
    );

    // Log the revocation for security monitoring
    await SecurityLog.create({
      event: 'token_family_revoked',
      familyId,
      reason: 'possible_token_reuse',
      timestamp: new Date()
    });
  }

  async revokeAllUserTokens(userId) {
    await TokenFamily.update(
      { revoked: true, revokedAt: new Date() },
      { where: { userId } }
    );
  }

  hashToken(token) {
    return crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
  }

  async cleanupExpiredTokens() {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() - 30); // 30 days ago

    await TokenFamily.destroy({
      where: {
        revoked: true,
        revokedAt: {
          [Op.lt]: expiryDate
        }
      }
    });
  }
}

// Middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
      }
      throw error;
    }
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Refresh endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken, tokenFamilyId } = req.body;
    
    const tokens = await tokenService.refreshAccessToken(
      refreshToken,
      tokenFamilyId
    );
    
    res.json(tokens);
  } catch (error) {
    if (error.message === 'Token reuse detected') {
      // Send security alert
      await SecurityAlert.create({
        userId: req.user?.id,
        type: 'token_reuse',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(401).json({ 
        error: 'Security alert: Session compromised',
        code: 'SESSION_COMPROMISED'
      });
    }
    
    res.status(401).json({ error: error.message });
  }
});
```

### Interview Questions
**Technical:**
1. Explain the concept of refresh token rotation and why it's important.
2. How do you detect refresh token reuse?
3. What are the security considerations for storing refresh tokens?
4. How would you implement token blacklisting?
5. Explain the trade-offs between JWT and database sessions.

**Scenario-based:**
1. How would you handle a situation where refresh tokens are being stolen?
2. Describe how you would implement "log out from all devices" functionality.
3. Your token service needs to handle 10,000 refresh requests per second. How would you scale it?
4. How would you migrate from a simple JWT system to refresh token rotation without logging users out?
5. A user reports unauthorized access to their account. How would you investigate using token logs?

---

## 10. Background Jobs <a name="background-jobs"></a>

### BullMQ Implementation
```javascript
// Advanced job queue system with BullMQ and Redis
const { Queue, Worker, QueueEvents, Job } = require('bullmq');
const IORedis = require('ioredis');

class JobQueueService {
  constructor() {
    this.connection = new IORedis(process.env.REDIS_URL, {
      maxRetriesPerRequest: null,
      enableReadyCheck: false
    });

    this.queues = new Map();
    this.workers = new Map();
    this.queueEvents = new Map();

    this.setupGlobalEventListeners();
  }

  async createQueue(name, options = {}) {
    if (this.queues.has(name)) {
      return this.queues.get(name);
    }

    const queue = new Queue(name, {
      connection: this.connection,
      defaultJobOptions: {
        removeOnComplete: 100, // Keep last 100 completed jobs
        removeOnFail: 1000, // Keep last 1000 failed jobs
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 1000
        },
        ...options.defaultJobOptions
      },
      ...options.queueOptions
    });

    const queueEvents = new QueueEvents(name, {
      connection: this.connection
    });

    this.queues.set(name, queue);
    this.queueEvents.set(name, queueEvents);

    this.setupQueueEventListeners(name, queueEvents);

    return queue;
  }

  setupQueueEventListeners(name, queueEvents) {
    queueEvents.on('completed', ({ jobId, returnvalue }) => {
      console.log(`Job ${jobId} completed in queue ${name}`);
      this.emit('job:completed', { queue: name, jobId, result: returnvalue });
    });

    queueEvents.on('failed', ({ jobId, failedReason }) => {
      console.error(`Job ${jobId} failed in queue ${name}:`, failedReason);
      this.emit('job:failed', { queue: name, jobId, error: failedReason });
      
      // Send alert for critical failures
      if (name === 'critical') {
        this.sendJobFailureAlert(name, jobId, failedReason);
      }
    });

    queueEvents.on('stalled', ({ jobId }) => {
      console.warn(`Job ${jobId} stalled in queue ${name}`);
      this.emit('job:stalled', { queue: name, jobId });
    });

    queueEvents.on('progress', ({ jobId, data }) => {
      this.emit('job:progress', { queue: name, jobId, progress: data });
    });
  }

  async addJob(queueName, jobName, data, options = {}) {
    const queue = await this.createQueue(queueName);
    
    const job = await queue.add(jobName, data, {
      jobId: options.jobId || `${jobName}-${Date.now()}-${Math.random().toString(36).substr(2)}`,
      priority: options.priority || 0,
      delay: options.delay,
      repeat: options.repeat,
      ...options
    });

    return job;
  }

  async addBulkJobs(queueName, jobs) {
    const queue = await this.createQueue(queueName);
    
    const bullJobs = jobs.map(job => ({
      name: job.name,
      data: job.data,
      opts: job.options
    }));

    const addedJobs = await queue.addBulk(bullJobs);
    return addedJobs;
  }

  createWorker(queueName, processor, options = {}) {
    if (this.workers.has(queueName)) {
      return this.workers.get(queueName);
    }

    const worker = new Worker(queueName, processor, {
      connection: this.connection,
      concurrency: options.concurrency || 1,
      limiter: options.limiter,
      ...options
    });

    worker.on('completed', (job) => {
      console.log(`Worker completed job ${job.id} in ${queueName}`);
    });

    worker.on('failed', (job, err) => {
      console.error(`Worker failed job ${job?.id} in ${queueName}:`, err);
    });

    worker.on('stalled', (jobId) => {
      console.warn(`Worker stalled job ${jobId} in ${queueName}`);
    });

    worker.on('error', (err) => {
      console.error(`Worker error in ${queueName}:`, err);
    });

    this.workers.set(queueName, worker);
    return worker;
  }

  // Job processors
  async emailProcessor(job) {
    const { to, subject, template, data } = job.data;
    
    try {
      await emailService.sendEmail({
        to,
        subject,
        template,
        data
      });
      
      return { success: true, sentAt: new Date() };
    } catch (error) {
      throw new Error(`Email sending failed: ${error.message}`);
    }
  }

  async imageProcessor(job) {
    const { imageBuffer, transformations } = job.data;
    
    let image = sharp(imageBuffer);
    
    for (const transformation of transformations) {
      switch (transformation.type) {
        case 'resize':
          image = image.resize(transformation.width, transformation.height, {
            fit: transformation.fit || 'cover'
          });
          break;
        
        case 'crop':
          image = image.extract(transformation);
          break;
        
        case 'format':
          image = image.toFormat(transformation.format, {
            quality: transformation.quality
          });
          break;
        
        case 'watermark':
          const watermark = await sharp(transformation.watermarkBuffer)
            .resize(transformation.size)
            .toBuffer();
          
          image = image.composite([{
            input: watermark,
            gravity: transformation.position
          }]);
          break;
      }
      
      // Report progress
      await job.updateProgress(Math.floor(
        (transformations.indexOf(transformation) + 1) / transformations.length * 100
      ));
    }
    
    const processedBuffer = await image.toBuffer();
    return processedBuffer;
  }

  async reportProcessor(job) {
    const { startDate, endDate, reportType, email } = job.data;
    
    // Generate report
    let reportData;
    switch (reportType) {
      case 'sales':
        reportData = await salesService.generateSalesReport(startDate, endDate);
        break;
      
      case 'user_activity':
        reportData = await analyticsService.getUserActivityReport(startDate, endDate);
        break;
      
      case 'system_health':
        reportData = await monitoringService.getSystemHealthReport();
        break;
    }
    
    // Generate PDF
    const pdfBuffer = await pdfService.generatePdf(reportData);
    
    // Send email with attachment
    await emailService.sendEmail({
      to: email,
      subject: `Your ${reportType} Report`,
      template: 'report',
      data: { reportType, startDate, endDate },
      attachments: [{
        filename: `${reportType}_report_${Date.now()}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf'
      }]
    });
    
    return { 
      success: true, 
      reportType, 
      generatedAt: new Date(),
      size: pdfBuffer.length 
    };
  }

  async dataSyncProcessor(job) {
    const { source, destination, data } = job.data;
    
    const batchSize = 1000;
    let processed = 0;
    let errors = [];
    
    for (let i = 0; i < data.length; i += batchSize) {
      const batch = data.slice(i, i + batchSize);
      
      try {
        await this.syncBatch(source, destination, batch);
        processed += batch.length;
        
        // Update progress
        await job.updateProgress(Math.floor(processed / data.length * 100));
        
        // Throttle to avoid overwhelming systems
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        errors.push({
          batch: i / batchSize,
          error: error.message
        });
        
        // Continue with next batch despite errors
        continue;
      }
    }
    
    return {
      processed,
      total: data.length,
      errors: errors.length,
      errorDetails: errors
    };
  }

  async scheduleRecurringJob(queueName, jobName, cronPattern, data) {
    const queue = await this.createQueue(queueName);
    
    await queue.add(jobName, data, {
      repeat: {
        pattern: cronPattern,
        tz: 'UTC'
      },
      jobId: `recurring-${jobName}`
    });
  }

  async getQueueMetrics(queueName) {
    const queue = this.queues.get(queueName);
    if (!queue) return null;
    
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
      waiting,
      active,
      completed,
      failed,
      delayed,
      total: waiting + active + completed + failed + delayed
    };
  }

  async retryFailedJobs(queueName, count = 100) {
    const queue = this.queues.get(queueName);
    if (!queue) throw new Error(`Queue ${queueName} not found`);
    
    const failedJobs = await queue.getFailed(0, count - 1);
    
    const retriedJobs = [];
    for (const job of failedJobs) {
      if (job.attemptsMade < job.opts.attempts) {
        await job.retry();
        retriedJobs.push(job.id);
      }
    }
    
    return retriedJobs;
  }

  async cleanupOldJobs(queueName, days = 30) {
    const queue = this.queues.get(queueName);
    if (!queue) throw new Error(`Queue ${queueName} not found`);
    
    const cutoffDate = Date.now() - (days * 24 * 60 * 60 * 1000);
    
    // Remove old completed jobs
    await queue.obliterate({ force: true });
    
    // Clean Redis memory
    await this.connection.sendCommand(['MEMORY', 'PURGE']);
  }

  async sendJobFailureAlert(queueName, jobId, error) {
    await emailService.sendEmail({
      to: process.env.ALERT_EMAIL,
      subject: `Job Failure Alert: ${queueName}`,
      template: 'job-failure-alert',
      data: {
        queueName,
        jobId,
        error,
        timestamp: new Date().toISOString()
      },
      priority: 'high'
    });
  }

  emit(event, data) {
    // Implement event emitter pattern
    // This allows other services to listen for job events
  }
}

// Usage examples
const jobService = new JobQueueService();

// Setup workers
jobService.createWorker('email', jobService.emailProcessor, { concurrency: 5 });
jobService.createWorker('image-processing', jobService.imageProcessor, { concurrency: 3 });
jobService.createWorker('reports', jobService.reportProcessor);
jobService.createWorker('data-sync', jobService.dataSyncProcessor, { concurrency: 1 });

// Schedule recurring jobs
await jobService.scheduleRecurringJob(
  'maintenance',
  'cleanup-old-data',
  '0 2 * * *', // Daily at 2 AM
  { type: 'data_cleanup' }
);

await jobService.scheduleRecurringJob(
  'analytics',
  'generate-daily-report',
  '0 1 * * *', // Daily at 1 AM
  { reportType: 'daily_summary' }
);

// Add jobs
await jobService.addJob('email', 'welcome-email', {
  to: 'user@example.com',
  subject: 'Welcome!',
  template: 'welcome',
  data: { name: 'John' }
});

await jobService.addJob('image-processing', 'process-profile-picture', {
  imageBuffer: buffer,
  transformations: [
    { type: 'resize', width: 500, height: 500 },
    { type: 'format', format: 'webp', quality: 80 }
  ]
}, {
  priority: 1
});

// Bulk add
await jobService.addBulkJobs('email', [
  {
    name: 'newsletter',
    data: { to: 'user1@example.com', subject: 'Newsletter', template: 'newsletter' },
    options: { priority: 3 }
  },
  {
    name: 'newsletter',
    data: { to: 'user2@example.com', subject: 'Newsletter', template: 'newsletter' },
    options: { priority: 3 }
  }
]);
```

### Kafka Implementation (Alternative for High Throughput)
```javascript
const { Kafka, Partitioners } = require('kafkajs');

class KafkaJobService {
  constructor() {
    this.kafka = new Kafka({
      clientId: 'job-service',
      brokers: process.env.KAFKA_BROKERS.split(','),
      ssl: process.env.KAFKA_SSL === 'true',
      sasl: process.env.KAFKA_USERNAME ? {
        mechanism: 'plain',
        username: process.env.KAFKA_USERNAME,
        password: process.env.KAFKA_PASSWORD
      } : undefined
    });

    this.producer = this.kafka.producer({
      createPartitioner: Partitioners.LegacyPartitioner,
      transactionTimeout: 30000
    });

    this.consumers = new Map();
  }

  async publishJob(topic, job) {
    await this.producer.connect();
    
    const messages = [{
      key: job.jobId || `${job.type}-${Date.now()}`,
      value: JSON.stringify({
        ...job,
        publishedAt: new Date().toISOString(),
        metadata: {
          source: 'job-service',
          version: '1.0'
        }
      }),
      headers: {
        'job-type': job.type,
        'priority': job.priority?.toString() || '0'
      }
    }];

    await this.producer.send({
      topic,
      messages,
      acks: -1 // All replicas acknowledge
    });
  }

  async consumeJobs(topic, groupId, processor) {
    const consumer = this.kafka.consumer({ 
      groupId,
      sessionTimeout: 30000,
      heartbeatInterval: 3000,
      maxBytesPerPartition: 1048576, // 1MB
      retry: {
        retries: 10
      }
    });

    await consumer.connect();
    await consumer.subscribe({ topic, fromBeginning: false });

    await consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const job = JSON.parse(message.value.toString());
          
          // Process the job
          const result = await processor(job);
          
          // Commit offset if successful
          await consumer.commitOffsets([{
            topic,
            partition,
            offset: (Number(message.offset) + 1).toString()
          }]);
          
          // Log success
          await this.logJobCompletion(topic, job, result);
        } catch (error) {
          console.error(`Error processing job in ${topic}:`, error);
          
          // Move to dead letter queue
          await this.sendToDLQ(topic, message, error);
        }
      },
      autoCommit: false
    });

    this.consumers.set(`${topic}-${groupId}`, consumer);
  }

  async sendToDLQ(topic, message, error) {
    const dlqMessage = {
      originalTopic: topic,
      originalMessage: message,
      error: error.message,
      failedAt: new Date().toISOString()
    };

    await this.publishJob(`${topic}.dlq`, dlqMessage);
  }
}
```

### Interview Questions
**Technical:**
1. Compare different message queue systems (RabbitMQ, Kafka, BullMQ).
2. How do you ensure exactly-once processing in a distributed job system?
3. Explain dead letter queues and their use cases.
4. How would you implement job prioritization?
5. What are the considerations for job retry strategies?

**Scenario-based:**
1. Your job queue is backing up with millions of pending jobs. How would you handle this?
2. How would you implement a job dependency system (job B runs after job A completes)?
3. Describe how you would monitor and alert on job queue health.
4. Jobs are failing due to database connection issues. How would you design a resilient system?
5. How would you migrate from one job queue system to another without losing jobs?

---

## 11. Cloud Storage System <a name="cloud-storage-system"></a>

### Implementation
```javascript
// Unified cloud storage service with multi-provider support
const { S3 } = require('@aws-sdk/client-s3');
const { CloudFront } = require('@aws-sdk/client-cloudfront');
const { Storage } = require('@google-cloud/storage');
const { BlobServiceClient } = require('@azure/storage-blob');
const fs = require('fs').promises;
const path = require('path');

class CloudStorageService {
  constructor() {
    this.providers = {
      aws: this.setupAWS(),
      gcp: this.setupGCP(),
      azure: this.setupAzure(),
      local: this.setupLocal()
    };

    this.defaultProvider = process.env.STORAGE_PROVIDER || 'aws';
    this.cdnUrl = process.env.CDN_URL;
    this.cacheControl = 'public, max-age=31536000';
  }

  setupAWS() {
    const s3 = new S3({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      },
      maxAttempts: 3,
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED'
    });

    const cloudFront = new CloudFront({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });

    return { s3, cloudFront };
  }

  setupGCP() {
    const storage = new Storage({
      projectId: process.env.GCP_PROJECT_ID,
      keyFilename: process.env.GCP_KEY_FILE,
      retryOptions: {
        autoRetry: true,
        maxRetries: 3
      }
    });

    return { storage };
  }

  setupAzure() {
    const blobServiceClient = BlobServiceClient.fromConnectionString(
      process.env.AZURE_STORAGE_CONNECTION_STRING
    );

    return { blobServiceClient };
  }

  setupLocal() {
    const uploadDir = path.join(__dirname, 'uploads');
    
    // Ensure upload directory exists
    fs.mkdir(uploadDir, { recursive: true });
    
    return { uploadDir };
  }

  async uploadFile(file, options = {}) {
    const {
      provider = this.defaultProvider,
      folder = 'uploads',
      isPublic = false,
      metadata = {},
      contentType,
      generateThumbnails = false
    } = options;

    // Generate unique filename
    const fileExt = path.extname(file.originalname);
    const fileName = `${Date.now()}-${Math.random().toString(36).substr(2)}${fileExt}`;
    const filePath = `${folder}/${fileName}`;

    let uploadResult;
    
    switch (provider) {
      case 'aws':
        uploadResult = await this.uploadToS3(file.buffer, filePath, {
          isPublic,
          metadata,
          contentType: contentType || file.mimetype
        });
        break;
      
      case 'gcp':
        uploadResult = await this.uploadToGCS(file.buffer, filePath, {
          isPublic,
          metadata,
          contentType: contentType || file.mimetype
        });
        break;
      
      case 'azure':
        uploadResult = await this.uploadToAzure(file.buffer, filePath, {
          metadata,
          contentType: contentType || file.mimetype
        });
        break;
      
      case 'local':
        uploadResult = await this.uploadToLocal(file.buffer, filePath);
        break;
      
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }

    // Generate thumbnails for images
    if (generateThumbnails && file.mimetype.startsWith('image/')) {
      const thumbnails = await this.generateThumbnails(
        file.buffer,
        filePath,
        provider
      );
      
      uploadResult.thumbnails = thumbnails;
    }

    // Store file metadata in database
    const fileRecord = await File.create({
      originalName: file.originalname,
      fileName,
      filePath,
      provider,
      size: file.size,
      contentType: file.mimetype,
      isPublic,
      metadata: {
        ...metadata,
        uploaderId: options.userId
      },
      url: uploadResult.url,
      thumbnailUrls: uploadResult.thumbnails
    });

    return {
      ...uploadResult,
      id: fileRecord.id,
      originalName: file.originalname
    };
  }

  async uploadToS3(buffer, filePath, options = {}) {
    const { s3 } = this.providers.aws;
    
    const uploadParams = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: filePath,
      Body: buffer,
      ContentType: options.contentType,
      Metadata: options.metadata || {},
      CacheControl: this.cacheControl
    };

    if (options.isPublic) {
      uploadParams.ACL = 'public-read';
    }

    await s3.putObject(uploadParams);

    const url = options.isPublic 
      ? `https://${process.env.AWS_S3_BUCKET}.s3.amazonaws.com/${filePath}`
      : await this.generatePresignedUrl(filePath);

    return {
      provider: 'aws',
      key: filePath,
      url,
      bucket: process.env.AWS_S3_BUCKET
    };
  }

  async uploadToGCS(buffer, filePath, options = {}) {
    const { storage } = this.providers.gcp;
    const bucket = storage.bucket(process.env.GCS_BUCKET);
    const file = bucket.file(filePath);

    await file.save(buffer, {
      metadata: {
        contentType: options.contentType,
        metadata: options.metadata,
        cacheControl: this.cacheControl
      },
      public: options.isPublic,
      validation: 'md5'
    });

    const url = options.isPublic
      ? `https://storage.googleapis.com/${process.env.GCS_BUCKET}/${filePath}`
      : await this.generateSignedUrlGCS(filePath);

    return {
      provider: 'gcp',
      key: filePath,
      url,
      bucket: process.env.GCS_BUCKET
    };
  }

  async uploadToAzure(buffer, filePath, options = {}) {
    const { blobServiceClient } = this.providers.azure;
    const containerClient = blobServiceClient.getContainerClient(
      process.env.AZURE_CONTAINER_NAME
    );
    
    const blockBlobClient = containerClient.getBlockBlobClient(filePath);

    await blockBlobClient.upload(buffer, buffer.length, {
      blobHTTPHeaders: {
        blobContentType: options.contentType,
        blobCacheControl: this.cacheControl
      },
      metadata: options.metadata
    });

    const url = blockBlobClient.url;

    return {
      provider: 'azure',
      key: filePath,
      url,
      container: process.env.AZURE_CONTAINER_NAME
    };
  }

  async uploadToLocal(buffer, filePath) {
    const { uploadDir } = this.providers.local;
    const fullPath = path.join(uploadDir, filePath);
    
    // Create directory if it doesn't exist
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    
    await fs.writeFile(fullPath, buffer);

    const url = `${process.env.APP_URL}/uploads/${filePath}`;

    return {
      provider: 'local',
      key: filePath,
      url,
      path: fullPath
    };
  }

  async generatePresignedUrl(filePath, expiresIn = 3600) {
    const { s3 } = this.providers.aws;
    
    const command = new GetObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: filePath
    });

    return await getSignedUrl(s3, command, { expiresIn });
  }

  async generateSignedUrlGCS(filePath, expiresIn = 3600) {
    const { storage } = this.providers.gcp;
    const bucket = storage.bucket(process.env.GCS_BUCKET);
    const file = bucket.file(filePath);

    const [url] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + expiresIn * 1000,
      version: 'v4'
    });

    return url;
  }

  async generateThumbnails(buffer, originalPath, provider) {
    const thumbnails = {};
    const sizes = {
      small: { width: 150, height: 150 },
      medium: { width: 300, height: 300 },
      large: { width: 600, height: 600 }
    };

    for (const [size, dimensions] of Object.entries(sizes)) {
      const thumbnailBuffer = await sharp(buffer)
        .resize(dimensions.width, dimensions.height, { fit: 'cover' })
        .toFormat('webp')
        .toBuffer();

      const thumbnailPath = originalPath.replace(
        path.extname(originalPath),
        `-${size}.webp`
      );

      let thumbnailUrl;
      
      switch (provider) {
        case 'aws':
          thumbnailUrl = await this.uploadToS3(thumbnailBuffer, thumbnailPath, {
            isPublic: true,
            contentType: 'image/webp'
          });
          break;
        
        case 'gcp':
          thumbnailUrl = await this.uploadToGCS(thumbnailBuffer, thumbnailPath, {
            isPublic: true,
            contentType: 'image/webp'
          });
          break;
        
        default:
          continue;
      }

      thumbnails[size] = thumbnailUrl.url;
    }

    return thumbnails;
  }

  async deleteFile(filePath, provider = this.defaultProvider) {
    switch (provider) {
      case 'aws':
        await this.deleteFromS3(filePath);
        break;
      
      case 'gcp':
        await this.deleteFromGCS(filePath);
        break;
      
      case 'azure':
        await this.deleteFromAzure(filePath);
        break;
      
      case 'local':
        await this.deleteFromLocal(filePath);
        break;
    }

    // Also delete from database
    await File.destroy({ where: { filePath, provider } });

    // Delete thumbnails if they exist
    const thumbnailPattern = filePath.replace(
      path.extname(filePath),
      '-*.webp'
    );

    await this.deleteMultiple([thumbnailPattern], provider);
  }

  async deleteMultiple(filePatterns, provider = this.defaultProvider) {
    const deletePromises = filePatterns.map(pattern =>
      this.deleteFile(pattern, provider)
    );

    await Promise.all(deletePromises);
  }

  async getFileMetadata(filePath, provider = this.defaultProvider) {
    switch (provider) {
      case 'aws':
        return await this.getS3Metadata(filePath);
      
      case 'gcp':
        return await this.getGCSMetadata(filePath);
      
      case 'azure':
        return await this.getAzureMetadata(filePath);
      
      default:
        return null;
    }
  }

  async getS3Metadata(filePath) {
    const { s3 } = this.providers.aws;
    
    const response = await s3.headObject({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: filePath
    });

    return {
      size: response.ContentLength,
      contentType: response.ContentType,
      lastModified: response.LastModified,
      metadata: response.Metadata,
      etag: response.ETag
    };
  }

  async createCloudFrontInvalidation(filePaths) {
    const { cloudFront } = this.providers.aws;
    
    const invalidation = await cloudFront.createInvalidation({
      DistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
      InvalidationBatch: {
        CallerReference: Date.now().toString(),
        Paths: {
          Quantity: filePaths.length,
          Items: filePaths.map(path => `/${path}`)
        }
      }
    });

    return invalidation;
  }

  async generateCDNUrl(filePath) {
    if (!this.cdnUrl) {
      return this.generatePresignedUrl(filePath);
    }

    return `${this.cdnUrl}/${filePath}`;
  }

  async migrateFile(sourcePath, sourceProvider, destPath, destProvider) {
    // Download from source
    const fileBuffer = await this.downloadFile(sourcePath, sourceProvider);
    
    // Upload to destination
    const result = await this.uploadFile(
      { buffer: fileBuffer, originalname: path.basename(sourcePath) },
      {
        provider: destProvider,
        folder: path.dirname(destPath)
      }
    );
    
    // Delete from source if successful
    await this.deleteFile(sourcePath, sourceProvider);
    
    return result;
  }

  async downloadFile(filePath, provider = this.defaultProvider) {
    switch (provider) {
      case 'aws':
        return await this.downloadFromS3(filePath);
      
      case 'gcp':
        return await this.downloadFromGCS(filePath);
      
      case 'azure':
        return await this.downloadFromAzure(filePath);
      
      case 'local':
        return await this.downloadFromLocal(filePath);
      
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  }

  async downloadFromS3(filePath) {
    const { s3 } = this.providers.aws;
    
    const response = await s3.getObject({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: filePath
    });

    return await response.Body.transformToByteArray();
  }

  async syncDirectory(localDir, remotePath, provider = this.defaultProvider) {
    const files = await fs.readdir(localDir, { withFileTypes: true });
    
    for (const file of files) {
      const localPath = path.join(localDir, file.name);
      const remoteFilePath = path.join(remotePath, file.name);
      
      if (file.isDirectory()) {
        await this.syncDirectory(localPath, remoteFilePath, provider);
      } else {
        const buffer = await fs.readFile(localPath);
        
        await this.uploadFile(
          { buffer, originalname: file.name },
          {
            provider,
            folder: path.dirname(remoteFilePath)
          }
        );
      }
    }
  }

  async getStorageUsage(provider = this.defaultProvider) {
    switch (provider) {
      case 'aws':
        return await this.getS3Usage();
      
      case 'gcp':
        return await this.getGCSUsage();
      
      default:
        return null;
    }
  }

  async getS3Usage() {
    const { s3 } = this.providers.aws;
    
    let totalSize = 0;
    let totalFiles = 0;
    let continuationToken;
    
    do {
      const response = await s3.listObjectsV2({
        Bucket: process.env.AWS_S3_BUCKET,
        ContinuationToken: continuationToken
      });
      
      totalFiles += response.Contents.length;
      totalSize += response.Contents.reduce(
        (sum, obj) => sum + (obj.Size || 0), 0
      );
      
      continuationToken = response.NextContinuationToken;
    } while (continuationToken);
    
    return {
      totalSize,
      totalFiles,
      averageSize: totalFiles > 0 ? totalSize / totalFiles : 0
    };
  }
}
```

### Interview Questions
**Technical:**
1. Compare different cloud storage providers (S3, GCS, Azure Blob).
2. How do you handle file versioning in cloud storage?
3. Explain CDN integration and cache invalidation strategies.
4. How would you implement cross-region replication for disaster recovery?
5. What are the security considerations for cloud storage?

**Scenario-based:**
1. Your cloud storage costs are unexpectedly high. How would you optimize them?
2. How would you implement a file migration from one cloud provider to another?
3. Describe how you would handle large file uploads (10GB+) to cloud storage.
4. Files are being accessed without authorization. How would you implement access controls?
5. How would you design a system that stores files across multiple cloud providers for redundancy?

---

## 12. Multi-tenant Architecture <a name="multi-tenant-architecture"></a>

### Implementation
```javascript
// Complete multi-tenant system with database isolation
class MultiTenantService {
  constructor() {
    this.tenantCache = new Map();
    this.tenantConnections = new Map();
    this.setupTenantResolver();
  }

  setupTenantResolver() {
    // Middleware to resolve tenant from request
    this.resolveTenant = async (req, res, next) => {
      try {
        // Try to get tenant from subdomain
        const host = req.headers.host;
        const subdomain = host.split('.')[0];
        
        // Or from header (for API calls)
        const tenantId = req.headers['x-tenant-id'] || subdomain;
        
        if (!tenantId) {
          return res.status(400).json({ error: 'Tenant not specified' });
        }
        
        // Get tenant from cache or database
        const tenant = await this.getTenant(tenantId);
        
        if (!tenant) {
          return res.status(404).json({ error: 'Tenant not found' });
        }
        
        // Check if tenant is active
        if (!tenant.isActive) {
          return res.status(403).json({ error: 'Tenant is inactive' });
        }
        
        // Set tenant on request
        req.tenant = tenant;
        
        // Set up tenant-specific database connection
        await this.setupTenantConnection(tenant);
        
        next();
      } catch (error) {
        res.status(500).json({ error: 'Tenant resolution failed' });
      }
    };
  }

  async getTenant(tenantId) {
    // Check cache first
    if (this.tenantCache.has(tenantId)) {
      return this.tenantCache.get(tenantId);
    }
    
    // Get from database
    const tenant = await Tenant.findOne({
      where: {
        [Op.or]: [
          { id: tenantId },
          { subdomain: tenantId },
          { customDomain: tenantId }
        ]
      }
    });
    
    if (tenant) {
      // Cache for 5 minutes
      this.tenantCache.set(tenantId, tenant);
      setTimeout(() => {
        this.tenantCache.delete(tenantId);
      }, 5 * 60 * 1000);
    }
    
    return tenant;
  }

  async setupTenantConnection(tenant) {
    const connectionKey = `tenant_${tenant.id}`;
    
    if (this.tenantConnections.has(connectionKey)) {
      return this.tenantConnections.get(connectionKey);
    }
    
    let connection;
    
    switch (tenant.isolationStrategy) {
      case 'database':
        connection = await this.createDatabaseConnection(tenant);
        break;
      
      case 'schema':
        connection = await this.createSchemaConnection(tenant);
        break;
      
      case 'row':
        connection = await this.createRowLevelConnection(tenant);
        break;
      
      default:
        throw new Error('Unsupported isolation strategy');
    }
    
    this.tenantConnections.set(connectionKey, connection);
    return connection;
  }

  async createDatabaseConnection(tenant) {
    // Create a separate database for each tenant
    const sequelize = new Sequelize(
      `tenant_${tenant.id}`,
      process.env.DB_USER,
      process.env.DB_PASSWORD,
      {
        host: process.env.DB_HOST,
        dialect: 'postgres',
        logging: false,
        pool: {
          max: 5,
          min: 0,
          acquire: 30000,
          idle: 10000
        }
      }
    );
    
    // Initialize models for this tenant
    await this.initializeTenantModels(sequelize, tenant);
    
    return sequelize;
  }

  async createSchemaConnection(tenant) {
    // Use schema isolation (PostgreSQL schemas)
    const sequelize = new Sequelize(
      process.env.DB_NAME,
      process.env.DB_USER,
      process.env.DB_PASSWORD,
      {
        host: process.env.DB_HOST,
        dialect: 'postgres',
        logging: false,
        schema: `tenant_${tenant.id}`,
        pool: {
          max: 5,
          min: 0,
          acquire: 30000,
          idle: 10000
        }
      }
    );
    
    // Create schema if it doesn't exist
    await sequelize.createSchema(`tenant_${tenant.id}`, {});
    
    // Initialize models in this schema
    await this.initializeTenantModels(sequelize, tenant);
    
    return sequelize;
  }

  async createRowLevelConnection(tenant) {
    // Row-level isolation - use the same connection but add tenant ID to queries
    const sequelize = new Sequelize(
      process.env.DB_NAME,
      process.env.DB_USER,
      process.env.DB_PASSWORD,
      {
        host: process.env.DB_HOST,
        dialect: 'postgres',
        logging: false,
        pool: {
          max: 10,
          min: 0,
          acquire: 30000,
          idle: 10000
        }
      }
    );
    
    // Add tenant_id to all queries
    sequelize.addHook('beforeCreate', (instance) => {
      if (instance.tenantId === undefined) {
        instance.tenantId = tenant.id;
      }
    });
    
    sequelize.addHook('beforeFind', (options) => {
      options.where = {
        ...options.where,
        tenantId: tenant.id
      };
    });
    
    sequelize.addHook('beforeUpdate', (options) => {
      options.where = {
        ...options.where,
        tenantId: tenant.id
      };
    });
    
    sequelize.addHook('beforeDestroy', (options) => {
      options.where = {
        ...options.where,
        tenantId: tenant.id
      };
    });
    
    return sequelize;
  }

  async initializeTenantModels(sequelize, tenant) {
    // Define tenant-specific models
    const User = sequelize.define('User', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      // ... other fields
    });
    
    // Add tenant_id for row-level isolation
    if (tenant.isolationStrategy === 'row') {
      User.init({
        tenantId: {
          type: DataTypes.UUID,
          allowNull: false
        }
      }, { sequelize });
    }
    
    await sequelize.sync();
  }

  async createTenant(tenantData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Create tenant record
      const tenant = await Tenant.create({
        id: uuid.v4(),
        name: tenantData.name,
        subdomain: tenantData.subdomain,
        customDomain: tenantData.customDomain,
        isolationStrategy: tenantData.isolationStrategy || 'row',
        isActive: true,
        settings: tenantData.settings || {},
        metadata: tenantData.metadata || {},
        createdAt: new Date()
      }, { transaction });
      
      // Create tenant database/schema
      await this.setupTenantConnection(tenant);
      
      // Create default admin user
      await this.createTenantAdmin(tenant, tenantData.admin);
      
      // Initialize tenant data
      await this.initializeTenantData(tenant);
      
      await transaction.commit();
      
      // Invalidate cache
      this.tenantCache.delete(tenant.id);
      this.tenantCache.delete(tenant.subdomain);
      if (tenant.customDomain) {
        this.tenantCache.delete(tenant.customDomain);
      }
      
      return tenant;
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  }

  async createTenantAdmin(tenant, adminData) {
    const tenantConnection = await this.setupTenantConnection(tenant);
    
    const User = tenantConnection.models.User;
    
    const admin = await User.create({
      email: adminData.email,
      password: await bcrypt.hash(adminData.password, 12),
      role: 'admin',
      isActive: true
    });
    
    return admin;
  }

  async initializeTenantData(tenant) {
    const tenantConnection = await this.setupTenantConnection(tenant);
    
    // Create default roles
    const Role = tenantConnection.models.Role;
    await Role.bulkCreate([
      { name: 'admin', permissions: ['*'] },
      { name: 'manager', permissions: ['users:read', 'users:write'] },
      { name: 'user', permissions: ['profile:read', 'profile:write'] }
    ]);
    
    // Create default settings
    const Setting = tenantConnection.models.Setting;
    await Setting.bulkCreate([
      { key: 'theme', value: 'light' },
      { key: 'language', value: 'en' },
      { key: 'timezone', value: 'UTC' }
    ]);
  }

  async deleteTenant(tenantId, hardDelete = false) {
    const tenant = await this.getTenant(tenantId);
    
    if (!tenant) {
      throw new Error('Tenant not found');
    }
    
    if (hardDelete) {
      // Permanently delete tenant data
      await this.deleteTenantData(tenant);
    } else {
      // Soft delete - mark as inactive
      await tenant.update({ isActive: false, deletedAt: new Date() });
    }
    
    // Clean up connections
    const connectionKey = `tenant_${tenant.id}`;
    if (this.tenantConnections.has(connectionKey)) {
      const connection = this.tenantConnections.get(connectionKey);
      await connection.close();
      this.tenantConnections.delete(connectionKey);
    }
    
    // Clear cache
    this.tenantCache.delete(tenant.id);
    this.tenantCache.delete(tenant.subdomain);
    if (tenant.customDomain) {
      this.tenantCache.delete(tenant.customDomain);
    }
  }

  async deleteTenantData(tenant) {
    switch (tenant.isolationStrategy) {
      case 'database':
        await this.deleteTenantDatabase(tenant);
        break;
      
      case 'schema':
        await this.deleteTenantSchema(tenant);
        break;
      
      case 'row':
        await this.deleteTenantRows(tenant);
        break;
    }
    
    // Delete tenant record
    await Tenant.destroy({ where: { id: tenant.id } });
  }

  async deleteTenantDatabase(tenant) {
    const connection = await this.setupTenantConnection(tenant);
    await connection.close();
    
    // Drop database
    await sequelize.query(`DROP DATABASE IF EXISTS tenant_${tenant.id}`);
  }

  async deleteTenantSchema(tenant) {
    const connection = await this.setupTenantConnection(tenant);
    
    // Drop schema
    await connection.query(`DROP SCHEMA IF EXISTS tenant_${tenant.id} CASCADE`);
    await connection.close();
  }

  async deleteTenantRows(tenant) {
    const connection = await this.setupTenantConnection(tenant);
    
    // Delete all tenant data
    const models = Object.values(connection.models);
    
    for (const model of models) {
      await model.destroy({ where: { tenantId: tenant.id } });
    }
    
    await connection.close();
  }

  async migrateTenantData(sourceTenant, targetTenant, options = {}) {
    // Migrate data from one tenant to another
    const sourceConnection = await this.setupTenantConnection(sourceTenant);
    const targetConnection = await this.setupTenantConnection(targetTenant);
    
    const modelsToMigrate = options.models || ['User', 'Product', 'Order'];
    
    for (const modelName of modelsToMigrate) {
      const SourceModel = sourceConnection.models[modelName];
      const TargetModel = targetConnection.models[modelName];
      
      if (!SourceModel || !TargetModel) continue;
      
      const records = await SourceModel.findAll({
        limit: options.batchSize || 1000
      });
      
      let batch = [];
      for (const record of records) {
        const data = record.toJSON();
        
        // Remove tenantId if migrating to different tenant
        if (data.tenantId === sourceTenant.id) {
          delete data.tenantId;
        }
        
        batch.push(data);
        
        if (batch.length >= (options.batchSize || 1000)) {
          await TargetModel.bulkCreate(batch);
          batch = [];
        }
      }
      
      if (batch.length > 0) {
        await TargetModel.bulkCreate(batch);
      }
    }
  }

  async executeForAllTenants(callback, options = {}) {
    // Execute a callback for all active tenants
    const tenants = await Tenant.findAll({
      where: { isActive: true },
      limit: options.limit
    });
    
    const results = [];
    
    for (const tenant of tenants) {
      try {
        const result = await callback(tenant);
        results.push({
          tenantId: tenant.id,
          success: true,
          result
        });
      } catch (error) {
        results.push({
          tenantId: tenant.id,
          success: false,
          error: error.message
        });
      }
      
      // Rate limiting
      if (options.delay) {
        await new Promise(resolve => setTimeout(resolve, options.delay));
      }
    }
    
    return results;
  }

  async backupTenant(tenantId) {
    const tenant = await this.getTenant(tenantId);
    const connection = await this.setupTenantConnection(tenant);
    
    const backup = {
      tenant: tenant.toJSON(),
      data: {},
      timestamp: new Date()
    };
    
    // Backup all models
    const models = Object.values(connection.models);
    
    for (const model of models) {
      const records = await model.findAll();
      backup.data[model.name] = records.map(record => record.toJSON());
    }
    
    // Store backup in cloud storage
    const backupKey = `backups/tenant_${tenant.id}/${Date.now()}.json`;
    await cloudStorageService.uploadFile(
      { buffer: Buffer.from(JSON.stringify(backup)), originalname: 'backup.json' },
      { folder: `tenant-backups/${tenant.id}` }
    );
    
    return backupKey;
  }

  async restoreTenant(tenantId, backupKey) {
    const tenant = await this.getTenant(tenantId);
    const connection = await this.setupTenantConnection(tenant);
    
    // Download backup
    const backupBuffer = await cloudStorageService.downloadFile(backupKey);
    const backup = JSON.parse(backupBuffer.toString());
    
    // Restore data
    for (const [modelName, records] of Object.entries(backup.data)) {
      const Model = connection.models[modelName];
      
      if (Model) {
        // Clear existing data
        await Model.destroy({ where: {} });
        
        // Restore records
        if (records.length > 0) {
          await Model.bulkCreate(records);
        }
      }
    }
    
    // Update tenant settings
    if (backup.tenant.settings) {
      await tenant.update({ settings: backup.tenant.settings });
    }
  }
}

// Usage in Express app
const multiTenantService = new MultiTenantService();

app.use(multiTenantService.resolveTenant);

app.get('/api/users', async (req, res) => {
  // Get tenant-specific connection
  const tenantConnection = await multiTenantService.setupTenantConnection(req.tenant);
  const User = tenantConnection.models.User;
  
  const users = await User.findAll();
  res.json(users);
});

app.post('/api/tenants', async (req, res) => {
  try {
    const tenant = await multiTenantService.createTenant(req.body);
    res.status(201).json(tenant);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Admin route to execute operation on all tenants
app.post('/admin/execute-all-tenants', async (req, res) => {
  const { operation, data } = req.body;
  
  const results = await multiTenantService.executeForAllTenants(
    async (tenant) => {
      switch (operation) {
        case 'updateSettings':
          return await updateTenantSettings(tenant, data);
        case 'sendNotification':
          return await sendTenantNotification(tenant, data);
        case 'generateReport':
          return await generateTenantReport(tenant, data);
      }
    },
    { delay: 100 } // 100ms delay between tenants
  );
  
  res.json(results);
});
```

### Interview Questions
**Technical:**
1. Compare different multi-tenant isolation strategies (database, schema, row).
2. How do you handle tenant-specific configurations and settings?
3. Explain how you would implement cross-tenant data isolation.
4. What are the performance considerations for multi-tenant architectures?
5. How would you handle tenant migrations and backups?

**Scenario-based:**
1. A tenant needs to export all their data for compliance. How would you implement this?
2. How would you handle a tenant that exceeds their storage quota?
3. Describe how you would implement tenant-specific custom domains with SSL certificates.
4. Your multi-tenant system needs to support 10,000 tenants. How would you scale it?
5. How would you handle a situation where one tenant's heavy usage affects other tenants' performance?

---

## Installation & Setup

### Prerequisites
- Node.js 16+
- PostgreSQL 12+
- MongoDB 4.4+
- Redis 6+
- Docker (optional)

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/main_db
MONGODB_URI=mongodb://localhost:27017/app
REDIS_URL=redis://localhost:6379

# JWT
JWT_ACCESS_SECRET=your_access_secret_key
JWT_REFRESH_SECRET=your_refresh_secret_key

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Storage
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_S3_BUCKET=your-bucket-name

# Stripe
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_webhook_secret

# App
PORT=3000
NODE_ENV=production
CLIENT_URL=http://localhost:3000
```

### Running with Docker
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: main_db
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  mongodb:
    image: mongo:5
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/main_db
      - MONGODB_URI=mongodb://mongodb:27017/app
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - mongodb
      - redis

volumes:
  postgres_data:
  mongo_data:
  redis_data:
```

## Conclusion

This comprehensive backend implementation covers essential systems for modern web applications. Each component is designed with scalability, security, and maintainability in mind. The implementations include:

1. **Production-ready code** with error handling and validation
2. **Security best practices** including token rotation and input validation
3. **Performance optimizations** with caching and connection pooling
4. **Monitoring and logging** for production debugging
5. **Scalability considerations** for horizontal scaling

The system is modular and can be adapted to various use cases. Each service can be deployed independently or as part of a monolithic application, depending on your architecture needs.

Remember to:
- Add comprehensive testing for each component
- Implement proper monitoring and alerting
- Set up CI/CD pipelines
- Regularly update dependencies
- Conduct security audits
- Monitor performance metrics

This implementation serves as a solid foundation for building robust, scalable backend systems that can handle real-world production loads.