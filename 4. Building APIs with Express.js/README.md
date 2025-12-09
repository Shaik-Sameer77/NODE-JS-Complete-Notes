# Express.js API Development - Comprehensive Guide

## 📚 Table of Contents
- [Introduction](#introduction)
- [Basic Express App](#basic-express-app)
- [Routing](#routing)
- [Middlewares](#middlewares)
- [Error Handling Architecture](#error-handling-architecture)
- [Async Handlers](#async-handlers)
- [Cookies](#cookies)
- [Query Parameters & Route Parameters](#query-parameters--route-parameters)
- [Handling JSON](#handling-json)
- [File Uploads](#file-uploads)
- [Rate Limiting](#rate-limiting)
- [CORS](#cors)
- [Security with Helmet](#security-with-helmet)
- [Logging](#logging)
- [Interview Questions](#interview-questions)
- [Real-World Scenarios](#real-world-scenarios)

## Introduction

Express.js is a minimalist, unopinionated web framework for Node.js that provides robust features for building web applications and APIs. This guide covers production-grade Express.js development patterns for senior developers.

## Basic Express App

### 🚀 Minimal Application Structure

```javascript
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app; // For testing
```

### 📁 Production Application Structure

```
src/
├── app.js              # App initialization
├── server.js          # Server startup
├── config/            # Configuration
│   ├── index.js
│   └── environments/
├── api/               # API routes
│   ├── v1/
│   └── v2/
├── middleware/        # Custom middlewares
├── controllers/       # Route controllers
├── services/          # Business logic
├── utils/             # Utilities
├── validators/        # Request validation
└── types/             # TypeScript types
```

### 🎯 Advanced Application Configuration

```javascript
// config/express.js
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');

module.exports = () => {
  const app = express();
  
  // Trust proxy for reverse proxy setups
  app.set('trust proxy', 1);
  
  // Security middleware
  app.use(helmet());
  app.use(cors({
    origin: process.env.CORS_ORIGINS?.split(',') || '*',
    credentials: true,
    maxAge: 86400
  }));
  
  // Compression
  app.use(compression());
  
  // Body parsing with limits
  app.use(express.json({
    limit: '10mb',
    strict: true
  }));
  
  app.use(express.urlencoded({
    extended: true,
    limit: '10mb',
    parameterLimit: 1000
  }));
  
  // Request logging
  if (process.env.NODE_ENV !== 'test') {
    app.use(require('../middleware/logger'));
  }
  
  return app;
};
```

## Routing

### 🗺️ Basic Routing

```javascript
const router = express.Router();

// HTTP Methods
router.get('/users', getUsers);
router.post('/users', createUser);
router.put('/users/:id', updateUser);
router.patch('/users/:id', partialUpdateUser);
router.delete('/users/:id', deleteUser);

// Route parameters
router.get('/users/:userId/posts/:postId', getPost);
router.get('/products/:category?', getProducts); // Optional parameter

// Regex in routes
router.get('/file/:fileId(\\d+)', getFile); // Only numeric IDs
router.get('/flights/:from-:to', getFlight); // Multiple params with delimiter

// Route chaining
router.route('/articles')
  .get(getArticles)
  .post(createArticle)
  .all((req, res) => {
    // Handle all methods for this route
    res.status(405).json({ error: 'Method not allowed' });
  });
```

### 🏗️ Advanced Routing Patterns

```javascript
// config/routes.js
module.exports = (app) => {
  // API Versioning
  app.use('/api/v1', require('./api/v1'));
  app.use('/api/v2', require('./api/v2'));
  
  // Admin routes with prefix
  const adminRouter = express.Router();
  adminRouter.use(require('../middleware/adminAuth'));
  adminRouter.get('/dashboard', getDashboard);
  app.use('/admin', adminRouter);
  
  // Dynamic route loading
  const fs = require('fs').promises;
  const path = require('path');
  
  async function loadRoutes() {
    const routesDir = path.join(__dirname, 'routes');
    const files = await fs.readdir(routesDir);
    
    for (const file of files) {
      if (file.endsWith('.js')) {
        const route = require(path.join(routesDir, file));
        const routeName = file.replace('.js', '');
        app.use(`/${routeName}`, route);
      }
    }
  }
  
  // Route metadata
  router.get('/users', getUsers, {
    metadata: {
      description: 'Get all users',
      requiredRoles: ['admin', 'user'],
      rateLimit: '100/15min'
    }
  });
};
```

### 🚦 Route Organization with Controllers

```javascript
// controllers/userController.js
class UserController {
  async getUsers(req, res, next) {
    try {
      const { page = 1, limit = 10, sort = 'createdAt' } = req.query;
      const users = await userService.getUsers({ page, limit, sort });
      res.json({
        data: users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: await userService.countUsers()
        }
      });
    } catch (error) {
      next(error);
    }
  }
  
  async getUser(req, res, next) {
    const user = await userService.getUser(req.params.id);
    if (!user) {
      return next(new NotFoundError('User not found'));
    }
    res.json({ data: user });
  }
  
  async createUser(req, res, next) {
    const validation = userValidator.create(req.body);
    if (!validation.valid) {
      throw new ValidationError(validation.errors);
    }
    
    const user = await userService.createUser(req.body);
    res.status(201).json({ data: user });
  }
}

module.exports = new UserController();

// routes/userRoutes.js
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/', userController.getUsers);
router.post('/', userController.createUser);
router.get('/:id', userController.getUser);

module.exports = router;
```

## Middlewares

### 🔧 Types of Middlewares

```javascript
// Application-level middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Router-level middleware
router.use((req, res, next) => {
  if (!req.headers['x-api-key']) {
    return res.status(401).json({ error: 'API key required' });
  }
  next();
});

// Route-specific middleware
app.get('/admin', authMiddleware, adminController);

// Error-handling middleware (must have 4 parameters)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

// Built-in middleware
app.use(express.static('public', {
  maxAge: '1d',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));
```

### 🛠️ Custom Middleware Examples

```javascript
// middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = (roles = []) => {
  return async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        throw new Error('No token provided');
      }
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check roles if specified
      if (roles.length > 0 && !roles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      
      // Attach user to request
      req.user = decoded;
      next();
    } catch (error) {
      next(new UnauthorizedError(error.message));
    }
  };
};

// middleware/validation.js
const { validationResult } = require('express-validator');

module.exports = (validations) => {
  return async (req, res, next) => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    next();
  };
};

// middleware/requestLogger.js
const pino = require('pino');
const logger = pino();

module.exports = (req, res, next) => {
  const start = Date.now();
  
  // Log request
  logger.info({
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('user-agent')
  }, 'Incoming request');
  
  // Capture response
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration,
      user: req.user?.id
    };
    
    if (res.statusCode >= 400) {
      logger.error(logData, 'Request failed');
    } else {
      logger.info(logData, 'Request completed');
    }
  });
  
  next();
};
```

### ⚙️ Middleware Execution Order

```javascript
// app.js - Correct middleware order
app.use(helmet());                          // 1. Security first
app.use(cors());                            // 2. CORS
app.use(compression());                     // 3. Compression
app.use(express.json());                    // 4. Body parsing
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());                    // 5. Cookies
app.use(session({ /* config */ }));        // 6. Session
app.use(passport.initialize());            // 7. Authentication
app.use(passport.session());
app.use(requestLogger);                     // 8. Logging
app.use(rateLimiter);                       // 9. Rate limiting

// Routes
app.use('/api', apiRouter);                 // 10. API routes

// Error handling (must be last)
app.use(notFoundHandler);                   // 11. 404 handler
app.use(errorHandler);                      // 12. Error handler
```

## Error Handling Architecture

### 🚨 Error Classes

```javascript
// errors/index.js
class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(errors) {
    super('Validation failed', 400);
    this.errors = errors;
  }
}

class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

class ForbiddenError extends AppError {
  constructor(message = 'Forbidden') {
    super(message, 403);
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409);
  }
}

class RateLimitError extends AppError {
  constructor(message = 'Too many requests') {
    super(message, 429);
  }
}

module.exports = {
  AppError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitError
};
```

### 🏗️ Centralized Error Handler

```javascript
// middleware/errorHandler.js
const { AppError } = require('../errors');
const logger = require('../utils/logger');

module.exports = (err, req, res, next) => {
  // Default values
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  
  // Log error
  logger.error({
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    user: req.user?.id,
    body: req.body,
    query: req.query
  });
  
  // Development vs Production response
  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  } else {
    // Production response
    if (err.isOperational) {
      res.status(err.statusCode).json({
        status: err.status,
        message: err.message
      });
    } else {
      // Programming or unknown errors
      console.error('ERROR 💥', err);
      res.status(500).json({
        status: 'error',
        message: 'Something went wrong!'
      });
    }
  }
};
```

### 🎯 Async Error Handling

```javascript
// utils/catchAsync.js
module.exports = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Usage in controllers
const catchAsync = require('../utils/catchAsync');

exports.getUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();
  res.json({ data: users });
});

// Advanced wrapper with transaction support
exports.withTransaction = (fn) => {
  return catchAsync(async (req, res, next) => {
    await sequelize.transaction(async (transaction) => {
      req.transaction = transaction;
      await fn(req, res, next);
    });
  });
};
```

### 🚑 Graceful Shutdown

```javascript
// server.js
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const gracefulShutdown = (signal) => {
  console.log(`\nReceived ${signal}. Starting graceful shutdown...`);
  
  // Stop accepting new connections
  server.close(() => {
    console.log('HTTP server closed');
    
    // Close database connections
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
  
  // Force shutdown after timeout
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
```

## Async Handlers

### 🚫 Avoiding Try-Catch Hell

```javascript
// ❌ Bad - Try-catch hell
app.get('/users/:id', async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    try {
      const profile = await Profile.findOne({ userId: user.id });
      if (!profile) {
        return res.status(404).json({ error: 'Profile not found' });
      }
      
      try {
        const stats = await Analytics.getUserStats(user.id);
        res.json({ user, profile, stats });
      } catch (error) {
        next(error);
      }
    } catch (error) {
      next(error);
    }
  } catch (error) {
    next(error);
  }
});

// ✅ Good - Using async handler wrapper
app.get('/users/:id', asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    throw new NotFoundError('User not found');
  }
  
  const [profile, stats] = await Promise.all([
    Profile.findOne({ userId: user.id }),
    Analytics.getUserStats(user.id)
  ]);
  
  res.json({ user, profile, stats });
}));
```

### 🔄 Promise-Based Patterns

```javascript
// Pattern 1: Promise.all for parallel operations
async function getUserDashboard(userId) {
  const [user, orders, notifications, analytics] = await Promise.all([
    User.findById(userId),
    Order.find({ userId }).limit(10),
    Notification.find({ userId, read: false }),
    Analytics.getDashboardData(userId)
  ]);
  
  return { user, orders, notifications, analytics };
}

// Pattern 2: Sequential operations with error handling
async function processOrder(orderId) {
  const order = await Order.findById(orderId);
  if (!order) throw new NotFoundError('Order not found');
  
  try {
    await Inventory.reserveItems(order.items);
    await Payment.process(order.total);
    await Shipping.schedule(order);
    
    order.status = 'processed';
    await order.save();
    
    await Notification.sendOrderConfirmation(order.userId, orderId);
    
    return order;
  } catch (error) {
    // Rollback logic
    await Inventory.releaseItems(order.items);
    await Payment.refund(order.total);
    throw error;
  }
}

// Pattern 3: Timeout handling
async function fetchWithTimeout(url, timeout = 5000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    return response.json();
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}
```

### 🏗️ Advanced Async Patterns

```javascript
// Pattern 1: Retry logic with exponential backoff
async function retryWithBackoff(fn, maxRetries = 3, baseDelay = 1000) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt === maxRetries) break;
      
      const delay = baseDelay * Math.pow(2, attempt - 1);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw lastError;
}

// Pattern 2: Circuit breaker
class CircuitBreaker {
  constructor(fn, options = {}) {
    this.fn = fn;
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttempt = Date.now();
    this.options = {
      failureThreshold: 5,
      successThreshold: 2,
      timeout: 10000,
      ...options
    };
  }
  
  async call(...args) {
    if (this.state === 'OPEN') {
      if (this.nextAttempt <= Date.now()) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await Promise.race([
        this.fn(...args),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), this.options.timeout)
        )
      ]);
      
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  onSuccess() {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold) {
        this.state = 'CLOSED';
        this.successCount = 0;
      }
    }
  }
  
  onFailure() {
    this.failureCount++;
    if (this.failureCount >= this.options.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.options.timeout;
    }
  }
}
```

## Cookies

### 🍪 Cookie Basics

```javascript
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Setting cookies
app.get('/set-cookie', (req, res) => {
  // Basic cookie
  res.cookie('username', 'john_doe', {
    maxAge: 900000, // 15 minutes in milliseconds
    httpOnly: true, // Not accessible via JavaScript
    secure: process.env.NODE_ENV === 'production', // HTTPS only
    sameSite: 'strict', // CSRF protection
    domain: '.example.com', // Domain scope
    path: '/' // Path scope
  });
  
  // Signed cookie
  res.cookie('session', 'encrypted_value', {
    signed: true,
    httpOnly: true,
    secure: true
  });
  
  // Multiple cookies
  res
    .cookie('preferences', JSON.stringify({ theme: 'dark' }))
    .cookie('tracking_id', 'abc123');
    
  res.json({ message: 'Cookies set' });
});

// Reading cookies
app.get('/get-cookie', (req, res) => {
  const username = req.cookies.username; // Unsigned cookies
  const session = req.signedCookies.session; // Signed cookies
  
  res.json({ username, session });
});

// Clearing cookies
app.get('/clear-cookie', (req, res) => {
  res.clearCookie('username');
  res.clearCookie('session');
  res.json({ message: 'Cookies cleared' });
});
```

### 🔐 Secure Cookie Patterns

```javascript
// middleware/sessionCookies.js
const crypto = require('crypto');

module.exports = (app) => {
  const secret = process.env.COOKIE_SECRET || crypto.randomBytes(64).toString('hex');
  app.use(cookieParser(secret));
  
  // Session cookie configuration
  app.use((req, res, next) => {
    if (req.cookies.session && !req.signedCookies.session) {
      // Tampered cookie detected
      res.clearCookie('session');
      return res.status(401).json({ error: 'Invalid session' });
    }
    next();
  });
};

// JWT + Cookie authentication
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);
  
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
    domain: process.env.COOKIE_DOMAIN
  });
  
  res.json({ user: { id: user.id, email: user.email } });
});

// CSRF protection with cookies
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const csrfToken = crypto.randomBytes(32).toString('hex');
    res.cookie('csrf_token', csrfToken, {
      httpOnly: false, // Must be accessible by JavaScript
      secure: true,
      sameSite: 'strict'
    });
    res.locals.csrfToken = csrfToken;
  }
  next();
});
```

## Query Parameters & Route Parameters

### 🔍 Query Parameters

```javascript
// Basic query params
app.get('/search', (req, res) => {
  const { q, page = 1, limit = 20, sort = 'createdAt' } = req.query;
  
  // Validate and sanitize
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
  const offset = (pageNum - 1) * limitNum;
  
  res.json({
    query: q,
    page: pageNum,
    limit: limitNum,
    offset
  });
});

// Multiple values
app.get('/filter', (req, res) => {
  // /filter?categories=books&categories=movies&price=10-50
  const categories = Array.isArray(req.query.categories) 
    ? req.query.categories 
    : [req.query.categories].filter(Boolean);
  
  const priceRange = req.query.price?.split('-') || [];
  const minPrice = parseFloat(priceRange[0]) || 0;
  const maxPrice = parseFloat(priceRange[1]) || Infinity;
  
  res.json({ categories, minPrice, maxPrice });
});

// Query validation middleware
const { query, validationResult } = require('express-validator');

app.get('/users', [
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('sort').optional().isIn(['name', 'email', 'createdAt']),
  query('search').optional().trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  // Use validated params
  const { page = 1, limit = 20, sort = 'createdAt', search } = req.query;
  // ...
});
```

### 🛣️ Route Parameters

```javascript
// Single parameter
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  
  // Validate ID format
  if (!isValidObjectId(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  // Proceed with database query
});

// Multiple parameters
app.get('/users/:userId/posts/:postId/comments/:commentId', (req, res) => {
  const { userId, postId, commentId } = req.params;
  
  // Hierarchical validation
  if (!await User.exists(userId)) {
    throw new NotFoundError('User not found');
  }
  
  if (!await Post.exists({ _id: postId, userId })) {
    throw new NotFoundError('Post not found');
  }
  
  // Continue processing...
});

// Regex constraints
app.get('/products/:id(\\d+)', (req, res) => {
  // Only matches numeric IDs
  const productId = parseInt(req.params.id);
});

app.get('/files/:filename(.+\\..+)', (req, res) => {
  // Matches files with extensions
  const filename = req.params.filename;
});

// Optional parameters
app.get('/books/:category?', (req, res) => {
  const category = req.params.category || 'all';
  // ...
});
```

### 🎯 Advanced Parameter Handling

```javascript
// Parameter transformation middleware
app.param('userId', async (req, res, next, userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      return next(new NotFoundError('User not found'));
    }
    
    // Attach user to request for subsequent handlers
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
});

// Now routes automatically have user attached
app.get('/users/:userId', (req, res) => {
  // req.user is already populated
  res.json({ data: req.user });
});

app.get('/users/:userId/posts', async (req, res) => {
  const posts = await Post.find({ userId: req.user.id });
  res.json({ data: posts });
});

// Multiple param handlers
app.param('postId', async (req, res, next, postId) => {
  const post = await Post.findOne({
    _id: postId,
    userId: req.user?.id // Uses previously attached user
  });
  
  if (!post) {
    return next(new NotFoundError('Post not found'));
  }
  
  req.post = post;
  next();
});

// Complex validation chain
const validateParams = {
  userId: [
    param('userId').isMongoId(),
    async (req, res, next) => {
      const user = await User.findById(req.params.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      req.user = user;
      next();
    }
  ],
  
  postId: [
    param('postId').isMongoId(),
    async (req, res, next) => {
      if (!req.user) {
        return res.status(400).json({ error: 'User context required' });
      }
      
      const post = await Post.findOne({
        _id: req.params.postId,
        author: req.user.id
      });
      
      if (!post) {
        return res.status(404).json({ error: 'Post not found' });
      }
      
      req.post = post;
      next();
    }
  ]
};

app.get('/users/:userId/posts/:postId', 
  validateParams.userId,
  validateParams.postId,
  (req, res) => {
    res.json({ user: req.user, post: req.post });
  }
);
```

## Handling JSON

### 📝 JSON Request/Response Handling

```javascript
// app.js configuration
app.use(express.json({
  limit: '10mb', // Maximum request body size
  strict: true, // Only accept arrays and objects
  type: 'application/json', // Content-Type to parse
  verify: (req, res, buf, encoding) => {
    // Raw body access for signature verification
    req.rawBody = buf.toString(encoding);
  }
}));

// Custom JSON parsing with validation
app.use((req, res, next) => {
  if (req.is('application/json')) {
    let data = '';
    
    req.on('data', chunk => {
      data += chunk.toString();
      
      // Prevent DoS by limiting size
      if (data.length > 10 * 1024 * 1024) { // 10MB
        req.destroy();
        return res.status(413).json({ error: 'Payload too large' });
      }
    });
    
    req.on('end', () => {
      try {
        req.body = JSON.parse(data);
        next();
      } catch (error) {
        res.status(400).json({ 
          error: 'Invalid JSON', 
          details: error.message 
        });
      }
    });
  } else {
    next();
  }
});

// JSON response formatting middleware
app.use((req, res, next) => {
  const originalJson = res.json;
  
  res.json = function(data, ...args) {
    // Standardize response format
    const formatted = {
      success: res.statusCode < 400,
      data: data?.data || data,
      meta: data?.meta || {},
      errors: data?.errors || null,
      timestamp: new Date().toISOString(),
      version: process.env.API_VERSION || '1.0'
    };
    
    // Remove null/undefined fields
    Object.keys(formatted).forEach(key => {
      if (formatted[key] === null || formatted[key] === undefined) {
        delete formatted[key];
      }
    });
    
    return originalJson.call(this, formatted, ...args);
  };
  
  next();
});
```

### 🎨 Advanced JSON Features

```javascript
// JSON streaming for large datasets
app.get('/large-dataset', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.write('[\n');
  
  const cursor = db.collection('largeData').find().batchSize(100);
  let first = true;
  
  for await (const doc of cursor) {
    if (!first) {
      res.write(',\n');
    }
    first = false;
    res.write(JSON.stringify(doc));
  }
  
  res.write('\n]');
  res.end();
});

// JSON Patch (RFC 6902)
const jsonpatch = require('fast-json-patch');

app.patch('/resources/:id', (req, res) => {
  const { id } = req.params;
  const patches = req.body; // Array of patch operations
  
  try {
    // Validate patch operations
    jsonpatch.validate(patches);
    
    // Apply patches
    const resource = getResource(id);
    const updated = jsonpatch.applyPatch(resource, patches).newDocument;
    
    // Save updated resource
    saveResource(id, updated);
    
    res.json({ data: updated });
  } catch (error) {
    if (error.name === 'JsonPatchError') {
      throw new ValidationError('Invalid patch operation');
    }
    throw error;
  }
});

// JSON Schema validation
const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true });

const userSchema = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: { type: 'string', format: 'email' },
    password: { type: 'string', minLength: 8 },
    age: { type: 'integer', minimum: 0, maximum: 150 }
  }
};

const validateUser = ajv.compile(userSchema);

app.post('/users', (req, res) => {
  if (!validateUser(req.body)) {
    throw new ValidationError(validateUser.errors);
  }
  
  // Process valid data
  // ...
});
```

## File Uploads

### 📤 Multer Configuration

```javascript
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

// Ensure upload directory exists
const uploadDir = 'uploads';
fs.mkdir(uploadDir, { recursive: true }).catch(console.error);

// Storage configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    // Dynamic destination based on user or file type
    const userDir = path.join(uploadDir, req.user?.id || 'anonymous');
    await fs.mkdir(userDir, { recursive: true });
    cb(null, userDir);
  },
  
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const filename = file.fieldname + '-' + uniqueSuffix + ext;
    cb(null, filename);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
  const extname = allowedTypes.test(
    path.extname(file.originalname).toLowerCase()
  );
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Error: File type not allowed!'));
  }
};

// Multer instance
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 10 // Max 10 files
  },
  fileFilter
});

// Upload handlers
const uploadSingle = upload.single('avatar');
const uploadMultiple = upload.array('images', 10);
const uploadFields = upload.fields([
  { name: 'avatar', maxCount: 1 },
  { name: 'gallery', maxCount: 10 }
]);
```

### 🚀 Advanced Upload Patterns

```javascript
// Streaming uploads with busboy (no temporary files)
const busboy = require('busboy');

app.post('/upload-stream', (req, res) => {
  const bb = busboy({ headers: req.headers });
  const files = [];
  const fields = {};
  
  bb.on('file', (fieldname, file, info) => {
    const { filename, encoding, mimeType } = info;
    const chunks = [];
    
    file.on('data', (chunk) => {
      chunks.push(chunk);
    });
    
    file.on('end', () => {
      const buffer = Buffer.concat(chunks);
      
      // Process file buffer (upload to S3, save to DB, etc.)
      files.push({
        fieldname,
        filename,
        encoding,
        mimeType,
        size: buffer.length
      });
    });
  });
  
  bb.on('field', (fieldname, val) => {
    fields[fieldname] = val;
  });
  
  bb.on('close', () => {
    res.json({ fields, files });
  });
  
  req.pipe(bb);
});

// Chunked uploads for large files
const crypto = require('crypto');

app.post('/upload-chunk', async (req, res) => {
  const { chunk, totalChunks, chunkIndex, fileId, fileName } = req.body;
  
  if (!fileId) {
    fileId = crypto.randomBytes(16).toString('hex');
  }
  
  const chunkDir = path.join(uploadDir, 'chunks', fileId);
  await fs.mkdir(chunkDir, { recursive: true });
  
  // Save chunk
  const chunkPath = path.join(chunkDir, `chunk-${chunkIndex}`);
  await fs.writeFile(chunkPath, Buffer.from(chunk, 'base64'));
  
  // Check if all chunks are uploaded
  const uploadedChunks = await fs.readdir(chunkDir);
  
  if (uploadedChunks.length === parseInt(totalChunks)) {
    // Combine chunks
    const chunks = await Promise.all(
      uploadedChunks.sort().map(async (chunkFile) => {
        return fs.readFile(path.join(chunkDir, chunkFile));
      })
    );
    
    const fileBuffer = Buffer.concat(chunks);
    const finalPath = path.join(uploadDir, fileName);
    await fs.writeFile(finalPath, fileBuffer);
    
    // Cleanup chunks
    await fs.rm(chunkDir, { recursive: true });
    
    res.json({ 
      status: 'complete', 
      fileId, 
      size: fileBuffer.length 
    });
  } else {
    res.json({ 
      status: 'chunk_received', 
      fileId, 
      received: uploadedChunks.length,
      total: totalChunks 
    });
  }
});

// S3 upload with multer-s3
const multerS3 = require('multer-s3');
const { S3Client } = require('@aws-sdk/client-s3');

const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
  }
});

const s3Upload = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: process.env.S3_BUCKET,
    metadata: (req, file, cb) => {
      cb(null, { 
        fieldName: file.fieldname,
        uploadedBy: req.user?.id 
      });
    },
    key: (req, file, cb) => {
      const folder = req.user?.id ? `users/${req.user.id}` : 'anonymous';
      const filename = `${Date.now()}-${file.originalname}`;
      cb(null, `${folder}/${filename}`);
    }
  }),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB
  }
});
```

### 🛡️ Upload Security

```javascript
// File type validation using magic numbers
const fileType = require('file-type');

const validateFileType = async (buffer) => {
  const type = await fileType.fromBuffer(buffer);
  
  const allowedMimes = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'application/pdf': ['pdf']
  };
  
  if (!type || !allowedMimes[type.mime]) {
    throw new Error('Invalid file type');
  }
  
  return type;
};

// Virus scanning integration
const clamav = require('clamav.js');

app.post('/upload-secure', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  try {
    // 1. Validate file type
    const fileBuffer = await fs.readFile(req.file.path);
    const validatedType = await validateFileType(fileBuffer);
    
    // 2. Virus scan
    const scanResult = await clamav.scan(req.file.path);
    if (scanResult.isInfected) {
      await fs.unlink(req.file.path);
      throw new Error('File contains malware');
    }
    
    // 3. Image validation (if image)
    if (validatedType.mime.startsWith('image/')) {
      const sharp = require('sharp');
      const image = sharp(fileBuffer);
      const metadata = await image.metadata();
      
      // Check dimensions
      if (metadata.width > 5000 || metadata.height > 5000) {
        throw new Error('Image dimensions too large');
      }
      
      // Strip EXIF data for privacy
      const cleanBuffer = await image
        .rotate() // Auto-rotate based on EXIF
        .withMetadata({}) // Remove all metadata
        .toBuffer();
      
      await fs.writeFile(req.file.path, cleanBuffer);
    }
    
    // 4. Proceed with processing
    res.json({ 
      success: true, 
      filename: req.file.filename,
      type: validatedType.mime 
    });
    
  } catch (error) {
    // Cleanup on error
    if (req.file?.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    next(error);
  }
});
```

## Rate Limiting

### ⚡ Basic Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: false, // Count successful requests
  skipFailedRequests: false // Count failed requests
});

// Apply globally
app.use(globalLimiter);

// API-specific rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.ip === '127.0.0.1' // Skip for localhost
});

app.use('/api/', apiLimiter);

// Route-specific rate limiting
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: 'Too many login attempts, please try again after an hour.',
  skipSuccessfulRequests: true // Don't count successful logins
});

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
```

### 🏗️ Advanced Rate Limiting Strategies

```javascript
// Redis-based rate limiting for distributed systems
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);
const { RateLimiterRedis } = require('rate-limiter-flexible');

// Create rate limiter instance
const rateLimiterRedis = new RateLimiterRedis({
  storeClient: redis,
  points: 10, // Number of points
  duration: 1, // Per second
  blockDuration: 60, // Block for 60 seconds if exceeded
  keyPrefix: 'rl' // Redis key prefix
});

// Custom middleware using Redis
const redisRateLimiter = (points = 10, duration = 1) => {
  const limiter = new RateLimiterRedis({
    storeClient: redis,
    points,
    duration,
    keyPrefix: 'middleware'
  });
  
  return async (req, res, next) => {
    try {
      const key = req.ip || req.headers['x-forwarded-for'];
      await limiter.consume(key);
      next();
    } catch (error) {
      if (error instanceof Error) {
        next(error);
      } else {
        res.status(429).json({
          error: 'Too Many Requests',
          retryAfter: Math.ceil(error.msBeforeNext / 1000) || 1
        });
      }
    }
  };
};

// User-based rate limiting
const userRateLimiter = async (req, res, next) => {
  if (!req.user) {
    return next();
  }
  
  const userLimiter = new RateLimiterRedis({
    storeClient: redis,
    points: 100, // 100 requests
    duration: 60 * 60, // Per hour
    keyPrefix: `user:${req.user.id}`
  });
  
  try {
    await userLimiter.consume('requests');
    next();
  } catch (error) {
    res.status(429).json({
      error: 'Rate limit exceeded for user',
      retryAfter: Math.ceil(error.msBeforeNext / 1000)
    });
  }
};

// Tiered rate limiting based on API keys
const apiKeyRateLimiter = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return next();
  }
  
  // Look up API key tier
  const tier = await redis.get(`apikey:tier:${apiKey}`);
  const limits = {
    free: { points: 100, duration: 3600 },
    pro: { points: 1000, duration: 3600 },
    enterprise: { points: 10000, duration: 3600 }
  };
  
  const config = limits[tier] || limits.free;
  const limiter = new RateLimiterRedis({
    storeClient: redis,
    points: config.points,
    duration: config.duration,
    keyPrefix: `apikey:${apiKey}`
  });
  
  try {
    await limiter.consume('requests');
    next();
  } catch (error) {
    res.status(429).json({
      error: `Rate limit exceeded for ${tier} tier`,
      retryAfter: Math.ceil(error.msBeforeNext / 1000)
    });
  }
};
```

### 🎯 Dynamic Rate Limiting

```javascript
// Adaptive rate limiting based on server load
const os = require('os');

const adaptiveRateLimiter = (req, res, next) => {
  const load = os.loadavg()[0] / os.cpus().length;
  
  // Adjust limits based on system load
  let points = 100;
  let windowMs = 15 * 60 * 1000;
  
  if (load > 2.0) {
    points = 20; // Reduce limits under high load
  } else if (load > 1.0) {
    points = 50;
  }
  
  const limiter = rateLimit({
    windowMs,
    max: points,
    keyGenerator: (req) => {
      // Combine IP and user agent for better identification
      return req.ip + req.get('user-agent');
    },
    handler: (req, res) => {
      res.status(429).json({
        error: 'Rate limit exceeded',
        load: load.toFixed(2),
        retryAfter: windowMs / 1000
      });
    }
  });
  
  limiter(req, res, next);
};

// Rate limiting with cost-based points
const costBasedRateLimiter = (cost = 1) => {
  return async (req, res, next) => {
    const key = `ip:${req.ip}`;
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute window
    
    try {
      const current = await redis.get(key);
      let usage = current ? JSON.parse(current) : { count: 0, resetTime: now + windowMs };
      
      // Reset if window expired
      if (now > usage.resetTime) {
        usage = { count: 0, resetTime: now + windowMs };
      }
      
      // Check if adding cost would exceed limit
      if (usage.count + cost > 100) { // 100 points limit
        const retryAfter = Math.ceil((usage.resetTime - now) / 1000);
        return res.status(429).json({
          error: 'Rate limit exceeded',
          retryAfter,
          remaining: 100 - usage.count
        });
      }
      
      // Update usage
      usage.count += cost;
      await redis.setex(key, Math.ceil(windowMs / 1000), JSON.stringify(usage));
      
      // Add headers
      res.set({
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': 100 - usage.count,
        'X-RateLimit-Reset': usage.resetTime
      });
      
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Apply different costs to different endpoints
app.get('/api/expensive-operation', 
  costBasedRateLimiter(10), // Costs 10 points
  expensiveController
);

app.get('/api/cheap-operation',
  costBasedRateLimiter(1), // Costs 1 point
  cheapController
);
```

## CORS

### 🔧 Basic CORS Configuration

```javascript
const cors = require('cors');

// Basic CORS - allow all origins (NOT recommended for production)
app.use(cors());

// Configured CORS
app.use(cors({
  origin: 'https://example.com', // Single origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Total-Count'],
  credentials: true, // Allow cookies
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Dynamic origin based on environment
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? ['https://app.example.com', 'https://admin.example.com']
  : ['http://localhost:3000', 'http://localhost:3001'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    
    return callback(null, true);
  },
  credentials: true
}));
```

### 🏗️ Advanced CORS Patterns

```javascript
// Route-specific CORS configuration
const apiRouter = express.Router();

// Public API routes
apiRouter.use(cors({
  origin: '*',
  methods: ['GET'],
  allowedHeaders: ['Content-Type']
}));

// Protected API routes
apiRouter.use('/protected', cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// Admin routes
apiRouter.use('/admin', cors({
  origin: process.env.ADMIN_ORIGIN || 'https://admin.example.com',
  credentials: true
}));

app.use('/api', apiRouter);

// CORS with pre-flight caching
const corsOptionsDelegate = (req, callback) => {
  let corsOptions;
  
  // Check the origin against whitelist
  const origin = req.header('Origin');
  const isWhitelisted = allowedOrigins.includes(origin);
  
  if (isWhitelisted) {
    corsOptions = {
      origin: true, // Reflect the requested origin
      credentials: true,
      maxAge: 86400, // Cache preflight for 24 hours
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-API-Key',
        'X-CSRF-Token'
      ],
      exposedHeaders: [
        'X-Total-Count',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining'
      ]
    };
  } else {
    corsOptions = { origin: false }; // Disable CORS
  }
  
  callback(null, corsOptions);
};

app.use(cors(corsOptionsDelegate));

// Handle pre-flight requests manually
app.options('*', cors(corsOptionsDelegate));

// CORS with rate limiting
const corsWithRateLimit = (req, res, next) => {
  // Apply CORS
  cors(corsOptionsDelegate)(req, res, (err) => {
    if (err) return next(err);
    
    // Apply rate limiting after CORS
    if (req.method === 'OPTIONS') {
      // Skip rate limiting for pre-flight requests
      next();
    } else {
      rateLimiter(req, res, next);
    }
  });
};

app.use(corsWithRateLimit);
```

### 🛡️ CORS Security Considerations

```javascript
// CORS with CSRF protection
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// CSRF token endpoint (must be accessible from frontend)
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Protected endpoints
app.post('/api/protected', 
  csrfProtection,
  (req, res) => {
    // CSRF token validated automatically
    res.json({ success: true });
  }
);

// CORS with JWT authentication
const jwt = require('jsonwebtoken');

const corsWithAuth = (req, res, next) => {
  const origin = req.headers.origin;
  
  // Check if origin is allowed
  if (!origin || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // Handle pre-flight
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.sendStatus(204);
    }
  }
  
  // Continue with authentication
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    try {
      req.user = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      // Invalid token, but continue (some routes might be public)
    }
  }
  
  next();
};

app.use(corsWithAuth);
```

## Security with Helmet

### 🛡️ Basic Helmet Configuration

```javascript
const helmet = require('helmet');

// Basic usage with defaults
app.use(helmet());

// Configure individual policies
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https://api.example.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    noSniff: true,
    xssFilter: true,
    frameguard: {
      action: 'deny'
    },
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    }
  })
);
```

### 🔒 Advanced Security Headers

```javascript
// Custom security headers middleware
const securityHeaders = (req, res, next) => {
  // Remove powered-by header
  res.removeHeader('X-Powered-By');
  
  // Security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': [
      'geolocation=()',
      'microphone=()',
      'camera=()',
      'payment=()'
    ].join(', '),
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
  });
  
  // Dynamic CSP based on route
  if (req.path.startsWith('/admin')) {
    res.set('Content-Security-Policy', 
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.admin.example.com;"
    );
  } else {
    res.set('Content-Security-Policy',
      "default-src 'self'; script-src 'self';"
    );
  }
  
  next();
};

app.use(securityHeaders);

// API-specific security
const apiSecurity = (req, res, next) => {
  // Rate limiting headers
  res.set({
    'X-RateLimit-Limit': '100',
    'X-RateLimit-Remaining': '99',
    'X-RateLimit-Reset': Date.now() + 900000
  });
  
  // CORS headers for API
  if (req.method === 'OPTIONS') {
    res.set({
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      'Access-Control-Max-Age': '86400'
    });
  }
  
  next();
};

app.use('/api', apiSecurity);
```

### 🎯 Content Security Policy (CSP) Management

```javascript
// Dynamic CSP based on environment and features
const generateCSP = (req) => {
  const isDev = process.env.NODE_ENV === 'development';
  const isAdmin = req.path.startsWith('/admin');
  
  const directives = {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"], // Inline styles are often needed
    scriptSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"]
  };
  
  // Development additions
  if (isDev) {
    directives.scriptSrc.push("'unsafe-eval'");
    directives.connectSrc.push("ws://localhost:24678");
  }
  
  // Admin panel additions
  if (isAdmin) {
    directives.scriptSrc.push("https://cdn.admin.example.com");
    directives.styleSrc.push("https://cdn.admin.example.com");
  }
  
  // Analytics
  if (process.env.GOOGLE_ANALYTICS_ID) {
    directives.scriptSrc.push("https://www.google-analytics.com");
    directives.imgSrc.push("https://www.google-analytics.com");
    directives.connectSrc.push("https://www.google-analytics.com");
  }
  
  // Convert to CSP string
  return Object.entries(directives)
    .map(([key, values]) => `${key} ${values.join(' ')}`)
    .join('; ');
};

app.use((req, res, next) => {
  const csp = generateCSP(req);
  res.set('Content-Security-Policy', csp);
  next();
});

// CSP violation reporting endpoint
app.post('/csp-violation', express.json({ type: 'application/csp-report' }), (req, res) => {
  const violation = req.body['csp-report'];
  
  // Log violation (don't log in production to avoid DoS)
  if (process.env.NODE_ENV === 'development') {
    console.warn('CSP Violation:', violation);
  }
  
  // You could send this to a monitoring service
  // monitorService.reportCSPViolation(violation);
  
  res.status(204).send();
});

// Add reporting to CSP
const cspWithReporting = (req) => {
  const directives = generateCSP(req);
  const reportUri = '/csp-violation';
  
  return `${directives}; report-uri ${reportUri}; report-to csp-endpoint`;
};

// Report-To header for CSP reporting API
app.use((req, res, next) => {
  res.set('Report-To', JSON.stringify({
    group: 'csp-endpoint',
    max_age: 10886400,
    endpoints: [{ url: '/csp-violation' }],
    include_subdomains: true
  }));
  
  const csp = cspWithReporting(req);
  res.set('Content-Security-Policy', csp);
  
  next();
});
```

## Logging

### 📝 Basic Logging with Morgan

```javascript
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

// Create write stream for access logs
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'access.log'),
  { flags: 'a' }
);

// Custom token for request ID
morgan.token('request-id', (req) => req.id || '-');
morgan.token('user-id', (req) => req.user?.id || '-');

// Custom format
const format = ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms :request-id :user-id';

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Production logging
app.use(morgan(format, {
  stream: accessLogStream,
  skip: (req) => req.path === '/health' // Skip health checks
}));

// Log only errors
app.use(morgan('combined', {
  skip: (req, res) => res.statusCode < 400,
  stream: fs.createWriteStream(path.join(__dirname, 'logs', 'error.log'), { flags: 'a' })
}));
```

### 🎯 Structured Logging with Pino

```javascript
const pino = require('pino');
const expressPino = require('express-pino-logger');

// Create logger instance
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  serializers: {
    req: pino.stdSerializers.req,
    res: pino.stdSerializers.res,
    err: pino.stdSerializers.err
  },
  formatters: {
    level: (label) => ({ level: label.toUpperCase() }),
    bindings: (bindings) => ({
      pid: bindings.pid,
      hostname: bindings.hostname,
      node_version: process.version
    })
  },
  timestamp: () => `,"time":"${new Date().toISOString()}"`,
  messageKey: 'message',
  nestedKey: 'payload',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      'body.password',
      'body.token',
      'body.creditCard'
    ],
    censor: '**REDACTED**'
  }
});

// Express middleware
const expressLogger = expressPino({
  logger,
  autoLogging: {
    ignore: (req) => req.path === '/health',
    ignorePaths: ['/health', '/metrics']
  },
  customAttributeKeys: {
    req: 'request',
    res: 'response',
    err: 'error'
  },
  customLogLevel: (req, res, err) => {
    if (res.statusCode >= 500 || err) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  serializers: {
    req: (req) => ({
      id: req.id,
      method: req.method,
      url: req.url,
      query: req.query,
      params: req.params,
      user: req.user?.id
    }),
    res: (res) => ({
      statusCode: res.statusCode,
      headers: {
        'content-length': res.get('content-length')
      }
    })
  }
});

app.use(expressLogger);

// Custom logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  // Add request ID if not present
  req.id = req.id || require('crypto').randomBytes(16).toString('hex');
  
  // Log request start
  logger.info({
    req: req,
    message: 'Request started',
    requestId: req.id
  });
  
  // Capture response
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    const logData = {
      requestId: req.id,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      user: req.user?.id,
      userAgent: req.get('user-agent'),
      ip: req.ip
    };
    
    if (res.statusCode >= 500) {
      logger.error(logData, 'Request failed');
    } else if (res.statusCode >= 400) {
      logger.warn(logData, 'Client error');
    } else {
      logger.info(logData, 'Request completed');
    }
  });
  
  next();
});
```

### 🔍 Advanced Logging Patterns

```javascript
// Correlation ID middleware
const { v4: uuidv4 } = require('uuid');

app.use((req, res, next) => {
  // Get correlation ID from header or generate new one
  const correlationId = req.headers['x-correlation-id'] || uuidv4();
  
  // Store in request
  req.correlationId = correlationId;
  
  // Set in response headers
  res.set('X-Correlation-ID', correlationId);
  
  // Create child logger with correlation ID
  req.log = logger.child({ correlationId });
  
  next();
});

// Audit logging for sensitive operations
const auditLogger = pino({
  level: 'info',
  name: 'audit',
  serializers: {
    audit: (data) => ({
      actor: data.actor,
      action: data.action,
      resource: data.resource,
      resourceId: data.resourceId,
      changes: data.changes,
      timestamp: new Date().toISOString(),
      ip: data.ip,
      userAgent: data.userAgent
    })
  }
}).child({ type: 'audit' });

// Audit middleware
const auditLog = (action, getResource = (req) => ({})) => {
  return (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(body) {
      // Log after response is sent
      if (res.statusCode < 400) {
        const resource = getResource(req);
        
        auditLogger.info({
          audit: {
            actor: req.user?.id || 'anonymous',
            action,
            resource: resource.type || req.baseUrl,
            resourceId: resource.id || req.params.id,
            changes: req.method !== 'GET' ? req.body : undefined,
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        });
      }
      
      return originalSend.call(this, body);
    };
    
    next();
  };
};

// Usage
app.post('/users', 
  authMiddleware,
  auditLog('user.create', (req) => ({ type: 'user', id: req.body.id })),
  userController.create
);

// Structured error logging
const errorLogger = logger.child({ type: 'error' });

app.use((err, req, res, next) => {
  const errorId = uuidv4();
  
  errorLogger.error({
    errorId,
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack,
      code: err.code,
      statusCode: err.statusCode
    },
    request: {
      id: req.id,
      method: req.method,
      url: req.url,
      query: req.query,
      params: req.params,
      body: req.body,
      user: req.user?.id
    },
    response: {
      statusCode: res.statusCode
    }
  });
  
  // Include error ID in response for support
  res.status(err.statusCode || 500).json({
    error: err.message,
    errorId: process.env.NODE_ENV === 'production' ? errorId : undefined
  });
});

// Performance logging
const perfLogger = logger.child({ type: 'performance' });

const perfMiddleware = (name) => {
  return (req, res, next) => {
    const start = process.hrtime();
    
    res.on('finish', () => {
      const diff = process.hrtime(start);
      const duration = diff[0] * 1000 + diff[1] / 1000000; // Convert to milliseconds
      
      perfLogger.info({
        name,
        duration: duration.toFixed(2),
        method: req.method,
        url: req.url,
        statusCode: res.statusCode
      });
    });
    
    next();
  };
};

// Database query logging
const dbLogger = logger.child({ type: 'database' });

const logQuery = (query, parameters, duration) => {
  dbLogger.debug({
    query: query.replace(/\s+/g, ' ').trim(),
    parameters,
    duration: duration.toFixed(2)
  });
  
  if (duration > 1000) { // Log slow queries
    dbLogger.warn({
      query: query.replace(/\s+/g, ' ').trim(),
      duration: duration.toFixed(2),
      message: 'Slow query detected'
    });
  }
};
```

## Interview Questions

### 🚀 Basic Express App

**Basic:**
1. How do you create a basic Express server?
2. What's the purpose of `app.use(express.json())`?
3. How do you handle different environments (dev/prod) in Express?

**Advanced:**
4. Explain the Express app lifecycle from creation to request handling.
5. How would you structure a large Express application?
6. What are the differences between `app.listen()` and creating an HTTP server manually?

**Senior Level:**
7. Design a production-ready Express application with proper error handling, logging, and security.
8. How would you implement graceful shutdown in an Express app?
9. Explain how Express handles concurrent requests.

### 🗺️ Routing

**Basic:**
1. What are route parameters and how do you access them?
2. How do you handle different HTTP methods (GET, POST, etc.)?
3. What's the difference between `app.get()` and `app.use()`?

**Advanced:**
4. Explain route chaining and when to use it.
5. How do you implement API versioning in Express?
6. What are route-level middleware and when would you use them?

**Senior Level:**
7. Design a routing system for a microservices architecture.
8. How would you implement dynamic route loading based on configuration?
9. Explain advanced route patterns with regex constraints.

### 🔧 Middlewares

**Basic:**
1. What is middleware in Express?
2. What's the order of middleware execution?
3. How do error-handling middleware differ from regular middleware?

**Advanced:**
4. Explain the middleware chain and how `next()` works.
5. How would you implement authentication middleware?
6. What are some common third-party middleware you've used?

**Senior Level:**
7. Design a middleware pipeline for request validation, transformation, and logging.
8. How would you implement conditional middleware based on request properties?
9. Explain middleware composition patterns for reusable functionality.

### 🚨 Error Handling

**Basic:**
1. How do you handle errors in Express?
2. What's the difference between synchronous and asynchronous error handling?
3. How do you create custom error classes?

**Advanced:**
4. Explain the centralized error handling pattern.
5. How would you handle different types of errors (validation, database, etc.) differently?
6. What's the purpose of error stacks and when should they be exposed?

**Senior Level:**
7. Design an error handling system that integrates with monitoring tools.
8. How would you implement retry logic for transient errors?
9. Explain circuit breaker pattern in the context of error handling.

### 🔄 Async Handlers

**Basic:**
1. How do you handle async operations in route handlers?
2. What's the problem with try-catch in async handlers?
3. How does `async/await` work with Express?

**Advanced:**
4. Explain different patterns for handling async errors in Express.
5. How would you implement timeout handling for async operations?
6. What are some common async patterns you use (Promise.all, etc.)?

**Senior Level:**
7. Design a system for handling long-running async operations with progress tracking.
8. How would you implement transaction management across multiple async operations?
9. Explain backpressure handling in async streams.

### 🍪 Cookies

**Basic:**
1. How do you set and read cookies in Express?
2. What are the security options for cookies (httpOnly, secure, etc.)?
3. How do signed cookies work?

**Advanced:**
4. Explain the SameSite cookie attribute and its importance.
5. How would you implement session management using cookies?
6. What are the differences between cookies, localStorage, and sessionStorage?

**Senior Level:**
7. Design a secure authentication system using cookies with CSRF protection.
8. How would you handle cookie consent and GDPR compliance?
9. Explain strategies for migrating between cookie-based and token-based auth.

### 🔍 Query & Route Parameters

**Basic:**
1. How do you access query parameters in Express?
2. What's the difference between query parameters and route parameters?
3. How do you handle optional parameters?

**Advanced:**
4. Explain parameter validation and sanitization strategies.
5. How would you implement pagination using query parameters?
6. What are some common patterns for complex filtering?

**Senior Level:**
7. Design a flexible filtering system that supports multiple operators and nested conditions.
8. How would you implement GraphQL-like field selection using query parameters?
9. Explain strategies for versioning API parameters.

### 📝 JSON Handling

**Basic:**
1. How do you parse JSON request bodies in Express?
2. What's the purpose of the `express.json()` middleware?
3. How do you send JSON responses?

**Advanced:**
4. Explain JSON parsing limits and security considerations.
5. How would you implement JSON schema validation?
6. What are some strategies for handling large JSON payloads?

**Senior Level:**
7. Design a system for streaming JSON responses for large datasets.
8. How would you implement JSON Patch (RFC 6902) support?
9. Explain strategies for backward-compatible JSON API evolution.

### 📤 File Uploads

**Basic:**
1. How do you handle file uploads in Express?
2. What's Multer and how does it work?
3. How do you validate uploaded files?

**Advanced:**
4. Explain different storage strategies for uploaded files (disk, memory, S3).
5. How would you handle large file uploads with progress tracking?
6. What are the security considerations for file uploads?

**Senior Level:**
7. Design a file upload system with virus scanning, image optimization, and CDN integration.
8. How would you implement chunked uploads for very large files?
9. Explain strategies for handling concurrent uploads and rate limiting.

### ⚡ Rate Limiting

**Basic:**
1. What is rate limiting and why is it important?
2. How do you implement basic rate limiting in Express?
3. What are the different rate limiting algorithms?

**Advanced:**
4. Explain token bucket vs leaky bucket algorithms.
5. How would you implement user-based rate limiting?
6. What are some strategies for handling rate limit headers?

**Senior Level:**
7. Design a distributed rate limiting system using Redis.
8. How would you implement adaptive rate limiting based on server load?
9. Explain strategies for API key-based rate limiting tiers.

### 🔧 CORS

**Basic:**
1. What is CORS and why is it needed?
2. How do you enable CORS in Express?
3. What's the difference between simple and preflight requests?

**Advanced:**
4. Explain CORS headers and their purposes.
5. How would you implement dynamic CORS origins?
6. What are the security considerations for CORS configuration?

**Senior Level:**
7. Design a CORS configuration for a multi-tenant SaaS application.
8. How would you implement CORS with CSRF protection?
9. Explain strategies for handling CORS in microservices architecture.

### 🛡️ Security Headers

**Basic:**
1. What security headers should every Express app include?
2. How does Helmet.js help with security?
3. What's Content Security Policy (CSP) and why is it important?

**Advanced:**
4. Explain different CSP directives and their purposes.
5. How would you implement CSP violation reporting?
6. What are the security implications of different SameSite cookie values?

**Senior Level:**
7. Design a comprehensive security header configuration for a financial application.
8. How would you implement dynamic CSP based on user roles and features?
9. Explain strategies for security header testing and monitoring.

### 📊 Logging

**Basic:**
1. What information should be logged in a production application?
2. How do you implement request logging in Express?
3. What's the difference between structured and unstructured logging?

**Advanced:**
4. Explain log levels and when to use each.
5. How would you implement correlation IDs for distributed tracing?
6. What are some strategies for log aggregation and analysis?

**Senior Level:**
7. Design a logging system that integrates with ELK stack or similar.
8. How would you implement audit logging for compliance requirements?
9. Explain strategies for log rotation and retention policies.

## Real-World Scenarios

### 🎯 Scenario 1: High-Traffic API Design
**Situation:** You're building a public API that expects 10,000+ requests per second. The API needs to handle user authentication, rate limiting, and real-time data updates.

**Tasks:**
1. Design the Express application structure
2. Implement efficient middleware pipeline
3. Add rate limiting with Redis
4. Handle database connection pooling
5. Implement caching strategies
6. Add comprehensive monitoring and logging

**Solution Approach:**
```javascript
// Architecture plan
const architecture = {
  layers: [
    "Load Balancer (Nginx)",
    "Express App Cluster (PM2)",
    "Redis (Rate limiting & Cache)",
    "Database (Read Replicas)",
    "Message Queue (RabbitMQ/Kafka)"
  ],
  features: [
    "Stateless authentication (JWT)",
    "Request ID generation",
    "Structured logging with correlation IDs",
    "Health check endpoints",
    "Circuit breaker for external services",
    "Compression middleware",
    "CDN for static assets"
  ]
};

// Key implementation
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    cluster.fork();
  });
} else {
  // Worker process
  const app = express();
  
  // Optimized middleware order
  app.use(requestIdMiddleware);
  app.use(compression());
  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));
  app.use(rateLimiterRedis);
  app.use(cacheMiddleware);
  app.use(loggingMiddleware);
  
  // Stateless routes
  app.use('/api/v1', apiRouter);
  
  app.listen(PORT);
}
```

### 🏗️ Scenario 2: Legacy System Migration
**Situation:** You need to migrate a monolithic PHP application to Node.js/Express while maintaining backward compatibility for existing clients.

**Tasks:**
1. Design API versioning strategy
2. Implement request/response transformation
3. Handle deprecated endpoints
4. Add migration monitoring
5. Create rollback plan

**Solution Template:**
```javascript
// API versioning with semantic versioning
app.use('/api/v1', legacyCompatibilityLayer, v1Router);
app.use('/api/v2', modernRouter);

// Legacy compatibility middleware
const legacyCompatibilityLayer = (req, res, next) => {
  // Transform legacy request format
  if (req.headers['x-api-version'] === 'legacy') {
    req.body = transformLegacyRequest(req.body);
    req.legacyFormat = true;
  }
  
  next();
};

// Response transformation
app.use((req, res, next) => {
  const originalJson = res.json;
  
  res.json = function(data) {
    if (req.legacyFormat) {
      data = transformToLegacyResponse(data);
    }
    
    // Add deprecation headers for old endpoints
    if (req.path.startsWith('/api/v1/') && !req.path.includes('/health')) {
      res.set({
        'Deprecation': 'Wed, 31 Dec 2025 23:59:59 GMT',
        'Sunset': 'Thu, 31 Dec 2026 23:59:59 GMT',
        'Link': '</api/v2/docs>; rel="successor-version"'
      });
    }
    
    originalJson.call(this, data);
  };
  
  next();
});

// Migration dashboard endpoint
app.get('/api/migration-status', (req, res) => {
  const stats = {
    v1_requests: getRequestCount('v1'),
    v2_requests: getRequestCount('v2'),
    migration_rate: calculateMigrationRate(),
    deprecated_endpoints: getDeprecatedEndpoints(),
    scheduled_removals: getScheduledRemovals()
  };
  
  res.json(stats);
});
```

### 🚀 Scenario 3: Real-time Collaborative Application
**Situation:** Building a collaborative document editing tool like Google Docs with real-time updates, presence, and conflict resolution.

**Tasks:**
1. Implement WebSocket integration with Express
2. Handle concurrent editing conflicts
3. Add presence detection
4. Implement operational transformation
5. Add offline support and synchronization

**WebSocket Integration:**
```javascript
const WebSocket = require('ws');
const express = require('express');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Express middleware for WebSocket upgrade
app.use((req, res, next) => {
  req.wss = wss;
  next();
});

// WebSocket connection handling
wss.on('connection', (ws, req) => {
  const userId = authenticateWebSocket(req);
  const documentId = getDocumentIdFromUrl(req.url);
  
  ws.userId = userId;
  ws.documentId = documentId;
  
  // Join document room
  joinDocumentRoom(documentId, ws);
  
  // Handle messages
  ws.on('message', async (data) => {
    try {
      const operation = JSON.parse(data);
      
      // Validate operation
      if (!validateOperation(operation, userId, documentId)) {
        ws.send(JSON.stringify({ error: 'Invalid operation' }));
        return;
      }
      
      // Apply operational transformation
      const transformed = await applyOT(documentId, operation);
      
      // Broadcast to other clients in room
      broadcastToDocument(documentId, {
        type: 'operation',
        data: transformed,
        from: userId
      }, ws);
      
      // Persist to database
      await saveOperation(documentId, transformed);
      
    } catch (error) {
      console.error('WebSocket error:', error);
      ws.send(JSON.stringify({ error: 'Processing failed' }));
    }
  });
  
  // Presence
  ws.on('close', () => {
    leaveDocumentRoom(documentId, ws);
    broadcastPresence(documentId);
  });
});

// REST endpoints for offline sync
app.post('/api/documents/:id/sync', async (req, res) => {
  const { operations, clientVersion } = req.body;
  const documentId = req.params.id;
  const userId = req.user.id;
  
  try {
    // Get server operations since clientVersion
    const serverOps = await getOperationsSince(documentId, clientVersion);
    
    // Transform client operations against server operations
    const transformedOps = operations.map(op => 
      transformAgainst(serverOps, op)
    );
    
    // Apply transformed operations
    const result = await applyOperations(documentId, transformedOps, userId);
    
    // Return server operations for client to apply
    res.json({
      operations: serverOps,
      serverVersion: result.version,
      conflicts: result.conflicts
    });
    
  } catch (error) {
    next(error);
  }
});
```

### 🛡️ Scenario 4: Security Audit & Hardening
**Situation:** Your company's Express API has suffered a security breach. You need to conduct a security audit and implement hardening measures.

**Tasks:**
1. Conduct security assessment
2. Implement security headers
3. Add request validation and sanitization
4. Implement rate limiting and DDoS protection
5. Add security monitoring and alerting
6. Create incident response plan

**Security Implementation:**
```javascript
// Comprehensive security middleware
const securityMiddleware = [
  // 1. Basic security headers
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }),
  
  // 2. Request size limiting
  express.json({ limit: '1mb' }),
  express.urlencoded({ extended: true, limit: '1mb' }),
  
  // 3. Rate limiting with multiple strategies
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    keyGenerator: (req) => req.ip + req.get('user-agent'),
    skip: (req) => req.ip === '127.0.0.1'
  }),
  
  // 4. SQL injection protection
  (req, res, next) => {
    // Sanitize query parameters
    const sanitize = (obj) => {
      Object.keys(obj).forEach(key => {
        if (typeof obj[key] === 'string') {
          obj[key] = obj[key].replace(/[^\w\s\-.,]/gi, '');
        }
      });
    };
    
    sanitize(req.query);
    sanitize(req.params);
    sanitize(req.body);
    
    next();
  },
  
  // 5. XSS protection
  (req, res, next) => {
    const xssClean = (obj) => {
      Object.keys(obj).forEach(key => {
        if (typeof obj[key] === 'string') {
          obj[key] = obj[key]
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
        }
      });
    };
    
    if (req.body) xssClean(req.body);
    next();
  },
  
  // 6. Security logging
  (req, res, next) => {
    const securityLogger = require('../utils/securityLogger');
    
    // Log potential attacks
    const suspiciousPatterns = [
      /<script>/i,
      /union.*select/i,
      /exec\(/i,
      /etc\/passwd/i
    ];
    
    const checkSuspicious = (input) => {
      return suspiciousPatterns.some(pattern => pattern.test(input));
    };
    
    if (checkSuspicious(req.url) || 
        checkSuspicious(JSON.stringify(req.body)) ||
        checkSuspicious(JSON.stringify(req.query))) {
      
      securityLogger.warn({
        type: 'suspicious_request',
        ip: req.ip,
        url: req.url,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
      });
    }
    
    next();
  }
];

app.use(securityMiddleware);

// Security monitoring endpoint
app.get('/api/security/metrics', authMiddleware(['admin']), (req, res) => {
  const metrics = {
    failed_logins: await getFailedLoginCount('24h'),
    blocked_ips: await getBlockedIPs(),
    suspicious_requests: await getSuspiciousRequestCount('24h'),
    rate_limit_hits: await getRateLimitHits('24h'),
    security_alerts: await getRecentAlerts()
  };
  
  res.json(metrics);
});
```

### 🔄 Scenario 5: Microservices Communication
**Situation:** You're building an e-commerce platform with multiple microservices (users, products, orders, payments). Need to handle inter-service communication, data consistency, and fault tolerance.

**Tasks:**
1. Design service-to-service communication
2. Implement circuit breakers for external calls
3. Add request tracing across services
4. Handle distributed transactions
5. Implement retry logic with exponential backoff

**Service Communication Layer:**
```javascript
// services/httpClient.js - Enhanced HTTP client with resilience
const axios = require('axios');
const CircuitBreaker = require('opossum');

class ServiceClient {
  constructor(serviceName, baseURL, options = {}) {
    this.serviceName = serviceName;
    this.baseURL = baseURL;
    
    // Create axios instance with defaults
    this.client = axios.create({
      baseURL,
      timeout: options.timeout || 5000,
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Name': process.env.SERVICE_NAME || 'api-gateway'
      }
    });
    
    // Add request ID propagation
    this.client.interceptors.request.use((config) => {
      const requestId = global.requestId || require('crypto').randomBytes(16).toString('hex');
      config.headers['X-Request-ID'] = requestId;
      config.headers['X-Correlation-ID'] = global.correlationId || requestId;
      return config;
    });
    
    // Create circuit breaker
    this.breaker = new CircuitBreaker(
      async (config) => {
        const response = await this.client.request(config);
        return response.data;
      },
      {
        timeout: options.timeout || 5000,
        errorThresholdPercentage: 50,
        resetTimeout: 30000,
        rollingCountTimeout: 10000,
        rollingCountBuckets: 10
      }
    );
    
    // Circuit breaker events
    this.breaker.on('open', () => {
      console.warn(`Circuit breaker OPEN for ${serviceName}`);
    });
    
    this.breaker.on('halfOpen', () => {
      console.info(`Circuit breaker HALF_OPEN for ${serviceName}`);
    });
    
    this.breaker.on('close', () => {
      console.info(`Circuit breaker CLOSED for ${serviceName}`);
    });
  }
  
  async request(config) {
    try {
      return await this.breaker.fire(config);
    } catch (error) {
      if (error.name === 'TimeoutError') {
        throw new Error(`Service ${this.serviceName} timeout`);
      }
      
      if (error.isCircuitBreakerOpen) {
        throw new Error(`Service ${this.serviceName} unavailable`);
      }
      
      throw error;
    }
  }
  
  async get(path, config = {}) {
    return this.request({ ...config, method: 'GET', url: path });
  }
  
  async post(path, data, config = {}) {
    return this.request({ ...config, method: 'POST', url: path, data });
  }
  
  // Retry with exponential backoff
  async retryRequest(fn, maxRetries = 3, baseDelay = 100) {
    let lastError;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        
        // Don't retry on certain errors
        if (error.response?.status >= 400 && error.response?.status < 500) {
          break;
        }
        
        if (attempt < maxRetries - 1) {
          const delay = baseDelay * Math.pow(2, attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw lastError;
  }
}

// Usage in order service
const userService = new ServiceClient('users', process.env.USER_SERVICE_URL);
const productService = new ServiceClient('products', process.env.PRODUCT_SERVICE_URL);

app.post('/api/orders', async (req, res, next) => {
  try {
    // Concurrent service calls
    const [user, products] = await Promise.all([
      userService.get(`/users/${req.body.userId}`),
      productService.post('/products/validate', { ids: req.body.productIds })
    ]);
    
    // Create order with validated data
    const order = await createOrder({
      user: user.data,
      products: products.data,
      ...req.body
    });
    
    // Async processing (don't block response)
    processPayment(order.id).catch(console.error);
    sendConfirmationEmail(order.id).catch(console.error);
    
    res.status(201).json(order);
  } catch (error) {
    next(error);
  }
});
```

---

## 📚 Additional Resources

### Documentation
- [Express.js Official Documentation](https://expressjs.com/)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [OWASP Security Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [HTTP Status Codes](https://httpstatuses.com/)

### Security Tools
- [Helmet.js](https://helmetjs.github.io/)
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- [express-validator](https://express-validator.github.io/)
- [csurf](https://github.com/expressjs/csurf)

### Monitoring & Logging
- [Pino Logger](https://getpino.io/)
- [Winston](https://github.com/winstonjs/winston)
- [PM2](https://pm2.keymetrics.io/)
- [New Relic](https://newrelic.com/)

### Testing
- [Jest](https://jestjs.io/)
- [Supertest](https://github.com/visionmedia/supertest)
- [Sinon](https://sinonjs.org/)
- [Nock](https://github.com/nock/nock)

### Performance
- [Node.js Performance Hooks](https://nodejs.org/api/perf_hooks.html)
- [Clinic.js](https://clinicjs.org/)
- [0x](https://github.com/davidmarkclements/0x)

---

