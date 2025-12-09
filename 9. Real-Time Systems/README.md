# API Architecture - Complete Guide

<<<<<<< HEAD
## Table of Contents
- [Project Structure Overview](#project-structure-overview)
- [MVC Pattern](#mvc-pattern)
- [Services Layer](#services-folder)
- [Repositories Layer](#repositories)
- [DTOs (Data Transfer Objects)](#dtos-data-transfer-objects)
- [Middlewares Layer](#middlewares-layer)
- [Utils Folder](#utils-folder)
- [Error Handling Structure](#error-handling-structure)
- [Separate Env Config](#separate-env-config)
- [Versioning APIs](#versioning-apis)
- [Pagination](#pagination)
- [Filtering](#filtering)
- [Sorting](#sorting)
- [HATEOAS (Optional)](#hateoas-optional)
- [Interview Questions](#interview-questions)
  - [Senior Developer Questions](#senior-developer-questions)
  - [Real-World Scenario Questions](#real-world-scenario-questions)

---

## Project Structure Overview

```
src/
├── config/
│   ├── database.js
│   ├── env.js
│   └── constants.js
├── controllers/
│   ├── userController.js
│   ├── productController.js
│   └── orderController.js
├── models/
│   ├── User.js
│   ├── Product.js
│   └── Order.js
├── services/
│   ├── userService.js
│   ├── productService.js
│   └── paymentService.js
├── repositories/
│   ├── userRepository.js
│   ├── productRepository.js
│   └── baseRepository.js
├── middlewares/
│   ├── auth.js
│   ├── validation.js
│   ├── errorHandler.js
│   └── rateLimiter.js
├── dtos/
│   ├── userDTO.js
│   ├── productDTO.js
│   └── requestDTO.js
├── utils/
│   ├── logger.js
│   ├── validators.js
│   ├── helpers.js
│   └── pagination.js
├── routes/
│   ├── v1/
│   │   ├── userRoutes.js
│   │   └── productRoutes.js
│   └── v2/
│       └── userRoutes.js
└── app.js
```

---

## MVC Pattern
=======
## 📚 Table of Contents
1. [Socket.io](#1-socketio)
2. [WebSockets Bare Implementation](#2-websockets-bare-implementation)
3. [Redis Pub/Sub](#3-redis-pubsub)
4. [Broadcasting Events](#4-broadcasting-events)
5. [Chat Applications](#5-chat-applications)
6. [Online/Offline Presence Detection](#6-onlineoffline-presence-detection)
7. [Interview Questions](#7-interview-questions)
8. [Real-World Scenarios](#8-real-world-scenarios)

---

## 1. Socket.io
>>>>>>> d0a590e89fef871f6721283530db2ba86930d6aa

### Overview
The Model-View-Controller pattern separates concerns into three components:
- **Models**: Represent data structures and business logic
- **Controllers**: Handle incoming requests and orchestrate responses
- **Views**: In API context, often replaced with response formatters

### Implementation Example

```javascript
// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);

// controllers/userController.js
const User = require('../models/User');
const userService = require('../services/userService');

class UserController {
  async getUsers(req, res, next) {
    try {
      const { page = 1, limit = 10 } = req.query;
      const users = await userService.getPaginatedUsers(page, limit);
      res.json(users);
    } catch (error) {
      next(error);
    }
  }

  async createUser(req, res, next) {
    try {
      const userData = req.body;
      const user = await userService.createUser(userData);
      res.status(201).json(user);
    } catch (error) {
      next(error);
    }
  }
}

// routes/userRoutes.js
const express = require('express');
const UserController = require('../controllers/userController');
const { validateUser } = require('../middlewares/validation');

const router = express.Router();
const userController = new UserController();

router.get('/', userController.getUsers.bind(userController));
router.post('/', validateUser, userController.createUser.bind(userController));

module.exports = router;
```

---

## Services Folder

### Purpose
Services contain business logic, acting as an intermediary between controllers and repositories. They handle complex business rules, transactions, and orchestration.

### Implementation Example

```javascript
// services/userService.js
const userRepository = require('../repositories/userRepository');
const emailService = require('./emailService');
const { UserDTO } = require('../dtos/userDTO');

class UserService {
  constructor() {
    this.userRepository = userRepository;
  }

  async createUser(userData) {
    // Business logic
    if (userData.email.includes('temp')) {
      throw new Error('Temporary emails not allowed');
    }

    // Check if user exists
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Create user
    const user = await this.userRepository.create(userData);

    // Send welcome email (async, don't await)
    emailService.sendWelcomeEmail(user.email).catch(console.error);

    // Return DTO
    return new UserDTO(user);
  }

  async getPaginatedUsers(page, limit, filters = {}) {
    const { data, total } = await this.userRepository.findPaginated(
      page, 
      limit, 
      filters
    );

    return {
      data: data.map(user => new UserDTO(user)),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }

  async updateUserProfile(userId, updateData) {
    // Complex business logic
    if (updateData.email) {
      await this.validateEmailChange(userId, updateData.email);
    }

    const updatedUser = await this.userRepository.update(userId, updateData);
    
    // Audit trail
    await this.auditService.logProfileUpdate(userId, updateData);

    return new UserDTO(updatedUser);
  }
}

module.exports = new UserService();
```

---

## Repositories

### Purpose
Repositories abstract data access logic, providing a clean API for data operations. They decouple the business logic from the data storage implementation.

### Implementation Example

```javascript
// repositories/baseRepository.js
class BaseRepository {
  constructor(model) {
    this.model = model;
  }

  async create(data) {
    return await this.model.create(data);
  }

  async findById(id, select = '') {
    return await this.model.findById(id).select(select);
  }

  async findOne(conditions) {
    return await this.model.findOne(conditions);
  }

  async find(conditions = {}, options = {}) {
    const { 
      skip = 0, 
      limit = 100, 
      sort = { createdAt: -1 },
      select = '' 
    } = options;

    return await this.model.find(conditions)
      .select(select)
      .skip(skip)
      .limit(limit)
      .sort(sort);
  }

  async update(id, data) {
    return await this.model.findByIdAndUpdate(
      id, 
      data, 
      { new: true, runValidators: true }
    );
  }

  async delete(id) {
    return await this.model.findByIdAndDelete(id);
  }

  async count(conditions = {}) {
    return await this.model.countDocuments(conditions);
  }
}

// repositories/userRepository.js
const User = require('../models/User');
const BaseRepository = require('./baseRepository');

class UserRepository extends BaseRepository {
  constructor() {
    super(User);
  }

  async findByEmail(email) {
    return await this.model.findOne({ email });
  }

  async findActiveUsers() {
    return await this.model.find({ 
      isActive: true,
      deletedAt: null 
    });
  }

  async findPaginated(page = 1, limit = 10, filters = {}) {
    const skip = (page - 1) * limit;
    
    const [data, total] = await Promise.all([
      this.model.find(filters)
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 }),
      this.model.countDocuments(filters)
    ]);

    return { data, total };
  }

  async searchUsers(searchTerm, page = 1, limit = 10) {
    const skip = (page - 1) * limit;
    const searchConditions = {
      $or: [
        { name: { $regex: searchTerm, $options: 'i' } },
        { email: { $regex: searchTerm, $options: 'i' } }
      ]
    };

    const [data, total] = await Promise.all([
      this.model.find(searchConditions)
        .skip(skip)
        .limit(limit),
      this.model.countDocuments(searchConditions)
    ]);

    return { data, total };
  }
}

module.exports = new UserRepository();
```

---

## DTOs (Data Transfer Objects)

### Purpose
DTOs define the shape of data transferred between layers, providing:
- Data validation
- Serialization control
- Versioning support
- Security (exclude sensitive fields)

### Implementation Example

```javascript
// dtos/baseDTO.js
class BaseDTO {
  constructor(data) {
    this.id = data._id || data.id;
    this.createdAt = data.createdAt;
    this.updatedAt = data.updatedAt;
  }

  toJSON() {
    return Object.getOwnPropertyNames(this).reduce((obj, key) => {
      if (this[key] !== undefined) {
        obj[key] = this[key];
      }
      return obj;
    }, {});
  }

  static fromArray(dataArray) {
    return dataArray.map(data => new this(data));
  }
}

// dtos/userDTO.js
const BaseDTO = require('./baseDTO');

class UserDTO extends BaseDTO {
  constructor(user) {
    super(user);
    this.email = user.email;
    this.name = user.name;
    this.role = user.role;
    this.isActive = user.isActive;
    
    // Exclude sensitive data
    // this.password = undefined;
    // this.resetPasswordToken = undefined;
  }

  static publicProfile(user) {
    const dto = new UserDTO(user);
    dto.email = undefined; // Hide email for public profiles
    return dto;
  }

  static adminView(user) {
    const dto = new UserDTO(user);
    dto.lastLogin = user.lastLogin;
    dto.loginAttempts = user.loginAttempts;
    return dto;
  }
}

// dtos/requestDTOs.js
class CreateUserRequestDTO {
  constructor(body) {
    this.email = body.email?.toLowerCase().trim();
    this.name = body.name?.trim();
    this.password = body.password;
    this.role = body.role || 'user';
  }

  validate() {
    const errors = [];
    
    if (!this.email || !this.email.includes('@')) {
      errors.push('Valid email is required');
    }
    
    if (!this.name || this.name.length < 2) {
      errors.push('Name must be at least 2 characters');
    }
    
    if (!this.password || this.password.length < 8) {
      errors.push('Password must be at least 8 characters');
    }
    
    if (errors.length > 0) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }
    
    return this;
  }
}

module.exports = { UserDTO, CreateUserRequestDTO };
```

---

## Middlewares Layer

### Purpose
Middlewares handle cross-cutting concerns like authentication, validation, logging, and error handling.

### Implementation Example

```javascript
// middlewares/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = {
  authenticate: async (req, res, next) => {
    try {
      const token = req.header('Authorization')?.replace('Bearer ', '');
      
      if (!token) {
        throw new Error('Authentication required');
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findOne({ 
        _id: decoded.userId, 
        'tokens.token': token 
      });

      if (!user) {
        throw new Error('User not found');
      }

      req.token = token;
      req.user = user;
      next();
    } catch (error) {
      res.status(401).json({ error: 'Please authenticate' });
    }
  },

  authorize: (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ 
          error: 'Insufficient permissions' 
        });
      }

      next();
    };
  },

  rateLimiter: require('express-rate-limit')({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
  })
};

// middlewares/validation.js
const { validationResult, body } = require('express-validator');

const validateRequest = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    res.status(400).json({
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value
      }))
    });
  };
};

const userValidationRules = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be 2-50 characters'),
  
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number')
];

// middlewares/errorHandler.js
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    Error.captureStackTrace(this, this.constructor);
  }
}

const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Development vs Production error responses
  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  } else {
    // Production: Don't leak error details
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
        message: 'Something went wrong'
      });
    }
  }
};

module.exports = { 
  authMiddleware, 
  validateRequest, 
  userValidationRules,
  AppError,
  errorHandler 
};
```

---

## Utils Folder

### Purpose
Utility functions for common tasks that don't fit into other layers.

### Implementation Example

```javascript
// utils/logger.js
const winston = require('winston');
const path = require('path');

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    new winston.transports.File({ 
      filename: path.join(__dirname, '../logs/error.log'), 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: path.join(__dirname, '../logs/combined.log') 
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

module.exports = logger;

// utils/pagination.js
class PaginationHelper {
  static getPaginationParams(query) {
    const page = Math.max(1, parseInt(query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 10));
    const skip = (page - 1) * limit;

    return { page, limit, skip };
  }

  static buildPaginationLinks(req, page, totalPages, totalItems, limit) {
    const baseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`;
    const query = { ...req.query };
    
    const links = {
      self: `${baseUrl}?${new URLSearchParams({ ...query, page })}`,
      first: `${baseUrl}?${new URLSearchParams({ ...query, page: 1 })}`,
      last: `${baseUrl}?${new URLSearchParams({ ...query, page: totalPages })}`
    };

    if (page > 1) {
      links.prev = `${baseUrl}?${new URLSearchParams({ ...query, page: page - 1 })}`;
    }

    if (page < totalPages) {
      links.next = `${baseUrl}?${new URLSearchParams({ ...query, page: page + 1 })}`;
    }

    return {
      total: totalItems,
      pages: totalPages,
      page,
      limit,
      links
    };
  }
}

// utils/validators.js
const validator = {
  isEmail: (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  },

  isStrongPassword: (password) => {
    const minLength = 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength && 
           hasUpper && 
           hasLower && 
           hasNumber && 
           hasSpecial;
  },

  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input;
    
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove HTML tags
      .replace(/\s+/g, ' ') // Normalize whitespace
      .substring(0, 1000); // Limit length
  }
};

module.exports = { logger, PaginationHelper, validator };
```

---

## Error Handling Structure

### Implementation Example

```javascript
// errors/customErrors.js
class ApiError extends Error {
  constructor(message, statusCode, details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends ApiError {
  constructor(errors) {
    super('Validation failed', 400, errors);
  }
}

class NotFoundError extends ApiError {
  constructor(resource) {
    super(`${resource || 'Resource'} not found`, 404);
  }
}

class AuthenticationError extends ApiError {
  constructor(message = 'Authentication required') {
    super(message, 401);
  }
}

class AuthorizationError extends ApiError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403);
  }
}

class RateLimitError extends ApiError {
  constructor(message = 'Too many requests') {
    super(message, 429);
  }
}

// middleware/errorHandler.js
const { ApiError } = require('../errors/customErrors');
const logger = require('../utils/logger');

const errorConverter = (err, req, res, next) => {
  let error = err;

  if (!(error instanceof ApiError)) {
    const statusCode = error.statusCode || 
                      (error instanceof mongoose.Error ? 400 : 500);
    const message = error.message || 'Internal Server Error';
    
    error = new ApiError(message, statusCode, error.details);
  }

  next(error);
};

const errorHandler = (err, req, res, next) => {
  const { statusCode, message, details } = err;

  // Log error
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user: req.user?._id
  });

  // Response
  const response = {
    status: 'error',
    message,
    ...(details && { details }),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  };

  res.status(statusCode || 500).json(response);
};

module.exports = { 
  ApiError,
  ValidationError,
  NotFoundError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  errorConverter,
  errorHandler 
};
```

---

## Separate Env Config

### Implementation Example

```javascript
// config/env.js
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables based on NODE_ENV
const envFile = process.env.NODE_ENV === 'test' 
  ? '.env.test' 
  : process.env.NODE_ENV === 'production' 
    ? '.env.production' 
    : '.env.development';

dotenv.config({ path: path.join(__dirname, '..', envFile) });

const requiredEnvVars = [
  'NODE_ENV',
  'PORT',
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_EXPIRES_IN'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
}

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  
  // Database
  MONGODB_URI: process.env.MONGODB_URI,
  
  // JWT
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  
  // Redis
  REDIS_URL: process.env.REDIS_URL,
  
  // AWS
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  AWS_REGION: process.env.AWS_REGION,
  S3_BUCKET_NAME: process.env.S3_BUCKET_NAME,
  
  // Email
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PASS: process.env.SMTP_PASS,
  
  // Logging
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  
  // Rate limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  
  // Security
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  
  // Feature flags
  FEATURE_NEW_API: process.env.FEATURE_NEW_API === 'true',
  
  // Validate configuration
  validate: () => {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long');
    }
    
    if (process.env.NODE_ENV === 'production' && process.env.CORS_ORIGIN === '*') {
      console.warn('Warning: CORS_ORIGIN is set to "*" in production');
    }
  }
};

// config/database.js
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const env = require('./env');

const connectDatabase = async () => {
  try {
    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4
    };

    await mongoose.connect(env.MONGODB_URI, options);
    
    logger.info('MongoDB connected successfully');
    
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (error) {
    logger.error('MongoDB connection failed:', error);
    process.exit(1);
  }
};

module.exports = { connectDatabase };
```

---

## Versioning APIs

### Implementation Example

```javascript
// app.js
const express = require('express');
const v1Routes = require('./routes/v1');
const v2Routes = require('./routes/v2');

const app = express();

// Route-based versioning
app.use('/api/v1', v1Routes);
app.use('/api/v2', v2Routes);

// Header-based versioning (alternative)
app.use('/api', (req, res, next) => {
  const apiVersion = req.headers['api-version'] || 'v1';
  
  if (apiVersion === 'v1') {
    return v1Routes(req, res, next);
  } else if (apiVersion === 'v2') {
    return v2Routes(req, res, next);
  }
  
  res.status(400).json({ error: 'Unsupported API version' });
});

// routes/v1/userRoutes.js
const express = require('express');
const router = express.Router();
const userControllerV1 = require('../../controllers/v1/userController');

// V1 endpoints
router.get('/users', userControllerV1.getUsers);
router.post('/users', userControllerV1.createUser);

module.exports = router;

// routes/v2/userRoutes.js
const express = require('express');
const router = express.Router();
const userControllerV2 = require('../../controllers/v2/userController');

// V2 endpoints with improvements
router.get('/users', userControllerV2.getUsers); // Includes pagination metadata
router.post('/users', userControllerV2.createUser); // Added email verification

module.exports = router;

// controllers/v2/userController.js
class UserControllerV2 {
  async getUsers(req, res) {
    const { page = 1, limit = 20 } = req.query;
    
    // Enhanced response with metadata
    const result = await userService.getUsersWithMetadata(page, limit);
    
    res.json({
      version: 'v2',
      timestamp: new Date().toISOString(),
      data: result.data,
      meta: {
        pagination: result.pagination,
        filters: req.query
      },
      links: {
        self: req.originalUrl,
        next: result.pagination.hasNext ? 
          `${req.baseUrl}?page=${page + 1}&limit=${limit}` : null
      }
    });
  }
}
```

---

## Pagination

### Implementation Example

```javascript
// services/paginationService.js
class PaginationService {
  static async paginate(model, query, options = {}) {
    const {
      page = 1,
      limit = 10,
      sort = { createdAt: -1 },
      select = '',
      populate = '',
      filters = {}
    } = options;

    const skip = (page - 1) * limit;
    const finalLimit = Math.min(limit, 100); // Prevent excessive limits

    // Build query
    const mongooseQuery = model.find(filters);

    // Apply additional filters from query params
    if (query.search) {
      mongooseQuery.or([
        { name: { $regex: query.search, $options: 'i' } },
        { email: { $regex: query.search, $options: 'i' } }
      ]);
    }

    if (query.status) {
      mongooseQuery.where({ status: query.status });
    }

    // Execute query with pagination
    const [data, total] = await Promise.all([
      mongooseQuery
        .clone()
        .select(select)
        .populate(populate)
        .skip(skip)
        .limit(finalLimit)
        .sort(sort)
        .lean(),
      mongooseQuery.countDocuments()
    ]);

    const totalPages = Math.ceil(total / finalLimit);

    return {
      data,
      pagination: {
        page: parseInt(page),
        limit: finalLimit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    };
  }

  static buildPaginationLinks(req, pagination) {
    const { page, limit, totalPages } = pagination;
    const baseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`;
    const query = { ...req.query };

    const links = {
      self: { href: `${baseUrl}?${new URLSearchParams({ ...query, page, limit })}` },
      first: { href: `${baseUrl}?${new URLSearchParams({ ...query, page: 1, limit })}` },
      last: { href: `${baseUrl}?${new URLSearchParams({ ...query, page: totalPages, limit })}` }
    };

    if (page > 1) {
      links.prev = { href: `${baseUrl}?${new URLSearchParams({ ...query, page: page - 1, limit })}` };
    }

    if (page < totalPages) {
      links.next = { href: `${baseUrl}?${new URLSearchParams({ ...query, page: page + 1, limit })}` };
    }

    return links;
  }
}

// Usage in controller
const getProducts = async (req, res) => {
  const { page = 1, limit = 20, sort = '-createdAt' } = req.query;
  
  const result = await PaginationService.paginate(Product, req.query, {
    page,
    limit,
    sort,
    select: 'name price category',
    populate: 'category',
    filters: { isActive: true }
  });

  const paginationLinks = PaginationService.buildPaginationLinks(req, result.pagination);

  res.json({
    success: true,
    count: result.data.length,
    pagination: result.pagination,
    links: paginationLinks,
    data: result.data
  });
};

// Cursor-based pagination (for real-time feeds)
class CursorPaginationService {
  static async paginateWithCursor(model, query, cursorField = '_id', limit = 20) {
    const { cursor, direction = 'next' } = query;
    let mongooseQuery = model.find();

    if (cursor) {
      if (direction === 'next') {
        mongooseQuery = mongooseQuery.where(cursorField).gt(cursor);
      } else {
        mongooseQuery = mongooseQuery.where(cursorField).lt(cursor);
      }
    }

    const data = await mongooseQuery
      .limit(limit + 1) // Fetch one extra to check for next page
      .sort({ [cursorField]: direction === 'next' ? 1 : -1 })
      .lean();

    const hasNextPage = data.length > limit;
    const hasPreviousPage = !!cursor;

    if (hasNextPage) {
      data.pop(); // Remove the extra item
    }

    return {
      data,
      pageInfo: {
        hasNextPage,
        hasPreviousPage,
        startCursor: data[0]?.[cursorField],
        endCursor: data[data.length - 1]?.[cursorField]
      }
    };
  }
}
```

---

## Filtering

### Implementation Example

```javascript
// utils/queryBuilder.js
class QueryBuilder {
  constructor(model, query) {
    this.model = model;
    this.query = query;
    this.filters = {};
    this.options = {};
  }

  filter() {
    // Text search
    if (this.query.search) {
      this.filters.$or = [
        { name: { $regex: this.query.search, $options: 'i' } },
        { description: { $regex: this.query.search, $options: 'i' } }
      ];
    }

    // Range filters
    if (this.query.minPrice || this.query.maxPrice) {
      this.filters.price = {};
      if (this.query.minPrice) {
        this.filters.price.$gte = parseFloat(this.query.minPrice);
      }
      if (this.query.maxPrice) {
        this.filters.price.$lte = parseFloat(this.query.maxPrice);
      }
    }

    // Date range filters
    if (this.query.startDate || this.query.endDate) {
      this.filters.createdAt = {};
      if (this.query.startDate) {
        this.filters.createdAt.$gte = new Date(this.query.startDate);
      }
      if (this.query.endDate) {
        this.filters.createdAt.$lte = new Date(this.query.endDate);
      }
    }

    // Boolean filters
    if (this.query.isActive !== undefined) {
      this.filters.isActive = this.query.isActive === 'true';
    }

    // Array filters (multiple values)
    if (this.query.categories) {
      const categories = Array.isArray(this.query.categories) 
        ? this.query.categories 
        : this.query.categories.split(',');
      this.filters.category = { $in: categories };
    }

    // Status filters
    if (this.query.status) {
      this.filters.status = this.query.status;
    }

    return this;
  }

  sort() {
    if (this.query.sort) {
      const sortFields = this.query.sort.split(',');
      this.options.sort = sortFields.reduce((sortObj, field) => {
        const order = field.startsWith('-') ? -1 : 1;
        const fieldName = field.replace(/^-/, '');
        sortObj[fieldName] = order;
        return sortObj;
      }, {});
    } else {
      this.options.sort = { createdAt: -1 };
    }

    return this;
  }

  paginate() {
    const page = Math.max(1, parseInt(this.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(this.query.limit) || 20));
    const skip = (page - 1) * limit;

    this.options.skip = skip;
    this.options.limit = limit;

    return this;
  }

  select() {
    if (this.query.fields) {
      this.options.select = this.query.fields.split(',').join(' ');
    }

    return this;
  }

  async execute() {
    const [data, total] = await Promise.all([
      this.model
        .find(this.filters)
        .select(this.options.select || '')
        .sort(this.options.sort || {})
        .skip(this.options.skip || 0)
        .limit(this.options.limit || 0)
        .lean(),
      this.model.countDocuments(this.filters)
    ]);

    return {
      data,
      total,
      page: Math.floor((this.options.skip || 0) / (this.options.limit || 20)) + 1,
      limit: this.options.limit || 20,
      totalPages: Math.ceil(total / (this.options.limit || 20))
    };
  }
}

// Usage in controller
const getProducts = async (req, res) => {
  try {
    const queryBuilder = new QueryBuilder(Product, req.query)
      .filter()
      .sort()
      .paginate()
      .select();

    const result = await queryBuilder.execute();

    res.json({
      success: true,
      count: result.data.length,
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.total,
        pages: result.totalPages
      },
      filters: req.query,
      data: result.data
    });
  } catch (error) {
    next(error);
  }
};

// Advanced filtering with operators
class AdvancedQueryBuilder extends QueryBuilder {
  constructor(model, query) {
    super(model, query);
    this.operatorsMap = {
      'gt': '$gt',
      'gte': '$gte',
      'lt': '$lt',
      'lte': '$lte',
      'ne': '$ne',
      'in': '$in',
      'nin': '$nin',
      'exists': '$exists',
      'regex': '$regex'
    };
  }

  parseAdvancedFilters() {
    Object.keys(this.query).forEach(key => {
      if (key.includes('[') && key.includes(']')) {
        const match = key.match(/(\w+)\[(\w+)\]/);
        if (match) {
          const [, field, operator] = match;
          const value = this.query[key];
          
          if (this.operatorsMap[operator]) {
            if (!this.filters[field]) {
              this.filters[field] = {};
            }
            
            this.filters[field][this.operatorsMap[operator]] = 
              this.parseValue(value, operator);
          }
        }
      }
    });

    return this;
  }

  parseValue(value, operator) {
    switch (operator) {
      case 'in':
      case 'nin':
        return value.split(',');
      case 'regex':
        return new RegExp(value, 'i');
      case 'exists':
        return value === 'true';
      default:
        return isNaN(value) ? value : Number(value);
    }
  }
}
```

---

<<<<<<< HEAD
## Sorting
=======
## 2. WebSockets Bare Implementation
>>>>>>> d0a590e89fef871f6721283530db2ba86930d6aa

### Implementation Example

```javascript
// utils/sortBuilder.js
class SortBuilder {
  static parseSortQuery(sortQuery, defaultSort = { createdAt: -1 }) {
    if (!sortQuery) {
      return defaultSort;
    }

    const sortFields = sortQuery.split(',');
    return sortFields.reduce((sortObj, field) => {
      const order = field.startsWith('-') ? -1 : 1;
      const fieldName = field.replace(/^-/, '');
      
      // Validate field name (prevent NoSQL injection)
      const validFields = ['createdAt', 'updatedAt', 'name', 'price', 'rating'];
      if (validFields.includes(fieldName)) {
        sortObj[fieldName] = order;
      }
      
      return sortObj;
    }, {});
  }

  static buildMongoSort(sortConfig) {
    const mongoSort = {};
    
    Object.entries(sortConfig).forEach(([field, order]) => {
      // Handle nested sorting
      if (field.includes('.')) {
        const [parent, child] = field.split('.');
        mongoSort[parent] = mongoSort[parent] || {};
        mongoSort[parent][child] = order;
      } else {
        mongoSort[field] = order;
      }
    });

    return mongoSort;
  }

  static validateSortFields(requestedFields, allowedFields) {
    const invalidFields = requestedFields.filter(
      field => !allowedFields.includes(field.replace(/^-/, ''))
    );
    
    if (invalidFields.length > 0) {
      throw new Error(`Invalid sort fields: ${invalidFields.join(', ')}`);
    }
  }
}

// Usage examples
const sortOptions = {
  // Simple sort
  simple: SortBuilder.parseSortQuery('-createdAt,name'),
  
  // With validation
  validated: (sortQuery) => {
    const allowedFields = ['createdAt', 'name', 'price', 'rating'];
    const fields = sortQuery ? sortQuery.split(',') : [];
    
    SortBuilder.validateSortFields(fields, allowedFields);
    return SortBuilder.parseSortQuery(sortQuery);
  },
  
  // Complex nested sort
  nested: SortBuilder.parseSortQuery('author.name,-createdAt')
};

// In repository
class ProductRepository {
  async findSortedProducts(sortQuery, filters = {}) {
    const sortConfig = SortBuilder.parseSortQuery(sortQuery, { createdAt: -1 });
    
    return await Product.find(filters)
      .sort(SortBuilder.buildMongoSort(sortConfig))
      .populate('category')
      .lean();
  }
}

// Dynamic sorting based on user preferences
class DynamicSortService {
  static getSortPreference(userId, defaultSort) {
    // Could fetch from user preferences in database
    const userPreferences = {
      'customer': { price: 1 },
      'admin': { createdAt: -1 },
      'analyst': { sales: -1, rating: -1 }
    };

    return userPreferences[userId] || defaultSort;
  }

  static applySmartSort(query, context) {
    let sortConfig = { createdAt: -1 };

    // Time-based sorting (trending content)
    if (context === 'trending') {
      const now = new Date();
      const oneWeekAgo = new Date(now.setDate(now.getDate() - 7));
      
      // Weighted score: (likes * 2) + comments - (age in hours)
      return {
        $sort: {
          $add: [
            { $multiply: ['$likesCount', 2] },
            '$commentsCount',
            { $multiply: [
              { $divide: [
                { $subtract: [new Date(), '$createdAt'] },
                1000 * 60 * 60 // Convert to hours
              ]},
              -1
            ]}
          ]
        }
      };
    }

    // Popularity-based sorting
    if (context === 'popular') {
      sortConfig = { 
        rating: -1, 
        reviewsCount: -1,
        createdAt: -1 
      };
    }

    // Price sorting with intelligence
    if (context === 'value') {
      // Sort by price per unit or other value metric
      return { pricePerUnit: 1, rating: -1 };
    }

    return sortConfig;
  }
}
```

---

## HATEOAS (Optional)

### Implementation Example

```javascript
// utils/hateoas.js
class HATEOASBuilder {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.links = [];
  }

  addLink(rel, href, method = 'GET', description = '') {
    this.links.push({
      rel,
      href: `${this.baseUrl}${href}`,
      method,
      description
    });
    return this;
  }

  addSelfLink(path) {
    return this.addLink('self', path, 'GET', 'Current resource');
  }

  addCreateLink(path) {
    return this.addLink('create', path, 'POST', 'Create new resource');
  }

  addUpdateLink(path) {
    return this.addLink('update', path, 'PUT', 'Update resource');
  }

  addDeleteLink(path) {
    return this.addLink('delete', path, 'DELETE', 'Delete resource');
  }

  addPaginationLinks(page, limit, totalPages, currentPath) {
    if (page > 1) {
      this.addLink('prev', `${currentPath}?page=${page - 1}&limit=${limit}`, 'GET', 'Previous page');
    }
    
    if (page < totalPages) {
      this.addLink('next', `${currentPath}?page=${page + 1}&limit=${limit}`, 'GET', 'Next page');
    }
    
    this.addLink('first', `${currentPath}?page=1&limit=${limit}`, 'GET', 'First page');
    this.addLink('last', `${currentPath}?page=${totalPages}&limit=${limit}`, 'GET', 'Last page');
    
    return this;
  }

  build() {
    return this.links;
  }
}

// Usage in controller
const getUser = async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const hateoas = new HATEOASBuilder(req.protocol + '://' + req.get('host'));
  
  const response = {
    ...user.toObject(),
    _links: hateoas
      .addSelfLink(`/api/v1/users/${user._id}`)
      .addUpdateLink(`/api/v1/users/${user._id}`)
      .addDeleteLink(`/api/v1/users/${user._id}`)
      .addLink('users', '/api/v1/users', 'GET', 'All users')
      .addLink('profile', `/api/v1/users/${user._id}/profile`, 'GET', 'User profile')
      .build()
  };

  res.json(response);
};

// Collection response with HATEOAS
const getUsers = async (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  
  const result = await User.paginate({}, { page, limit });
  
  const hateoas = new HATEOASBuilder(req.protocol + '://' + req.get('host'));
  
  const response = {
    data: result.docs.map(user => ({
      ...user.toObject(),
      _links: new HATEOASBuilder(req.protocol + '://' + req.get('host'))
        .addSelfLink(`/api/v1/users/${user._id}`)
        .build()
    })),
    _links: hateoas
      .addSelfLink(req.originalUrl)
      .addCreateLink('/api/v1/users')
      .addPaginationLinks(
        result.page, 
        result.limit, 
        result.totalPages,
        '/api/v1/users'
      )
      .build(),
    pagination: {
      page: result.page,
      limit: result.limit,
      total: result.total,
      pages: result.totalPages
    }
  };

  res.json(response);
};

// Advanced HATEOAS with action discovery
class ActionAwareHATEOAS extends HATEOASBuilder {
  constructor(baseUrl, userRole) {
    super(baseUrl);
    this.userRole = userRole;
    this.actions = [];
  }

  addAction(action, href, method, conditions = {}) {
    if (this.checkConditions(conditions)) {
      this.actions.push({
        action,
        href: `${this.baseUrl}${href}`,
        method,
        conditions
      });
    }
    return this;
  }

  checkConditions(conditions) {
    if (conditions.role && !conditions.role.includes(this.userRole)) {
      return false;
    }
    
    if (conditions.status) {
      // Check resource status or other conditions
    }
    
    return true;
  }

<<<<<<< HEAD
  buildFullResponse(resource) {
    return {
      ...resource,
      _links: this.links,
      _actions: this.actions,
      _metadata: {
        version: '1.0',
        timestamp: new Date().toISOString()
=======
  isRateLimited(ws, type = 'message') {
    // Different limits for different types
    const limits = {
      message: { limit: 60, windowMs: 60000 }, // 60 messages per minute
      connection: { limit: 10, windowMs: 3600000 }, // 10 connections per hour
      join: { limit: 30, windowMs: 60000 } // 30 room joins per minute
    };
    
    const config = limits[type] || limits.message;
    return !this.checkLimit(ws, type, config.limit, config.windowMs);
  }

  cleanup() {
    const now = Date.now();
    
    for (const [key, limitInfo] of this.limits) {
      if (now > limitInfo.resetTime) {
        this.limits.delete(key);
      }
    }
  }
}
```

---

## 3. Redis Pub/Sub

### Overview
Redis Pub/Sub (Publish/Subscribe) is a messaging pattern where senders (publishers) send messages to channels without knowing who will receive them, and receivers (subscribers) express interest in channels to receive messages.

### Architecture
```
┌────────────┐     publish     ┌─────────┐     subscribe     ┌─────────────┐
│ Publisher  │ ──────────────► │ Redis   │ ◄──────────────── │ Subscriber  │
│  (Server)  │                 │ Pub/Sub │                   │   (Server)  │
└────────────┘                 └─────────┘                   └─────────────┘
                                      │
                                      │ subscribe
                                      ▼
                               ┌─────────────┐
                               │ Subscriber  │
                               │   (Server)  │
                               └─────────────┘
```

### Basic Implementation

#### Setup and Configuration
```javascript
const redis = require('redis');

class RedisPubSub {
  constructor() {
    this.publisher = redis.createClient({
      url: process.env.REDIS_URL,
      socket: {
        reconnectStrategy: (retries) => {
          const delay = Math.min(retries * 100, 3000);
          return delay;
        }
      }
    });
    
    this.subscriber = this.publisher.duplicate();
    this.channelHandlers = new Map();
    this.patternHandlers = new Map();
    
    this.setupEventHandlers();
    this.connect();
  }

  async connect() {
    await this.publisher.connect();
    await this.subscriber.connect();
    console.log('Redis Pub/Sub connected');
  }

  setupEventHandlers() {
    // Message handler for subscribed channels
    this.subscriber.on('message', (channel, message) => {
      this.handleMessage(channel, message);
    });
    
    // Message handler for pattern subscriptions
    this.subscriber.on('pmessage', (pattern, channel, message) => {
      this.handlePatternMessage(pattern, channel, message);
    });
    
    // Error handlers
    this.publisher.on('error', (error) => {
      console.error('Redis publisher error:', error);
    });
    
    this.subscriber.on('error', (error) => {
      console.error('Redis subscriber error:', error);
    });
    
    // Reconnect handlers
    this.publisher.on('connect', () => {
      console.log('Redis publisher reconnected');
      // Resubscribe to channels
      this.resubscribe();
    });
    
    this.subscriber.on('connect', () => {
      console.log('Redis subscriber reconnected');
    });
  }

  async subscribe(channel, handler) {
    try {
      await this.subscriber.subscribe(channel, (message) => {
        handler(message, channel);
      });
      
      // Store handler for reconnection
      if (!this.channelHandlers.has(channel)) {
        this.channelHandlers.set(channel, new Set());
      }
      this.channelHandlers.get(channel).add(handler);
      
      console.log(`Subscribed to channel: ${channel}`);
      return true;
    } catch (error) {
      console.error(`Subscribe error for channel ${channel}:`, error);
      return false;
    }
  }

  async unsubscribe(channel, handler = null) {
    try {
      if (handler) {
        // Remove specific handler
        const handlers = this.channelHandlers.get(channel);
        if (handlers) {
          handlers.delete(handler);
          if (handlers.size === 0) {
            await this.subscriber.unsubscribe(channel);
            this.channelHandlers.delete(channel);
          }
        }
      } else {
        // Remove all handlers and unsubscribe
        await this.subscriber.unsubscribe(channel);
        this.channelHandlers.delete(channel);
      }
      
      console.log(`Unsubscribed from channel: ${channel}`);
      return true;
    } catch (error) {
      console.error(`Unsubscribe error for channel ${channel}:`, error);
      return false;
    }
  }

  async psubscribe(pattern, handler) {
    try {
      await this.subscriber.pSubscribe(pattern, (message, channel) => {
        handler(message, channel);
      });
      
      // Store pattern handler
      if (!this.patternHandlers.has(pattern)) {
        this.patternHandlers.set(pattern, new Set());
      }
      this.patternHandlers.get(pattern).add(handler);
      
      console.log(`Subscribed to pattern: ${pattern}`);
      return true;
    } catch (error) {
      console.error(`Pattern subscribe error for ${pattern}:`, error);
      return false;
    }
  }

  async publish(channel, message) {
    try {
      const serialized = typeof message === 'string' 
        ? message 
        : JSON.stringify(message);
      
      const result = await this.publisher.publish(channel, serialized);
      console.log(`Published to ${channel}:`, result);
      return result;
    } catch (error) {
      console.error(`Publish error for channel ${channel}:`, error);
      throw error;
    }
  }

  handleMessage(channel, message) {
    const handlers = this.channelHandlers.get(channel);
    if (!handlers) return;
    
    let parsedMessage;
    try {
      parsedMessage = JSON.parse(message);
    } catch {
      parsedMessage = message;
    }
    
    handlers.forEach(handler => {
      try {
        handler(parsedMessage, channel);
      } catch (error) {
        console.error(`Handler error for channel ${channel}:`, error);
      }
    });
  }

  handlePatternMessage(pattern, channel, message) {
    const handlers = this.patternHandlers.get(pattern);
    if (!handlers) return;
    
    let parsedMessage;
    try {
      parsedMessage = JSON.parse(message);
    } catch {
      parsedMessage = message;
    }
    
    handlers.forEach(handler => {
      try {
        handler(parsedMessage, channel);
      } catch (error) {
        console.error(`Pattern handler error for ${pattern}:`, error);
      }
    });
  }

  async resubscribe() {
    // Resubscribe to channels
    for (const [channel, handlers] of this.channelHandlers) {
      await this.subscriber.subscribe(channel, (message) => {
        this.handleMessage(channel, message);
      });
    }
    
    // Resubscribe to patterns
    for (const [pattern, handlers] of this.patternHandlers) {
      await this.subscriber.pSubscribe(pattern, (message, channel) => {
        this.handlePatternMessage(pattern, channel, message);
      });
    }
  }

  async disconnect() {
    await this.subscriber.quit();
    await this.publisher.quit();
  }
}
```

### Advanced Patterns

#### 1. Namespaced Channels
```javascript
class NamespacedPubSub extends RedisPubSub {
  constructor(namespace = 'app') {
    super();
    this.namespace = namespace;
  }

  getChannelName(channel) {
    return `${this.namespace}:${channel}`;
  }

  async subscribe(channel, handler) {
    const namespacedChannel = this.getChannelName(channel);
    return super.subscribe(namespacedChannel, handler);
  }

  async publish(channel, message) {
    const namespacedChannel = this.getChannelName(channel);
    return super.publish(namespacedChannel, message);
  }

  async subscribeToNamespace(handler) {
    // Subscribe to all channels in namespace
    return this.psubscribe(`${this.namespace}:*`, handler);
  }
}

// Usage
const pubsub = new NamespacedPubSub('chat');
await pubsub.subscribe('room:general', (message) => {
  console.log('General room message:', message);
});

await pubsub.publish('room:general', { text: 'Hello!' });
```

#### 2. Reliable Message Delivery with Redis Streams
```javascript
class ReliableRedisPubSub extends RedisPubSub {
  constructor() {
    super();
    this.pendingMessages = new Map();
    this.consumerGroup = 'websocket-servers';
    this.consumerName = `server-${process.pid}`;
  }

  async publishWithDeliveryGuarantee(channel, message, options = {}) {
    const {
      maxRetries = 3,
      ttl = 3600 // 1 hour
    } = options;
    
    const messageId = this.generateMessageId();
    const envelope = {
      id: messageId,
      channel,
      message,
      metadata: {
        publishedAt: Date.now(),
        ttl,
        attempts: 0,
        maxRetries
>>>>>>> d0a590e89fef871f6721283530db2ba86930d6aa
      }
    };
  }
}

// Usage with role-based actions
const getOrder = async (req, res) => {
  const order = await Order.findById(req.params.id)
    .populate('user', 'name email');
  
  const hateoas = new ActionAwareHATEOAS(
    req.protocol + '://' + req.get('host'),
    req.user.role
  );

  // Always available links
  hateoas
    .addSelfLink(`/api/v1/orders/${order._id}`)
    .addLink('user', `/api/v1/users/${order.user._id}`, 'GET', 'Order user');

  // Role-based actions
  hateoas
    .addAction('cancel', `/api/v1/orders/${order._id}/cancel`, 'POST', {
      role: ['customer', 'admin'],
      status: ['pending', 'processing']
    })
    .addAction('refund', `/api/v1/orders/${order._id}/refund`, 'POST', {
      role: ['admin'],
      status: ['completed', 'shipped']
    })
    .addAction('ship', `/api/v1/orders/${order._id}/ship`, 'POST', {
      role: ['admin', 'shipping_manager'],
      status: ['processing']
    });

  const response = hateoas.buildFullResponse(order.toObject());
  
  res.json(response);
};
```

---

<<<<<<< HEAD
## Interview Questions
=======
## 4. Broadcasting Events
>>>>>>> d0a590e89fef871f6721283530db2ba86930d6aa

### Senior Developer Questions

#### MVC Pattern
1. **Q:** How does MVC differ in API development compared to traditional web applications?
   **A:** In API development, the "View" component is often replaced with response formatters or serializers. Controllers return data (JSON/XML) instead of rendered HTML templates.

2. **Q:** When would you choose to deviate from strict MVC in API design?
   **A:** When implementing CQRS (Command Query Responsibility Segregation), where read and write operations are separated, or when using Hexagonal Architecture with ports and adapters.

3. **Q:** How do you handle shared business logic that doesn't fit neatly into MVC?
   **A:** Create service classes or domain services that encapsulate cross-cutting business logic, keeping controllers thin and focused on HTTP concerns.

#### Services Layer
1. **Q:** What criteria do you use to decide what logic goes in services vs repositories?
   **A:** Repositories handle data access and simple CRUD. Services contain business logic, orchestration, transaction management, and interactions between multiple repositories.

2. **Q:** How do you prevent services from becoming "God objects"?
   **A:** Apply Single Responsibility Principle, use dependency injection, create specialized services (EmailService, PaymentService), and consider Domain-Driven Design aggregates.

3. **Q:** How do you manage transactions across multiple service calls?
   **A:** Use unit of work pattern, database transactions, or implement saga pattern for distributed transactions in microservices.

#### Repositories
1. **Q:** What are the benefits of repository pattern over directly using ORM in controllers?
   **A:** Abstraction of data layer, easier testing (mocking), centralized query logic, ability to switch data sources, and enforcing data access patterns.

2. **Q:** How do you handle complex queries with multiple joins and aggregations?
   **A:** Create specialized query methods in repositories, use query builders, or implement specification pattern for complex filtering.

<<<<<<< HEAD
3. **Q:** What's your approach to caching in repositories?
   **A:** Implement caching decorator pattern, use Redis for distributed caching, set appropriate TTLs, and implement cache invalidation strategies.

#### DTOs
1. **Q:** When would you use DTOs vs directly returning domain models?
   **A:** Always use DTOs for API responses to control serialization, hide sensitive data, transform data structures, and maintain backward compatibility.

2. **Q:** How do you handle DTO validation and mapping complexity?
   **A:** Use class-validator decorators, implement mapper classes/patterns (like MapStruct), or use serialization libraries with custom transformers.

3. **Q:** What's your strategy for versioning DTOs in long-lived APIs?
   **A:** Create versioned DTO classes, use composition over inheritance, maintain backward compatibility, and document breaking changes.

#### Error Handling
1. **Q:** How do you design a comprehensive error handling strategy?
   **A:** Create custom error hierarchy, implement global error middleware, log errors with context, return appropriate HTTP status codes, and provide helpful error messages.

2. **Q:** What's your approach to handling and logging uncaught exceptions?
   **A:** Use process-level error handlers (uncaughtException, unhandledRejection), log to centralized logging system, and implement graceful shutdown.

3. **Q:** How do you handle partial failures in distributed systems?
   **A:** Implement retry logic with exponential backoff, circuit breakers, fallback mechanisms, and graceful degradation.

#### API Design
1. **Q:** How do you decide between REST, GraphQL, or gRPC for a new API?
   **A:** REST for simple CRUD, GraphQL for complex data requirements with multiple clients, gRPC for internal microservices requiring high performance.

2. **Q:** What factors influence your API versioning strategy?
   **A:** Rate of change, number of clients, backward compatibility requirements, and deployment complexity.

3. **Q:** How do you design APIs for scalability?
   **A:** Implement pagination, filtering, sorting, caching strategies, rate limiting, and consider eventual consistency where appropriate.

### Real-World Scenario Questions

#### Scenario 1: E-commerce Platform Migration
**Q:** You're migrating a monolithic e-commerce API to microservices. The current system has tightly coupled order processing, inventory management, and payment processing. How would you approach this migration while maintaining zero downtime?

**Expected Answer:**
- Start with strangler pattern, gradually extracting bounded contexts
- Implement API gateway for routing
- Use event-driven architecture with message queues
- Implement compensating transactions for distributed systems
- Create comprehensive testing strategy including contract tests
- Implement feature flags for gradual rollout

#### Scenario 2: High-Traffic Social Media API
**Q:** Your social media API is experiencing 10x traffic growth. Users complain about slow feed loading and frequent timeouts. How would you optimize and scale the system?

**Expected Answer:**
- Implement Redis caching for frequently accessed data
- Use CDN for media content
- Implement pagination with cursor-based approach
- Database read replicas and sharding
- Optimize database queries with indexing
- Implement rate limiting and request queuing
- Use async processing for non-critical operations

#### Scenario 3: Financial Transaction API
**Q:** You're building a financial transactions API that must be highly secure, auditable, and support idempotent operations. How would you design this?

**Expected Answer:**
- Implement idempotency keys for all POST/PUT operations
- Comprehensive audit logging with immutable logs
- Use HTTPS with TLS 1.3, implement API keys and OAuth 2.0
- Rate limiting per user/account
- Transaction validation and fraud detection
- Database transactions with rollback capability
- Regular security audits and penetration testing

#### Scenario 4: Multi-Tenant SaaS API
**Q:** Your SaaS platform needs to support 1000+ tenants with data isolation, custom configurations, and tenant-specific rate limiting. How would you design the architecture?

**Expected Answer:**
- Database per tenant or schema per tenant pattern
- Tenant context middleware for request isolation
- Tenant-aware connection pooling
- Customizable rate limiting per tenant
- Tenant-specific configuration management
- Shared caching with tenant prefixing
- Bulk operations with tenant filtering

#### Scenario 5: Real-time Collaboration API
**Q:** You're building a real-time collaborative document editing API similar to Google Docs. Multiple users can edit simultaneously with sub-second latency requirements. How would you design this?

**Expected Answer:**
- WebSocket connections for real-time updates
- Operational transformation or CRDT for conflict resolution
- Redis Pub/Sub for message broadcasting
- Version control for document history
- Presence tracking for online users
- Optimistic UI updates with rollback capability
- Load balancing with sticky sessions for WebSocket connections

#### Scenario 6: Legacy API Modernization
**Q:** You inherit a legacy SOAP API that needs to be modernized to REST while maintaining backward compatibility for existing clients. How would you approach this?

**Expected Answer:**
- Create REST API alongside existing SOAP API
- Implement API gateway to route requests
- Create adapter layer to transform between protocols
- Gradual migration plan with client communication
- Version both APIs during transition
- Comprehensive testing to ensure parity
- Deprecation timeline for SOAP API

#### Scenario 7: Global API with Data Residency Requirements
**Q:** Your API needs to serve users globally while complying with GDPR, CCPA, and data residency requirements in different regions. How would you architect this?

**Expected Answer:**
- Multi-region deployment strategy
- Data residency-aware routing
- Regional database instances
- Geo-distributed caching (Redis Cluster)
- Data anonymization and pseudonymization
- Consent management system
- Data deletion and export capabilities
- Regular compliance audits

These scenarios test architectural thinking, trade-off analysis, and practical implementation skills that are crucial for senior developers.
=======
  // Broadcast to multiple rooms
  broadcastToRooms(roomIds, event, data) {
    roomIds.forEach(roomId => {
      this.io.to(roomId).emit(event, data);
      this.updateRoomStats(roomId, event);
    });
  }

  // Broadcast to all rooms except some
  broadcastToAllExceptRooms(excludedRoomIds, event, data) {
    const rooms = this.getAllRooms();
    const targetRooms = rooms.filter(room => !excludedRoomIds.includes(room));
    
    targetRooms.forEach(roomId => {
      this.io.to(roomId).emit(event, data);
      this.updateRoomStats(roomId, event);
    });
  }

  // Get all active rooms
  getAllRooms() {
    return Array.from(this.io.sockets.adapter.rooms.keys())
      .filter(room => !this.io.sockets.adapter.sids.has(room)); // Exclude socket IDs
  }

  updateRoomStats(roomId, event) {
    if (!this.roomStats.has(roomId)) {
      this.roomStats.set(roomId, {
        messageCount: 0,
        lastMessage: null,
        events: new Map()
      });
    }
    
    const stats = this.roomStats.get(roomId);
    stats.messageCount++;
    stats.lastMessage = {
      event,
      timestamp: Date.now()
    };
    
    const eventCount = stats.events.get(event) || 0;
    stats.events.set(event, eventCount + 1);
  }

  getRoomStats(roomId) {
    return this.roomStats.get(roomId) || {
      messageCount: 0,
      lastMessage: null,
      events: new Map()
    };
  }
}
```

#### 3. User-based Broadcasting
```javascript
class UserBroadcaster {
  constructor(io) {
    this.io = io;
    this.userSockets = new Map(); // userId -> Set of socketIds
  }

  // Register user socket
  registerUserSocket(userId, socketId) {
    if (!this.userSockets.has(userId)) {
      this.userSockets.set(userId, new Set());
    }
    this.userSockets.get(userId).add(socketId);
  }

  // Unregister user socket
  unregisterUserSocket(userId, socketId) {
    const userSockets = this.userSockets.get(userId);
    if (userSockets) {
      userSockets.delete(socketId);
      if (userSockets.size === 0) {
        this.userSockets.delete(userId);
      }
    }
  }

  // Broadcast to specific user (all their sockets)
  broadcastToUser(userId, event, data) {
    const userSockets = this.userSockets.get(userId);
    if (!userSockets) return 0;

    let sentCount = 0;
    
    userSockets.forEach(socketId => {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket && socket.connected) {
        socket.emit(event, data);
        sentCount++;
      }
    });
    
    return sentCount;
  }

  // Broadcast to multiple users
  broadcastToUsers(userIds, event, data) {
    let totalSent = 0;
    
    userIds.forEach(userId => {
      totalSent += this.broadcastToUser(userId, event, data);
    });
    
    return totalSent;
  }

  // Broadcast to all users except some
  broadcastToAllExceptUsers(excludedUserIds, event, data) {
    const allUserIds = Array.from(this.userSockets.keys());
    const targetUserIds = allUserIds.filter(userId => 
      !excludedUserIds.includes(userId)
    );
    
    return this.broadcastToUsers(targetUserIds, event, data);
  }

  // Check if user is online
  isUserOnline(userId) {
    const userSockets = this.userSockets.get(userId);
    if (!userSockets) return false;
    
    // Check if any socket is still connected
    for (const socketId of userSockets) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket && socket.connected) {
        return true;
      }
    }
    
    return false;
  }

  // Get all online users
  getOnlineUsers() {
    const onlineUsers = [];
    
    for (const [userId, socketIds] of this.userSockets) {
      for (const socketId of socketIds) {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket && socket.connected) {
          onlineUsers.push(userId);
          break; // User is online, move to next user
        }
      }
    }
    
    return onlineUsers;
  }
}
```

### Advanced Broadcasting Techniques

#### 1. Conditional Broadcasting
```javascript
class ConditionalBroadcaster {
  constructor(io) {
    this.io = io;
    this.conditions = new Map(); // event -> condition function
  }

  // Register conditional broadcast
  registerCondition(event, conditionFn) {
    this.conditions.set(event, conditionFn);
  }

  // Conditional broadcast
  conditionalBroadcast(event, data, context = {}) {
    const conditionFn = this.conditions.get(event);
    
    if (!conditionFn) {
      // No condition, broadcast to all
      this.io.emit(event, data);
      return this.io.sockets.sockets.size;
    }
    
    let broadcastCount = 0;
    
    // Check each socket against condition
    this.io.sockets.sockets.forEach(socket => {
      if (socket.connected && conditionFn(socket, data, context)) {
        socket.emit(event, data);
        broadcastCount++;
      }
    });
    
    return broadcastCount;
  }

  // Example condition: broadcast only to admins
  setupAdminOnlyBroadcast() {
    this.registerCondition('admin-alert', (socket, data, context) => {
      return socket.user?.role === 'admin';
    });
  }

  // Example condition: broadcast based on user location
  setupLocationBasedBroadcast() {
    this.registerCondition('local-news', (socket, data, context) => {
      const userLocation = socket.user?.location;
      const newsLocation = data.location;
      
      if (!userLocation || !newsLocation) return false;
      
      // Simple distance calculation (in production, use proper geospatial query)
      const distance = this.calculateDistance(
        userLocation.lat, userLocation.lng,
        newsLocation.lat, newsLocation.lng
      );
      
      return distance <= 50; // Within 50km
    });
  }

  calculateDistance(lat1, lon1, lat2, lon2) {
    // Haversine formula
    const R = 6371; // Earth's radius in km
    const dLat = this.toRad(lat2 - lat1);
    const dLon = this.toRad(lon2 - lon1);
    
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(this.toRad(lat1)) * Math.cos(this.toRad(lat2)) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  toRad(degrees) {
    return degrees * (Math.PI / 180);
  }
}
```

#### 2. Batched Broadcasting for Performance
```javascript
class BatchedBroadcaster {
  constructor(io, batchSize = 10, batchTimeout = 100) {
    this.io = io;
    this.batchSize = batchSize;
    this.batchTimeout = batchTimeout;
    this.batches = new Map(); // roomId -> batch
    this.messageCount = 0;
  }

  // Add message to batch
  broadcastToRoomBatch(roomId, event, data) {
    if (!this.batches.has(roomId)) {
      this.batches.set(roomId, {
        messages: [],
        timeout: null
      });
    }
    
    const batch = this.batches.get(roomId);
    batch.messages.push({ event, data, timestamp: Date.now() });
    this.messageCount++;
    
    // Check if batch is full
    if (batch.messages.length >= this.batchSize) {
      this.flushBatch(roomId);
    } else if (!batch.timeout) {
      // Set timeout for batch flush
      batch.timeout = setTimeout(() => {
        this.flushBatch(roomId);
      }, this.batchTimeout);
    }
    
    return this.messageCount;
  }

  // Flush batch to room
  flushBatch(roomId) {
    const batch = this.batches.get(roomId);
    if (!batch || batch.messages.length === 0) {
      return;
    }
    
    if (batch.timeout) {
      clearTimeout(batch.timeout);
      batch.timeout = null;
    }
    
    const messages = batch.messages;
    batch.messages = [];
    
    // Send batched messages
    this.io.to(roomId).emit('batched-messages', {
      messages,
      count: messages.length,
      timestamp: Date.now()
    });
    
    // Remove empty batch
    if (batch.messages.length === 0) {
      this.batches.delete(roomId);
    }
  }

  // Flush all batches
  flushAll() {
    for (const roomId of this.batches.keys()) {
      this.flushBatch(roomId);
    }
  }

  // Get batch statistics
  getBatchStats() {
    const stats = {
      totalBatches: this.batches.size,
      totalMessages: this.messageCount,
      batches: []
    };
    
    for (const [roomId, batch] of this.batches) {
      stats.batches.push({
        roomId,
        messageCount: batch.messages.length,
        hasTimeout: !!batch.timeout
      });
    }
    
    return stats;
  }

  // Reset statistics
  resetStats() {
    this.messageCount = 0;
  }
}
```

#### 3. Priority-based Broadcasting
```javascript
class PriorityBroadcaster {
  constructor(io) {
    this.io = io;
    this.priorityQueues = new Map(); // priority -> queue
    this.currentPriority = 0;
    this.isProcessing = false;
  }

  // Add message to priority queue
  broadcastWithPriority(priority, roomId, event, data) {
    if (!this.priorityQueues.has(priority)) {
      this.priorityQueues.set(priority, []);
    }
    
    this.priorityQueues.get(priority).push({
      roomId,
      event,
      data,
      timestamp: Date.now(),
      id: this.generateMessageId()
    });
    
    // Start processing if not already
    if (!this.isProcessing) {
      this.processQueues();
    }
  }

  // Process queues in priority order
  async processQueues() {
    this.isProcessing = true;
    
    while (this.hasMessages()) {
      // Get highest priority with messages
      const priorities = Array.from(this.priorityQueues.keys())
        .filter(p => this.priorityQueues.get(p).length > 0)
        .sort((a, b) => b - a); // Higher priority first
      
      if (priorities.length === 0) {
        break;
      }
      
      const highestPriority = priorities[0];
      const queue = this.priorityQueues.get(highestPriority);
      const message = queue.shift();
      
      // Send message
      try {
        this.io.to(message.roomId).emit(message.event, message.data);
        
        // Rate limiting for high-volume broadcasts
        if (highestPriority < 3) { // Lower priority = more urgent
          await this.sleep(10); // Small delay for low priority messages
        }
      } catch (error) {
        console.error('Priority broadcast error:', error);
      }
      
      // Clean up empty queues
      if (queue.length === 0) {
        this.priorityQueues.delete(highestPriority);
      }
    }
    
    this.isProcessing = false;
  }

  hasMessages() {
    for (const queue of this.priorityQueues.values()) {
      if (queue.length > 0) {
        return true;
      }
    }
    return false;
  }

  // Define priority levels
  static get PRIORITIES() {
    return {
      CRITICAL: 0,    // System alerts, emergency notifications
      HIGH: 1,        // Important user notifications
      NORMAL: 2,      // Regular chat messages
      LOW: 3,         // Background updates, presence
      BACKGROUND: 4   // Analytics, logging
    };
  }

  generateMessageId() {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Convenience methods for common priorities
  broadcastCritical(roomId, event, data) {
    this.broadcastWithPriority(
      PriorityBroadcaster.PRIORITIES.CRITICAL,
      roomId,
      event,
      data
    );
  }

  broadcastImportant(roomId, event, data) {
    this.broadcastWithPriority(
      PriorityBroadcaster.PRIORITIES.HIGH,
      roomId,
      event,
      data
    );
  }

  broadcastNormal(roomId, event, data) {
    this.broadcastWithPriority(
      PriorityBroadcaster.PRIORITIES.NORMAL,
      roomId,
      event,
      data
    );
  }
}
```

### Multi-Server Broadcasting

#### 1. Redis-based Cross-Server Broadcasting
```javascript
class CrossServerBroadcaster {
  constructor(io, redisClient) {
    this.io = io;
    this.redis = redisClient;
    this.serverId = `server-${process.pid}-${Date.now()}`;
    this.setupRedisPubSub();
  }

  setupRedisPubSub() {
    // Subscribe to cross-server broadcast channel
    this.redis.subscribe('cross-server-broadcast', (message) => {
      this.handleCrossServerMessage(message);
    });
    
    // Subscribe to server-specific channel
    this.redis.subscribe(`server:${this.serverId}`, (message) => {
      this.handleServerMessage(message);
    });
  }

  handleCrossServerMessage(message) {
    try {
      const { event, data, excludeServerId, senderServerId } = JSON.parse(message);
      
      // Don't process our own messages
      if (senderServerId === this.serverId) {
        return;
      }
      
      // Don't process if we're excluded
      if (excludeServerId && excludeServerId === this.serverId) {
        return;
      }
      
      // Broadcast to local sockets
      if (data.roomId) {
        this.io.to(data.roomId).emit(event, data);
      } else {
        this.io.emit(event, data);
      }
    } catch (error) {
      console.error('Cross-server message error:', error);
    }
  }

  handleServerMessage(message) {
    try {
      const { type, data } = JSON.parse(message);
      
      switch (type) {
        case 'broadcast-to-room':
          this.io.to(data.roomId).emit(data.event, data.message);
          break;
        case 'broadcast-to-user':
          this.broadcastToUserLocally(data.userId, data.event, data.message);
          break;
        case 'get-room-info':
          this.sendRoomInfo(data.roomId, data.requestId);
          break;
      }
    } catch (error) {
      console.error('Server message error:', error);
    }
  }

  // Broadcast to room across all servers
  async broadcastToRoomCrossServer(roomId, event, message, options = {}) {
    const { excludeServerId } = options;
    
    const broadcastMessage = JSON.stringify({
      event,
      data: {
        roomId,
        message,
        timestamp: Date.now()
      },
      excludeServerId,
      senderServerId: this.serverId
    });
    
    await this.redis.publish('cross-server-broadcast', broadcastMessage);
    
    // Also broadcast locally
    this.io.to(roomId).emit(event, message);
  }

  // Broadcast to user across all servers
  async broadcastToUserCrossServer(userId, event, message) {
    // Get all servers that might have this user connected
    const userServers = await this.getUserServers(userId);
    
    // Send message to each server
    for (const serverId of userServers) {
      const serverMessage = JSON.stringify({
        type: 'broadcast-to-user',
        data: {
          userId,
          event,
          message,
          timestamp: Date.now()
        }
      });
      
      await this.redis.publish(`server:${serverId}`, serverMessage);
    }
  }

  async getUserServers(userId) {
    // In production, this would query a shared registry
    // For now, return all active servers
    const servers = await this.redis.sMembers('active-servers');
    return servers;
  }

  broadcastToUserLocally(userId, event, message) {
    // Find user's sockets and send message
    const userSockets = this.getUserSockets(userId);
    
    userSockets.forEach(socket => {
      if (socket.connected) {
        socket.emit(event, message);
      }
    });
  }

  getUserSockets(userId) {
    // Implementation depends on your user tracking
    // This is a simplified version
    const sockets = [];
    
    this.io.sockets.sockets.forEach(socket => {
      if (socket.userId === userId) {
        sockets.push(socket);
      }
    });
    
    return sockets;
  }

  async sendRoomInfo(roomId, requestId) {
    const socketsInRoom = this.io.sockets.adapter.rooms.get(roomId);
    const memberCount = socketsInRoom ? socketsInRoom.size : 0;
    
    const response = JSON.stringify({
      type: 'room-info-response',
      data: {
        requestId,
        roomId,
        memberCount,
        serverId: this.serverId,
        timestamp: Date.now()
      }
    });
    
    await this.redis.publish(`server:${this.serverId}`, response);
  }

  // Register server as active
  async registerServer() {
    await this.redis.sAdd('active-servers', this.serverId);
    
    // Set expiration (for cleanup if server crashes)
    await this.redis.expire('active-servers', 60);
    
    // Refresh expiration periodically
    setInterval(async () => {
      await this.redis.expire('active-servers', 60);
    }, 30000); // Every 30 seconds
  }

  // Unregister server
  async unregisterServer() {
    await this.redis.sRem('active-servers', this.serverId);
  }
}
```

#### 2. Consistent Hashing for Load Distribution
```javascript
class ConsistentHashBroadcaster {
  constructor(io, redisClient, totalServers = 10) {
    this.io = io;
    this.redis = redisClient;
    this.totalServers = totalServers;
    this.serverId = process.env.SERVER_ID || `server-${process.pid}`;
    this.virtualNodes = 100; // Virtual nodes per server for better distribution
    this.hashRing = new Map();
    this.setupHashRing();
    this.setupRedisPubSub();
  }

  setupHashRing() {
    // Create virtual nodes for each server
    for (let i = 0; i < this.totalServers; i++) {
      const server = `server-${i}`;
      
      for (let j = 0; j < this.virtualNodes; j++) {
        const nodeKey = `${server}#${j}`;
        const hash = this.hash(nodeKey);
        this.hashRing.set(hash, server);
      }
    }
    
    // Sort hash ring
    this.sortedHashes = Array.from(this.hashRing.keys()).sort((a, b) => a - b);
  }

  setupRedisPubSub() {
    // Subscribe to hash-based channels
    this.redis.psubscribe('broadcast:hash:*', (message, channel) => {
      this.handleHashBasedMessage(message, channel);
    });
  }

  handleHashBasedMessage(message, channel) {
    try {
      const { event, data, targetHash } = JSON.parse(message);
      
      // Check if we should handle this message
      if (this.shouldHandle(targetHash)) {
        this.io.emit(event, data);
      }
    } catch (error) {
      console.error('Hash-based message error:', error);
    }
  }

  // Consistent hashing algorithm
  getServerForRoom(roomId) {
    const hash = this.hash(roomId);
    
    // Find the first node with hash >= room hash
    for (const nodeHash of this.sortedHashes) {
      if (nodeHash >= hash) {
        return this.hashRing.get(nodeHash);
      }
    }
    
    // Wrap around to first node
    return this.hashRing.get(this.sortedHashes[0]);
  }

  shouldHandle(targetHash) {
    const server = this.getServerForHash(targetHash);
    return server === this.serverId;
  }

  getServerForHash(hash) {
    for (const nodeHash of this.sortedHashes) {
      if (nodeHash >= hash) {
        return this.hashRing.get(nodeHash);
      }
    }
    return this.hashRing.get(this.sortedHashes[0]);
  }

  // Broadcast to room using consistent hashing
  async broadcastToRoomHashed(roomId, event, data) {
    const targetHash = this.hash(roomId);
    const targetServer = this.getServerForHash(targetHash);
    
    if (targetServer === this.serverId) {
      // We're responsible for this room
      this.io.to(roomId).emit(event, data);
    } else {
      // Forward to responsible server
      const message = JSON.stringify({
        event,
        data,
        targetHash,
        timestamp: Date.now()
      });
      
      await this.redis.publish(`broadcast:hash:${targetServer}`, message);
    }
  }

  // Simple hash function (use better one in production)
  hash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  // Add new server to hash ring
  async addServer(serverId) {
    for (let j = 0; j < this.virtualNodes; j++) {
      const nodeKey = `${serverId}#${j}`;
      const hash = this.hash(nodeKey);
      this.hashRing.set(hash, serverId);
    }
    
    // Re-sort
    this.sortedHashes = Array.from(this.hashRing.keys()).sort((a, b) => a - b);
    this.totalServers++;
  }

  // Remove server from hash ring
  async removeServer(serverId) {
    for (let j = 0; j < this.virtualNodes; j++) {
      const nodeKey = `${serverId}#${j}`;
      const hash = this.hash(nodeKey);
      this.hashRing.delete(hash);
    }
    
    // Re-sort
    this.sortedHashes = Array.from(this.hashRing.keys()).sort((a, b) => a - b);
    this.totalServers--;
  }
}
```

### Monitoring and Analytics

#### 1. Broadcast Analytics
```javascript
class BroadcastAnalytics {
  constructor() {
    this.stats = {
      broadcasts: 0,
      events: new Map(), // event -> count
      rooms: new Map(), // roomId -> stats
      users: new Map(), // userId -> stats
      errors: [],
      startTime: Date.now()
    };
    
    this.analyticsInterval = 30000; // 30 seconds
    this.setupAnalytics();
  }

  setupAnalytics() {
    setInterval(() => {
      this.logAnalytics();
      this.cleanupOldData();
    }, this.analyticsInterval);
  }

  trackBroadcast(event, roomId = null, userId = null, success = true) {
    this.stats.broadcasts++;
    
    // Track event statistics
    const eventCount = this.stats.events.get(event) || 0;
    this.stats.events.set(event, eventCount + 1);
    
    // Track room statistics
    if (roomId) {
      if (!this.stats.rooms.has(roomId)) {
        this.stats.rooms.set(roomId, {
          broadcastCount: 0,
          lastBroadcast: null,
          events: new Map()
        });
      }
      
      const roomStats = this.stats.rooms.get(roomId);
      roomStats.broadcastCount++;
      roomStats.lastBroadcast = Date.now();
      
      const roomEventCount = roomStats.events.get(event) || 0;
      roomStats.events.set(event, roomEventCount + 1);
    }
    
    // Track user statistics
    if (userId) {
      if (!this.stats.users.has(userId)) {
        this.stats.users.set(userId, {
          broadcastCount: 0,
          lastBroadcast: null,
          events: new Map()
        });
      }
      
      const userStats = this.stats.users.get(userId);
      userStats.broadcastCount++;
      userStats.lastBroadcast = Date.now();
      
      const userEventCount = userStats.events.get(event) || 0;
      userStats.events.set(event, userEventCount + 1);
    }
    
    if (!success) {
      this.stats.errors.push({
        event,
        roomId,
        userId,
        timestamp: Date.now()
      });
      
      // Keep only last 100 errors
      if (this.stats.errors.length > 100) {
        this.stats.errors.shift();
      }
    }
  }

  logAnalytics() {
    const uptime = Date.now() - this.stats.startTime;
    const hours = Math.floor(uptime / 3600000);
    const minutes = Math.floor((uptime % 3600000) / 60000);
    
    console.log('=== Broadcast Analytics ===');
    console.log(`Uptime: ${hours}h ${minutes}m`);
    console.log(`Total broadcasts: ${this.stats.broadcasts}`);
    console.log(`Active rooms: ${this.stats.rooms.size}`);
    console.log(`Active users: ${this.stats.users.size}`);
    console.log(`Different events: ${this.stats.events.size}`);
    
    // Top 5 events
    const topEvents = Array.from(this.stats.events.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    
    console.log('\nTop 5 Events:');
    topEvents.forEach(([event, count], index) => {
      console.log(`${index + 1}. ${event}: ${count} broadcasts`);
    });
    
    // Top 5 rooms
    const topRooms = Array.from(this.stats.rooms.entries())
      .sort((a, b) => b[1].broadcastCount - a[1].broadcastCount)
      .slice(0, 5);
    
    console.log('\nTop 5 Rooms:');
    topRooms.forEach(([roomId, stats], index) => {
      console.log(`${index + 1}. ${roomId}: ${stats.broadcastCount} broadcasts`);
    });
    
    // Recent errors
    if (this.stats.errors.length > 0) {
      console.log('\nRecent Errors:');
      this.stats.errors.slice(-3).forEach((error, index) => {
        console.log(`${index + 1}. [${new Date(error.timestamp).toISOString()}] ${error.event} in ${error.roomId || 'global'}`);
      });
    }
    
    console.log('===========================\n');
  }

  cleanupOldData() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    // Cleanup old room data
    for (const [roomId, stats] of this.stats.rooms) {
      if (now - stats.lastBroadcast > maxAge) {
        this.stats.rooms.delete(roomId);
      }
    }
    
    // Cleanup old user data
    for (const [userId, stats] of this.stats.users) {
      if (now - stats.lastBroadcast > maxAge) {
        this.stats.users.delete(userId);
      }
    }
    
    // Cleanup old errors
    this.stats.errors = this.stats.errors.filter(
      error => now - error.timestamp <= maxAge
    );
  }

  getStats() {
    return {
      ...this.stats,
      uptime: Date.now() - this.stats.startTime,
      events: Array.from(this.stats.events.entries()).map(([name, count]) => ({
        name,
        count
      })),
      rooms: Array.from(this.stats.rooms.entries()).map(([id, stats]) => ({
        id,
        ...stats,
        events: Array.from(stats.events.entries()).map(([event, count]) => ({
          event,
          count
        }))
      })),
      users: Array.from(this.stats.users.entries()).map(([id, stats]) => ({
        id,
        ...stats,
        events: Array.from(stats.events.entries()).map(([event, count]) => ({
          event,
          count
        }))
      }))
    };
  }

  resetStats() {
    this.stats = {
      broadcasts: 0,
      events: new Map(),
      rooms: new Map(),
      users: new Map(),
      errors: [],
      startTime: Date.now()
    };
  }
}
```

---

## 5. Chat Applications

### Complete Chat Application Architecture

#### 1. Core Chat Server
```javascript
class ChatServer {
  constructor() {
    this.io = new Server(server, {
      cors: {
        origin: process.env.CLIENT_URL,
        credentials: true
      },
      connectionStateRecovery: {
        maxDisconnectionDuration: 2 * 60 * 1000, // 2 minutes
        skipMiddlewares: true
      }
    });
    
    this.rooms = new Map(); // roomId -> Room
    this.users = new Map(); // userId -> User
    this.messages = new Map(); // roomId -> Message[]
    this.setupMiddleware();
    this.setupEventHandlers();
  }

  setupMiddleware() {
    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token;
        
        if (!token) {
          return next(new Error('Authentication required'));
        }
        
        const user = await this.authenticateUser(token);
        socket.user = user;
        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });
    
    // Rate limiting middleware
    this.io.use((socket, next) => {
      const ip = socket.handshake.address;
      const rateLimitKey = `rate:${ip}`;
      
      // Check rate limit
      const rateLimit = this.checkRateLimit(rateLimitKey);
      if (!rateLimit.allowed) {
        return next(new Error(`Rate limit exceeded. Try again in ${rateLimit.retryAfter} seconds`));
      }
      
      next();
    });
  }

  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      console.log(`User connected: ${socket.user.id} (${socket.id})`);
      
      // Register user
      this.registerUser(socket);
      
      // Core chat events
      socket.on('join-room', (roomId) => this.handleJoinRoom(socket, roomId));
      socket.on('leave-room', (roomId) => this.handleLeaveRoom(socket, roomId));
      socket.on('send-message', (data) => this.handleSendMessage(socket, data));
      socket.on('typing', (roomId) => this.handleTyping(socket, roomId));
      socket.on('stop-typing', (roomId) => this.handleStopTyping(socket, roomId));
      socket.on('edit-message', (data) => this.handleEditMessage(socket, data));
      socket.on('delete-message', (data) => this.handleDeleteMessage(socket, data));
      socket.on('react-to-message', (data) => this.handleReactToMessage(socket, data));
      socket.on('read-receipt', (data) => this.handleReadReceipt(socket, data));
      
      // Presence
      socket.on('update-presence', (status) => this.handleUpdatePresence(socket, status));
      
      // Disconnect
      socket.on('disconnect', () => this.handleDisconnect(socket));
      socket.on('error', (error) => this.handleError(socket, error));
    });
  }

  async authenticateUser(token) {
    // JWT verification
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Fetch user from database
    const user = await User.findById(decoded.userId)
      .select('_id username email avatar role status lastSeen');
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return {
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      role: user.role,
      status: user.status || 'offline',
      lastSeen: user.lastSeen
    };
  }

  checkRateLimit(key) {
    // Implementation using Redis or in-memory store
    // Returns { allowed: boolean, retryAfter: number }
    return { allowed: true, retryAfter: 0 };
  }

  registerUser(socket) {
    const user = socket.user;
    
    if (!this.users.has(user.id)) {
      this.users.set(user.id, {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        status: 'online',
        sockets: new Set(),
        rooms: new Set(),
        lastActivity: Date.now()
      });
    }
    
    const userData = this.users.get(user.id);
    userData.sockets.add(socket.id);
    userData.status = 'online';
    userData.lastActivity = Date.now();
    
    // Notify friends/contacts about online status
    this.notifyPresenceChange(user.id, 'online');
  }

  async handleJoinRoom(socket, roomId) {
    try {
      // Verify user can join room
      const canJoin = await this.canUserJoinRoom(socket.user.id, roomId);
      if (!canJoin) {
        socket.emit('error', { message: 'Cannot join room' });
        return;
      }
      
      // Join socket to room
      await socket.join(roomId);
      
      // Update user's rooms
      const userData = this.users.get(socket.user.id);
      userData.rooms.add(roomId);
      
      // Update room data
      if (!this.rooms.has(roomId)) {
        this.rooms.set(roomId, {
          id: roomId,
          name: `Room ${roomId}`,
          members: new Set(),
          messages: [],
          createdAt: Date.now(),
          lastActivity: Date.now()
        });
      }
      
      const room = this.rooms.get(roomId);
      room.members.add(socket.user.id);
      room.lastActivity = Date.now();
      
      // Load recent messages
      const recentMessages = await this.loadRecentMessages(roomId);
      
      // Send room info and recent messages to user
      socket.emit('room-joined', {
        room: {
          id: room.id,
          name: room.name,
          memberCount: room.members.size
        },
        messages: recentMessages
      });
      
      // Notify others in room
      socket.to(roomId).emit('user-joined', {
        userId: socket.user.id,
        username: socket.user.username,
        avatar: socket.user.avatar,
        timestamp: Date.now()
      });
      
      console.log(`User ${socket.user.id} joined room ${roomId}`);
    } catch (error) {
      console.error('Join room error:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  }

  async handleLeaveRoom(socket, roomId) {
    try {
      // Leave socket from room
      await socket.leave(roomId);
      
      // Update user's rooms
      const userData = this.users.get(socket.user.id);
      userData.rooms.delete(roomId);
      
      // Update room data
      const room = this.rooms.get(roomId);
      if (room) {
        room.members.delete(socket.user.id);
        room.lastActivity = Date.now();
        
        // Cleanup empty room
        if (room.members.size === 0) {
          this.rooms.delete(roomId);
        }
      }
      
      // Notify others in room
      socket.to(roomId).emit('user-left', {
        userId: socket.user.id,
        timestamp: Date.now()
      });
      
      console.log(`User ${socket.user.id} left room ${roomId}`);
    } catch (error) {
      console.error('Leave room error:', error);
    }
  }

  async handleSendMessage(socket, data) {
    try {
      const { roomId, content, replyTo, attachments } = data;
      
      // Validate message
      if (!content?.trim() && (!attachments || attachments.length === 0)) {
        socket.emit('error', { message: 'Message cannot be empty' });
        return;
      }
      
      // Check if user is in room
      const userData = this.users.get(socket.user.id);
      if (!userData || !userData.rooms.has(roomId)) {
        socket.emit('error', { message: 'Not a member of this room' });
        return;
      }
      
      // Create message
      const message = {
        id: this.generateMessageId(),
        roomId,
        senderId: socket.user.id,
        senderName: socket.user.username,
        senderAvatar: socket.user.avatar,
        content: content?.trim(),
        replyTo,
        attachments: attachments || [],
        timestamp: Date.now(),
        edited: false,
        reactions: new Map(),
        readBy: new Set([socket.user.id])
      };
      
      // Store message
      if (!this.messages.has(roomId)) {
        this.messages.set(roomId, []);
      }
      this.messages.get(roomId).push(message);
      
      // Update room activity
      const room = this.rooms.get(roomId);
      if (room) {
        room.lastActivity = Date.now();
      }
      
      // Broadcast message to room
      this.io.to(roomId).emit('new-message', message);
      
      // Store in database (async)
      this.storeMessageInDatabase(message).catch(error => {
        console.error('Failed to store message:', error);
      });
      
      console.log(`Message from ${socket.user.id} in room ${roomId}: ${content}`);
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  }

  handleTyping(socket, roomId) {
    // Notify others in room
    socket.to(roomId).emit('user-typing', {
      userId: socket.user.id,
      username: socket.user.username,
      roomId,
      timestamp: Date.now()
    });
  }

  handleStopTyping(socket, roomId) {
    socket.to(roomId).emit('user-stopped-typing', {
      userId: socket.user.id,
      roomId,
      timestamp: Date.now()
    });
  }

  async handleEditMessage(socket, data) {
    try {
      const { messageId, roomId, newContent } = data;
      
      // Find message
      const roomMessages = this.messages.get(roomId);
      if (!roomMessages) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      const messageIndex = roomMessages.findIndex(m => m.id === messageId);
      if (messageIndex === -1) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      const message = roomMessages[messageIndex];
      
      // Check permission
      if (message.senderId !== socket.user.id) {
        socket.emit('error', { message: 'Cannot edit this message' });
        return;
      }
      
      // Update message
      message.content = newContent;
      message.edited = true;
      message.editedAt = Date.now();
      
      // Broadcast update
      this.io.to(roomId).emit('message-edited', {
        messageId,
        roomId,
        newContent,
        editedAt: message.editedAt,
        timestamp: Date.now()
      });
      
      // Update in database
      this.updateMessageInDatabase(messageId, newContent).catch(error => {
        console.error('Failed to update message:', error);
      });
    } catch (error) {
      console.error('Edit message error:', error);
      socket.emit('error', { message: 'Failed to edit message' });
    }
  }

  async handleDeleteMessage(socket, data) {
    try {
      const { messageId, roomId } = data;
      
      // Find message
      const roomMessages = this.messages.get(roomId);
      if (!roomMessages) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      const messageIndex = roomMessages.findIndex(m => m.id === messageId);
      if (messageIndex === -1) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      const message = roomMessages[messageIndex];
      
      // Check permission
      const isAdmin = socket.user.role === 'admin' || socket.user.role === 'moderator';
      if (message.senderId !== socket.user.id && !isAdmin) {
        socket.emit('error', { message: 'Cannot delete this message' });
        return;
      }
      
      // Remove message
      roomMessages.splice(messageIndex, 1);
      
      // Broadcast deletion
      this.io.to(roomId).emit('message-deleted', {
        messageId,
        roomId,
        deletedBy: socket.user.id,
        timestamp: Date.now()
      });
      
      // Delete from database
      this.deleteMessageFromDatabase(messageId).catch(error => {
        console.error('Failed to delete message:', error);
      });
    } catch (error) {
      console.error('Delete message error:', error);
      socket.emit('error', { message: 'Failed to delete message' });
    }
  }

  async handleReactToMessage(socket, data) {
    try {
      const { messageId, roomId, reaction } = data;
      
      // Find message
      const roomMessages = this.messages.get(roomId);
      if (!roomMessages) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      const message = roomMessages.find(m => m.id === messageId);
      if (!message) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }
      
      // Update reactions
      if (!message.reactions.has(reaction)) {
        message.reactions.set(reaction, new Set());
      }
      
      const reactionUsers = message.reactions.get(reaction);
      
      // Toggle reaction
      if (reactionUsers.has(socket.user.id)) {
        reactionUsers.delete(socket.user.id);
        if (reactionUsers.size === 0) {
          message.reactions.delete(reaction);
        }
      } else {
        reactionUsers.add(socket.user.id);
      }
      
      // Broadcast reaction update
      this.io.to(roomId).emit('message-reaction-updated', {
        messageId,
        roomId,
        reaction,
        userId: socket.user.id,
        hasReacted: reactionUsers.has(socket.user.id),
        reactionCount: reactionUsers.size,
        timestamp: Date.now()
      });
      
      // Update in database
      this.updateReactionInDatabase(messageId, reaction, socket.user.id).catch(error => {
        console.error('Failed to update reaction:', error);
      });
    } catch (error) {
      console.error('React to message error:', error);
      socket.emit('error', { message: 'Failed to react to message' });
    }
  }

  async handleReadReceipt(socket, data) {
    try {
      const { messageId, roomId } = data;
      
      // Find message
      const roomMessages = this.messages.get(roomId);
      if (!roomMessages) {
        return;
      }
      
      const message = roomMessages.find(m => m.id === messageId);
      if (!message) {
        return;
      }
      
      // Update readBy
      message.readBy.add(socket.user.id);
      
      // Broadcast read receipt (optional - depends on requirements)
      // Usually read receipts are sent privately to the sender
      const senderSockets = this.getUserSockets(message.senderId);
      senderSockets.forEach(senderSocket => {
        if (senderSocket.connected) {
          senderSocket.emit('message-read', {
            messageId,
            roomId,
            readerId: socket.user.id,
            timestamp: Date.now()
          });
        }
      });
      
      // Update in database
      this.updateReadReceiptInDatabase(messageId, socket.user.id).catch(error => {
        console.error('Failed to update read receipt:', error);
      });
    } catch (error) {
      console.error('Read receipt error:', error);
    }
  }

  handleUpdatePresence(socket, status) {
    const userData = this.users.get(socket.user.id);
    if (userData) {
      userData.status = status;
      userData.lastActivity = Date.now();
      
      // Notify friends/contacts
      this.notifyPresenceChange(socket.user.id, status);
    }
  }

  handleDisconnect(socket) {
    const userId = socket.user.id;
    console.log(`User disconnected: ${userId} (${socket.id})`);
    
    const userData = this.users.get(userId);
    if (userData) {
      // Remove socket from user
      userData.sockets.delete(socket.id);
      
      // If no more sockets, update status to offline
      if (userData.sockets.size === 0) {
        userData.status = 'offline';
        userData.lastSeen = Date.now();
        
        // Notify friends/contacts
        this.notifyPresenceChange(userId, 'offline');
        
        // Leave all rooms
        userData.rooms.forEach(roomId => {
          socket.to(roomId).emit('user-left', {
            userId,
            timestamp: Date.now()
          });
        });
      }
    }
  }

  handleError(socket, error) {
    console.error(`Socket error for user ${socket.user.id}:`, error);
    socket.emit('error', { message: 'An error occurred' });
  }

  // Helper methods
  async canUserJoinRoom(userId, roomId) {
    // Implement room access logic
    // This could check database for room permissions, membership, etc.
    return true; // Simplified for example
  }

  async loadRecentMessages(roomId, limit = 50) {
    // Load from in-memory cache first
    const cachedMessages = this.messages.get(roomId) || [];
    
    if (cachedMessages.length >= limit) {
      return cachedMessages.slice(-limit);
    }
    
    // Load from database if needed
    try {
      const dbMessages = await this.loadMessagesFromDatabase(roomId, limit);
      return dbMessages;
    } catch (error) {
      console.error('Failed to load messages:', error);
      return cachedMessages;
    }
  }

  generateMessageId() {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getUserSockets(userId) {
    const userData = this.users.get(userId);
    if (!userData) return [];
    
    const sockets = [];
    userData.sockets.forEach(socketId => {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) {
        sockets.push(socket);
      }
    });
    
    return sockets;
  }

  notifyPresenceChange(userId, status) {
    // Notify user's friends/contacts
    // Implementation depends on your friend/contact system
  }

  // Database methods (stubs - implement based on your database)
  async storeMessageInDatabase(message) {
    // Store message in MongoDB, PostgreSQL, etc.
  }

  async updateMessageInDatabase(messageId, newContent) {
    // Update message in database
  }

  async deleteMessageFromDatabase(messageId) {
    // Delete message from database (soft or hard delete)
  }

  async updateReactionInDatabase(messageId, reaction, userId) {
    // Update reaction in database
  }

  async updateReadReceiptInDatabase(messageId, userId) {
    // Update read receipt in database
  }

  async loadMessagesFromDatabase(roomId, limit) {
    // Load messages from database
    return [];
  }
}
```

#### 2. Chat Features Implementation

##### Typing Indicators
```javascript
class TypingIndicatorManager {
  constructor(io) {
    this.io = io;
    this.typingUsers = new Map(); // roomId -> Map(userId -> timeout)
    this.typingDuration = 3000; // 3 seconds
  }

  startTyping(socket, roomId) {
    // Clear existing timeout
    this.clearTypingTimeout(roomId, socket.user.id);
    
    // Set new timeout
    const timeout = setTimeout(() => {
      this.stopTyping(socket, roomId);
    }, this.typingDuration);
    
    // Store timeout
    if (!this.typingUsers.has(roomId)) {
      this.typingUsers.set(roomId, new Map());
    }
    this.typingUsers.get(roomId).set(socket.user.id, timeout);
    
    // Notify others in room
    socket.to(roomId).emit('user-typing', {
      userId: socket.user.id,
      username: socket.user.username,
      roomId,
      timestamp: Date.now()
    });
  }

  stopTyping(socket, roomId) {
    this.clearTypingTimeout(roomId, socket.user.id);
    
    // Notify others
    socket.to(roomId).emit('user-stopped-typing', {
      userId: socket.user.id,
      roomId,
      timestamp: Date.now()
    });
  }

  clearTypingTimeout(roomId, userId) {
    const roomTyping = this.typingUsers.get(roomId);
    if (roomTyping) {
      const timeout = roomTyping.get(userId);
      if (timeout) {
        clearTimeout(timeout);
        roomTyping.delete(userId);
      }
      
      // Cleanup empty room
      if (roomTyping.size === 0) {
        this.typingUsers.delete(roomId);
      }
    }
  }

  getTypingUsers(roomId) {
    const roomTyping = this.typingUsers.get(roomId);
    if (!roomTyping) return [];
    
    return Array.from(roomTyping.keys());
  }
}
```

##### Message Reactions
```javascript
class ReactionManager {
  constructor() {
    this.reactions = new Map(); // messageId -> Map(reaction -> Set(userId))
    this.allowedReactions = new Set(['👍', '❤️', '😂', '😮', '😢', '😡']);
  }

  addReaction(messageId, userId, reaction) {
    if (!this.allowedReactions.has(reaction)) {
      throw new Error('Invalid reaction');
    }
    
    if (!this.reactions.has(messageId)) {
      this.reactions.set(messageId, new Map());
    }
    
    const messageReactions = this.reactions.get(messageId);
    
    if (!messageReactions.has(reaction)) {
      messageReactions.set(reaction, new Set());
    }
    
    const reactionUsers = messageReactions.get(reaction);
    reactionUsers.add(userId);
    
    return {
      reaction,
      userId,
      count: reactionUsers.size,
      hasReacted: true
    };
  }

  removeReaction(messageId, userId, reaction) {
    const messageReactions = this.reactions.get(messageId);
    if (!messageReactions) return null;
    
    const reactionUsers = messageReactions.get(reaction);
    if (!reactionUsers) return null;
    
    reactionUsers.delete(userId);
    
    // Cleanup empty reactions
    if (reactionUsers.size === 0) {
      messageReactions.delete(reaction);
    }
    
    // Cleanup empty message
    if (messageReactions.size === 0) {
      this.reactions.delete(messageId);
    }
    
    return {
      reaction,
      userId,
      count: reactionUsers.size || 0,
      hasReacted: false
    };
  }

  toggleReaction(messageId, userId, reaction) {
    const messageReactions = this.reactions.get(messageId);
    if (messageReactions) {
      const reactionUsers = messageReactions.get(reaction);
      if (reactionUsers && reactionUsers.has(userId)) {
        return this.removeReaction(messageId, userId, reaction);
      }
    }
    
    return this.addReaction(messageId, userId, reaction);
  }

  getMessageReactions(messageId) {
    const messageReactions = this.reactions.get(messageId);
    if (!messageReactions) return [];
    
    const reactions = [];
    for (const [reaction, users] of messageReactions) {
      reactions.push({
        reaction,
        count: users.size,
        users: Array.from(users)
      });
    }
    
    return reactions;
  }

  getUserReaction(messageId, userId) {
    const messageReactions = this.reactions.get(messageId);
    if (!messageReactions) return null;
    
    for (const [reaction, users] of messageReactions) {
      if (users.has(userId)) {
        return reaction;
      }
    }
    
    return null;
  }
}
```

##### Message Search and Filtering
```javascript
class MessageSearchEngine {
  constructor() {
    this.messageIndex = new Map(); // roomId -> Map(messageId -> message)
    this.fullTextIndex = new Map(); // word -> Set(messageId)
    this.senderIndex = new Map(); // userId -> Set(messageId)
  }

  indexMessage(message) {
    // Store in room index
    if (!this.messageIndex.has(message.roomId)) {
      this.messageIndex.set(message.roomId, new Map());
    }
    this.messageIndex.get(message.roomId).set(message.id, message);
    
    // Index by sender
    if (!this.senderIndex.has(message.senderId)) {
      this.senderIndex.set(message.senderId, new Set());
    }
    this.senderIndex.get(message.senderId).add(message.id);
    
    // Full-text index
    if (message.content) {
      const words = this.extractWords(message.content);
      words.forEach(word => {
        if (!this.fullTextIndex.has(word)) {
          this.fullTextIndex.set(word, new Set());
        }
        this.fullTextIndex.get(word).add(message.id);
      });
    }
  }

  searchMessages(roomId, query, options = {}) {
    const {
      limit = 50,
      offset = 0,
      senderId = null,
      startDate = null,
      endDate = Date.now()
    } = options;
    
    let messageIds = new Set();
    
    // Get room messages
    const roomMessages = this.messageIndex.get(roomId);
    if (!roomMessages) return [];
    
    // Apply sender filter
    if (senderId) {
      const senderMessages = this.senderIndex.get(senderId) || new Set();
      messageIds = new Set(senderMessages);
    } else {
      messageIds = new Set(roomMessages.keys());
    }
    
    // Apply text search
    if (query) {
      const searchWords = this.extractWords(query);
      const matchingMessageIds = this.searchByText(searchWords);
      messageIds = this.intersectSets(messageIds, matchingMessageIds);
    }
    
    // Apply date filter
    if (startDate || endDate) {
      const filteredIds = new Set();
      for (const messageId of messageIds) {
        const message = roomMessages.get(messageId);
        if (!message) continue;
        
        const messageDate = message.timestamp;
        if ((!startDate || messageDate >= startDate) &&
            (!endDate || messageDate <= endDate)) {
          filteredIds.add(messageId);
        }
      }
      messageIds = filteredIds;
    }
    
    // Convert to messages and sort
    const messages = Array.from(messageIds)
      .map(id => roomMessages.get(id))
      .filter(Boolean)
      .sort((a, b) => b.timestamp - a.timestamp); // Newest first
    
    // Apply pagination
    return messages.slice(offset, offset + limit);
  }

  searchByText(words) {
    if (words.length === 0) return new Set();
    
    // Start with first word
    let result = new Set(this.fullTextIndex.get(words[0]) || []);
    
    // Intersect with other words (AND search)
    for (let i = 1; i < words.length; i++) {
      const wordMatches = this.fullTextIndex.get(words[i]) || new Set();
      result = this.intersectSets(result, wordMatches);
      
      if (result.size === 0) break;
    }
    
    return result;
  }

  extractWords(text) {
    return text.toLowerCase()
      .replace(/[^\w\s]/g, ' ') // Remove punctuation
      .split(/\s+/) // Split by whitespace
      .filter(word => word.length > 2) // Ignore short words
      .filter((word, index, array) => array.indexOf(word) === index); // Remove duplicates
  }

  intersectSets(setA, setB) {
    const intersection = new Set();
    for (const elem of setA) {
      if (setB.has(elem)) {
        intersection.add(elem);
      }
    }
    return intersection;
  }

  removeMessage(messageId, roomId) {
    // Remove from room index
    const roomMessages = this.messageIndex.get(roomId);
    if (roomMessages) {
      const message = roomMessages.get(messageId);
      if (message) {
        roomMessages.delete(messageId);
        
        // Remove from sender index
        const senderMessages = this.senderIndex.get(message.senderId);
        if (senderMessages) {
          senderMessages.delete(messageId);
          if (senderMessages.size === 0) {
            this.senderIndex.delete(message.senderId);
          }
        }
        
        // Remove from full-text index
        if (message.content) {
          const words = this.extractWords(message.content);
          words.forEach(word => {
            const wordMessages = this.fullTextIndex.get(word);
            if (wordMessages) {
              wordMessages.delete(messageId);
              if (wordMessages.size === 0) {
                this.fullTextIndex.delete(word);
              }
            }
          });
        }
      }
      
      // Cleanup empty room
      if (roomMessages.size === 0) {
        this.messageIndex.delete(roomId);
      }
    }
  }
}
```

#### 3. Scalable Chat Architecture with Microservices

##### Chat Service Architecture
```javascript
// Microservice-based chat architecture
class ChatMicroservice {
  constructor() {
    this.io = null;
    this.redis = null;
    this.messageQueue = null;
    this.database = null;
    this.setupServices();
  }

  async setupServices() {
    // Setup Redis for Pub/Sub and caching
    this.redis = await this.setupRedis();
    
    // Setup message queue for async processing
    this.messageQueue = await this.setupMessageQueue();
    
    // Setup database connection
    this.database = await this.setupDatabase();
    
    // Setup Socket.io server
    this.io = await this.setupSocketIO();
    
    // Start background workers
    this.startWorkers();
  }

  async setupSocketIO() {
    const server = http.createServer();
    const io = new Server(server, {
      adapter: createAdapter(
        redis.createClient({ url: process.env.REDIS_URL }),
        redis.createClient({ url: process.env.REDIS_URL })
      ),
      cors: {
        origin: process.env.CLIENT_URL,
        credentials: true
      }
    });
    
    // Authentication middleware
    io.use(async (socket, next) => {
      try {
        const user = await this.authenticate(socket.handshake.auth.token);
        socket.user = user;
        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });
    
    // Setup event handlers
    io.on('connection', (socket) => {
      this.handleConnection(socket);
    });
    
    server.listen(process.env.PORT || 3000);
    return io;
  }

  async setupRedis() {
    const client = redis.createClient({
      url: process.env.REDIS_URL,
      socket: {
        tls: process.env.NODE_ENV === 'production',
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
      }
    });
    
    await client.connect();
    return client;
  }

  async setupMessageQueue() {
    // Using Bull/Redis for job queues
    const queue = new Queue('chat-messages', {
      redis: process.env.REDIS_URL,
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 1000
        },
        removeOnComplete: true,
        removeOnFail: false
      }
    });
    
    // Message processing worker
    queue.process('process-message', async (job) => {
      return await this.processMessageJob(job.data);
    });
    
    // Notification worker
    queue.process('send-notification', async (job) => {
      return await this.sendNotificationJob(job.data);
    });
    
    return queue;
  }

  async setupDatabase() {
    // Setup database connection (MongoDB, PostgreSQL, etc.)
    // This is a stub - implement based on your database
    return {
      saveMessage: async (message) => { /* ... */ },
      getMessages: async (roomId, limit) => { /* ... */ },
      // ... other database methods
    };
  }

  handleConnection(socket) {
    console.log(`User connected: ${socket.user.id}`);
    
    // Join user to their personal room
    socket.join(`user:${socket.user.id}`);
    
    // Subscribe to user's channels in Redis
    this.redis.subscribe(`chat:user:${socket.user.id}`, (message) => {
      this.handleRedisMessage(socket, message);
    });
    
    // Handle chat events
    socket.on('send-message', async (data) => {
      await this.handleSendMessage(socket, data);
    });
    
    socket.on('join-room', async (roomId) => {
      await this.handleJoinRoom(socket, roomId);
    });
    
    // ... other event handlers
  }

  async handleSendMessage(socket, data) {
    const { roomId, content } = data;
    
    // Create message object
    const message = {
      id: this.generateId(),
      roomId,
      senderId: socket.user.id,
      content,
      timestamp: Date.now()
    };
    
    // Send immediately to room via Socket.io
    socket.to(roomId).emit('new-message', message);
    
    // Queue for processing (persistence, notifications, etc.)
    await this.messageQueue.add('process-message', {
      message,
      roomId,
      sender: socket.user
    });
    
    // Publish to Redis for other services
    await this.redis.publish(`chat:room:${roomId}`, JSON.stringify({
      type: 'new-message',
      message
    }));
  }

  async handleJoinRoom(socket, roomId) {
    // Join Socket.io room
    await socket.join(roomId);
    
    // Subscribe to Redis channel for this room
    await this.redis.subscribe(`chat:room:${roomId}`, (message) => {
      this.handleRedisRoomMessage(socket, message);
    });
    
    // Load recent messages
    const messages = await this.database.getMessages(roomId, 50);
    socket.emit('room-history', { roomId, messages });
    
    // Notify others
    socket.to(roomId).emit('user-joined', {
      userId: socket.user.id,
      roomId,
      timestamp: Date.now()
    });
  }

  async processMessageJob(data) {
    const { message, roomId, sender } = data;
    
    // 1. Store message in database
    await this.database.saveMessage(message);
    
    // 2. Update room last activity
    await this.database.updateRoomActivity(roomId, message.timestamp);
    
    // 3. Check for mentions and queue notifications
    const mentions = this.extractMentions(message.content);
    if (mentions.length > 0) {
      await this.messageQueue.add('send-notification', {
        type: 'mention',
        mentions,
        message,
        sender
      });
    }
    
    // 4. Update search index
    await this.updateSearchIndex(message);
    
    return { success: true, messageId: message.id };
  }

  async sendNotificationJob(data) {
    const { type, mentions, message, sender } = data;
    
    for (const userId of mentions) {
      // Send push notification
      await this.sendPushNotification(userId, {
        type,
        from: sender.username,
        message: message.content,
        roomId: message.roomId
      });
      
      // Send in-app notification via Redis
      await this.redis.publish(`notifications:${userId}`, JSON.stringify({
        type: 'chat-mention',
        from: sender.username,
        message: message.content,
        timestamp: Date.now()
      }));
    }
    
    return { sent: mentions.length };
  }

  handleRedisMessage(socket, message) {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'notification':
          socket.emit('notification', data);
          break;
        case 'presence-update':
          socket.emit('presence-update', data);
          break;
        // ... other message types
      }
    } catch (error) {
      console.error('Redis message error:', error);
    }
  }

  handleRedisRoomMessage(socket, message) {
    try {
      const data = JSON.parse(message);
      
      // Only process if not from current socket
      if (data.senderId !== socket.user.id) {
        socket.emit(data.type, data);
      }
    } catch (error) {
      console.error('Redis room message error:', error);
    }
  }

  extractMentions(text) {
    // Extract @username mentions
    const mentionRegex = /@(\w+)/g;
    const mentions = [];
    let match;
    
    while ((match = mentionRegex.exec(text)) !== null) {
      mentions.push(match[1]);
    }
    
    return mentions;
  }

  async sendPushNotification(userId, data) {
    // Implementation depends on your push notification service
    // (Firebase Cloud Messaging, Apple Push Notification Service, etc.)
  }

  async updateSearchIndex(message) {
    // Update Elasticsearch or other search index
  }

  generateId() {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  startWorkers() {
    // Start background workers for:
    // - Message queue processing
    // - Presence updates
    // - Analytics
    // - Cleanup tasks
  }
}
```

---

## 6. Online/Offline Presence Detection

### Comprehensive Presence System

#### 1. Core Presence Manager
```javascript
class PresenceManager {
  constructor(io, redis) {
    this.io = io;
    this.redis = redis;
    this.users = new Map(); // userId -> UserPresence
    this.presenceTimeout = 30000; // 30 seconds
    this.cleanupInterval = 60000; // 1 minute
    this.setupCleanup();
  }

  // User connects
  userConnected(socket) {
    const userId = socket.user.id;
    
    if (!this.users.has(userId)) {
      this.users.set(userId, {
        id: userId,
        username: socket.user.username,
        status: 'online',
        sockets: new Set(),
        lastSeen: Date.now(),
        metadata: {
          device: socket.handshake.headers['user-agent'],
          ip: socket.handshake.address,
          connectedAt: Date.now()
        }
      });
    }
    
    const userPresence = this.users.get(userId);
    userPresence.sockets.add(socket.id);
    userPresence.status = 'online';
    userPresence.lastSeen = Date.now();
    
    // Store in Redis for cross-server consistency
    this.storeInRedis(userPresence);
    
    // Notify friends/contacts
    this.notifyStatusChange(userId, 'online');
    
    // Setup heartbeat for this socket
    this.setupHeartbeat(socket);
    
    console.log(`User ${userId} connected (${userPresence.sockets.size} sockets)`);
  }

  // User disconnects
  userDisconnected(socket) {
    const userId = socket.user.id;
    const userPresence = this.users.get(userId);
    
    if (!userPresence) return;
    
    // Remove socket
    userPresence.sockets.delete(socket.id);
    
    // Update status if no more sockets
    if (userPresence.sockets.size === 0) {
      userPresence.status = 'offline';
      userPresence.lastSeen = Date.now();
      
      // Remove from Redis after delay (for reconnection)
      setTimeout(() => {
        if (userPresence.sockets.size === 0) {
          this.removeFromRedis(userId);
        }
      }, 5000); // 5 second grace period
      
      // Notify friends/contacts
      this.notifyStatusChange(userId, 'offline');
      
      console.log(`User ${userId} disconnected (offline)`);
    } else {
      console.log(`User ${userId} disconnected (${userPresence.sockets.size} sockets remaining)`);
    }
  }

  // Update user status
  updateStatus(userId, status, metadata = {}) {
    const userPresence = this.users.get(userId);
    if (!userPresence) return;
    
    const oldStatus = userPresence.status;
    userPresence.status = status;
    userPresence.lastSeen = Date.now();
    
    if (metadata) {
      userPresence.metadata = { ...userPresence.metadata, ...metadata };
    }
    
    // Store in Redis
    this.storeInRedis(userPresence);
    
    // Notify if status changed
    if (oldStatus !== status) {
      this.notifyStatusChange(userId, status);
    }
  }

  // Get user presence
  getUserPresence(userId) {
    const localPresence = this.users.get(userId);
    
    if (localPresence) {
      return localPresence;
    }
    
    // Check Redis for cross-server presence
    return this.getFromRedis(userId);
  }

  // Get multiple users presence
  async getUsersPresence(userIds) {
    const presences = [];
    
    for (const userId of userIds) {
      const presence = await this.getUserPresence(userId);
      presences.push(presence || {
        id: userId,
        status: 'offline',
        lastSeen: null
      });
    }
    
    return presences;
  }

  // Get online users
  getOnlineUsers() {
    const onlineUsers = [];
    
    for (const [userId, presence] of this.users) {
      if (presence.status === 'online') {
        onlineUsers.push({
          id: userId,
          username: presence.username,
          lastSeen: presence.lastSeen,
          metadata: presence.metadata
        });
      }
    }
    
    return onlineUsers;
  }

  // Setup heartbeat for socket
  setupHeartbeat(socket) {
    const interval = setInterval(() => {
      if (socket.connected) {
        socket.emit('ping', Date.now());
      } else {
        clearInterval(interval);
      }
    }, this.presenceTimeout / 2);
    
    socket.on('pong', (timestamp) => {
      const userId = socket.user.id;
      const userPresence = this.users.get(userId);
      
      if (userPresence) {
        userPresence.lastSeen = Date.now();
        
        // Update Redis
        this.storeInRedis(userPresence);
      }
    });
    
    socket.on('disconnect', () => {
      clearInterval(interval);
    });
  }

  // Notify status change to friends/contacts
  async notifyStatusChange(userId, status) {
    // Get user's friends/contacts
    const friends = await this.getUserFriends(userId);
    
    for (const friendId of friends) {
      // Check if friend is online
      const friendPresence = this.getUserPresence(friendId);
      
      if (friendPresence && friendPresence.status === 'online') {
        // Send via Redis Pub/Sub
        await this.redis.publish(`presence:${friendId}`, JSON.stringify({
          type: 'status-change',
          userId,
          status,
          timestamp: Date.now()
        }));
      }
    }
  }

  // Store presence in Redis
  async storeInRedis(presence) {
    const key = `presence:${presence.id}`;
    const value = JSON.stringify(presence);
    
    await this.redis.setex(key, 60, value); // Expire after 60 seconds
    await this.redis.sAdd('online-users', presence.id);
  }

  // Get presence from Redis
  async getFromRedis(userId) {
    try {
      const data = await this.redis.get(`presence:${userId}`);
      if (data) {
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Redis get error:', error);
    }
    
    return null;
  }

  // Remove from Redis
  async removeFromRedis(userId) {
    await this.redis.del(`presence:${userId}`);
    await this.redis.sRem('online-users', userId);
  }

  // Get user friends (stub - implement based on your system)
  async getUserFriends(userId) {
    // This would typically query your database
    return []; // Return array of friend IDs
  }

  // Cleanup stale entries
  setupCleanup() {
    setInterval(() => {
      this.cleanupStalePresence();
    }, this.cleanupInterval);
  }

  cleanupStalePresence() {
    const now = Date.now();
    
    for (const [userId, presence] of this.users) {
      // Check if presence is stale (no activity for timeout)
      if (now - presence.lastSeen > this.presenceTimeout) {
        // Update status to away
        if (presence.status === 'online') {
          presence.status = 'away';
          this.notifyStatusChange(userId, 'away');
        }
      }
    }
  }

  // Get presence statistics
  getStats() {
    const stats = {
      totalUsers: this.users.size,
      onlineCount: 0,
      awayCount: 0,
      offlineCount: 0,
      byDevice: {},
      byHour: new Array(24).fill(0)
    };
    
    const currentHour = new Date().getHours();
    
    for (const presence of this.users.values()) {
      if (presence.status === 'online') stats.onlineCount++;
      else if (presence.status === 'away') stats.awayCount++;
      else stats.offlineCount++;
      
      // Track devices
      const device = presence.metadata?.device || 'unknown';
      stats.byDevice[device] = (stats.byDevice[device] || 0) + 1;
      
      // Track activity by hour
      const connectedHour = new Date(presence.metadata?.connectedAt).getHours();
      stats.byHour[connectedHour]++;
    }
    
    return stats;
  }
}
```

#### 2. Advanced Presence with Status Messages
```javascript
class EnhancedPresenceManager extends PresenceManager {
  constructor(io, redis) {
    super(io, redis);
    this.statusMessages = new Map(); // userId -> status message
    this.customStatuses = new Map(); // userId -> custom status
    this.typingIndicators = new Map(); // roomId -> Set(userId)
  }

  // Update user status with message
  updateStatusWithMessage(userId, status, message = '', metadata = {}) {
    super.updateStatus(userId, status, metadata);
    
    if (message) {
      this.statusMessages.set(userId, {
        message,
        updatedAt: Date.now(),
        expiresAt: metadata.expiresAt || Date.now() + 24 * 60 * 60 * 1000 // 24 hours
      });
    }
    
    // Store in Redis
    this.storeStatusMessageInRedis(userId, message);
    
    // Notify friends
    this.notifyStatusUpdate(userId, status, message);
  }

  // Set custom status (like "In a meeting", "On vacation")
  setCustomStatus(userId, customStatus, emoji = '') {
    this.customStatuses.set(userId, {
      text: customStatus,
      emoji,
      setAt: Date.now()
    });
    
    // Store in Redis
    this.redis.setex(
      `custom-status:${userId}`,
      7 * 24 * 60 * 60, // 7 days
      JSON.stringify({ text: customStatus, emoji })
    );
    
    // Notify friends
    this.notifyCustomStatusChange(userId, customStatus, emoji);
  }

  // User starts typing in a room
  startTyping(userId, roomId) {
    if (!this.typingIndicators.has(roomId)) {
      this.typingIndicators.set(roomId, new Set());
    }
    
    this.typingIndicators.get(roomId).add(userId);
    
    // Notify others in room
    this.notifyTyping(userId, roomId, true);
    
    // Auto-clear after 5 seconds
    setTimeout(() => {
      this.stopTyping(userId, roomId);
    }, 5000);
  }

  // User stops typing in a room
  stopTyping(userId, roomId) {
    const roomTyping = this.typingIndicators.get(roomId);
    if (roomTyping) {
      roomTyping.delete(userId);
      
      // Cleanup empty room
      if (roomTyping.size === 0) {
        this.typingIndicators.delete(roomId);
      }
      
      // Notify others
      this.notifyTyping(userId, roomId, false);
    }
  }

  // Get users currently typing in a room
  getTypingUsers(roomId) {
    const roomTyping = this.typingIndicators.get(roomId);
    return roomTyping ? Array.from(roomTyping) : [];
  }

  // Get user's full presence info
  getFullPresence(userId) {
    const basicPresence = super.getUserPresence(userId);
    if (!basicPresence) return null;
    
    const statusMessage = this.statusMessages.get(userId);
    const customStatus = this.customStatuses.get(userId);
    const redisCustomStatus = this.getCustomStatusFromRedis(userId);
    
    return {
      ...basicPresence,
      statusMessage: statusMessage?.message,
      customStatus: customStatus?.text || redisCustomStatus?.text,
      customEmoji: customStatus?.emoji || redisCustomStatus?.emoji,
      isTypingIn: this.getRoomsWhereUserIsTyping(userId)
    };
  }

  // Get rooms where user is currently typing
  getRoomsWhereUserIsTyping(userId) {
    const rooms = [];
    
    for (const [roomId, typingUsers] of this.typingIndicators) {
      if (typingUsers.has(userId)) {
        rooms.push(roomId);
      }
    }
    
    return rooms;
  }

  // Store status message in Redis
  async storeStatusMessageInRedis(userId, message) {
    if (message) {
      await this.redis.setex(
        `status-message:${userId}`,
        24 * 60 * 60, // 24 hours
        message
      );
    } else {
      await this.redis.del(`status-message:${userId}`);
    }
  }

  // Get custom status from Redis
  async getCustomStatusFromRedis(userId) {
    try {
      const data = await this.redis.get(`custom-status:${userId}`);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Redis custom status error:', error);
      return null;
    }
  }

  // Notify status update
  async notifyStatusUpdate(userId, status, message) {
    const friends = await this.getUserFriends(userId);
    
    for (const friendId of friends) {
      const friendPresence = this.getUserPresence(friendId);
      
      if (friendPresence && friendPresence.status === 'online') {
        await this.redis.publish(`presence:${friendId}`, JSON.stringify({
          type: 'status-update',
          userId,
          status,
          message,
          timestamp: Date.now()
        }));
      }
    }
  }

  // Notify custom status change
  async notifyCustomStatusChange(userId, customStatus, emoji) {
    const friends = await this.getUserFriends(userId);
    
    for (const friendId of friends) {
      const friendPresence = this.getUserPresence(friendId);
      
      if (friendPresence && friendPresence.status === 'online') {
        await this.redis.publish(`presence:${friendId}`, JSON.stringify({
          type: 'custom-status-change',
          userId,
          customStatus,
          emoji,
          timestamp: Date.now()
        }));
      }
    }
  }

  // Notify typing status
  async notifyTyping(userId, roomId, isTyping) {
    // Get room members
    const roomMembers = await this.getRoomMembers(roomId);
    
    for (const memberId of roomMembers) {
      if (memberId === userId) continue; // Don't notify self
      
      const memberPresence = this.getUserPresence(memberId);
      if (memberPresence && memberPresence.status === 'online') {
        await this.redis.publish(`presence:${memberId}`, JSON.stringify({
          type: 'typing-update',
          userId,
          roomId,
          isTyping,
          timestamp: Date.now()
        }));
      }
    }
  }

  // Get room members (stub)
  async getRoomMembers(roomId) {
    // This would typically query your database
    return [];
  }

  // Cleanup expired status messages
  cleanupExpiredStatuses() {
    const now = Date.now();
    
    for (const [userId, statusMessage] of this.statusMessages) {
      if (statusMessage.expiresAt && now > statusMessage.expiresAt) {
        this.statusMessages.delete(userId);
        this.redis.del(`status-message:${userId}`);
      }
    }
  }
}
```

#### 3. Presence with Last Seen and Activity Tracking
```javascript
class ActivityTrackingPresenceManager extends EnhancedPresenceManager {
  constructor(io, redis) {
    super(io, redis);
    this.activityLogs = new Map(); // userId -> Activity[]
    this.activityRetention = 7 * 24 * 60 * 60 * 1000; // 7 days
    this.setupActivityCleanup();
  }

  // Track user activity
  trackActivity(userId, activityType, details = {}) {
    const activity = {
      type: activityType,
      timestamp: Date.now(),
      details,
      id: this.generateActivityId()
    };
    
    // Store in memory (limited retention)
    if (!this.activityLogs.has(userId)) {
      this.activityLogs.set(userId, []);
    }
    
    const userActivities = this.activityLogs.get(userId);
    userActivities.push(activity);
    
    // Keep only recent activities in memory
    if (userActivities.length > 1000) {
      userActivities.splice(0, userActivities.length - 1000);
    }
    
    // Store in Redis for persistence
    this.storeActivityInRedis(userId, activity);
    
    // Store in database for long-term storage
    this.storeActivityInDatabase(userId, activity);
    
    return activity;
  }

  // Get user activity history
  async getActivityHistory(userId, options = {}) {
    const {
      limit = 50,
      offset = 0,
      startDate = null,
      endDate = Date.now(),
      activityTypes = null
    } = options;
    
    // Get from memory cache first
    let activities = this.activityLogs.get(userId) || [];
    
    // Apply filters
    if (startDate) {
      activities = activities.filter(a => a.timestamp >= startDate);
    }
    
    if (endDate) {
      activities = activities.filter(a => a.timestamp <= endDate);
    }
    
    if (activityTypes) {
      activities = activities.filter(a => activityTypes.includes(a.type));
    }
    
    // Sort by timestamp (newest first)
    activities.sort((a, b) => b.timestamp - a.timestamp);
    
    // Apply pagination
    return activities.slice(offset, offset + limit);
  }

  // Get user's recent sessions
  async getUserSessions(userId, limit = 10) {
    const activities = await this.getActivityHistory(userId, {
      activityTypes: ['connect', 'disconnect'],
      limit: limit * 2 // Get extra to filter pairs
    });
    
    const sessions = [];
    let currentSession = null;
    
    for (const activity of activities) {
      if (activity.type === 'connect') {
        currentSession = {
          startTime: activity.timestamp,
          endTime: null,
          duration: null,
          device: activity.details.device,
          ip: activity.details.ip,
          activities: []
        };
      } else if (activity.type === 'disconnect' && currentSession) {
        currentSession.endTime = activity.timestamp;
        currentSession.duration = currentSession.endTime - currentSession.startTime;
        sessions.push(currentSession);
        currentSession = null;
      }
    }
    
    // Handle ongoing session
    if (currentSession) {
      currentSession.endTime = Date.now();
      currentSession.duration = currentSession.endTime - currentSession.startTime;
      sessions.push(currentSession);
    }
    
    return sessions.slice(0, limit);
  }

  // Get user activity statistics
  async getUserActivityStats(userId, period = 'day') {
    const now = Date.now();
    let startTime;
    
    switch (period) {
      case 'day':
        startTime = now - 24 * 60 * 60 * 1000;
        break;
      case 'week':
        startTime = now - 7 * 24 * 60 * 60 * 1000;
        break;
      case 'month':
        startTime = now - 30 * 24 * 60 * 60 * 1000;
        break;
      default:
        startTime = now - 24 * 60 * 60 * 1000;
    }
    
    const activities = await this.getActivityHistory(userId, {
      startDate: startTime,
      endDate: now
    });
    
    const stats = {
      totalActivities: activities.length,
      byType: {},
      byHour: new Array(24).fill(0),
      averageSessionDuration: 0,
      longestSessionDuration: 0
    };
    
    let totalSessionDuration = 0;
    let sessionCount = 0;
    
    // Analyze activities
    for (const activity of activities) {
      // Count by type
      stats.byType[activity.type] = (stats.byType[activity.type] || 0) + 1;
      
      // Count by hour
      const hour = new Date(activity.timestamp).getHours();
      stats.byHour[hour]++;
      
      // Calculate session durations
      if (activity.type === 'disconnect' && activity.details.sessionDuration) {
        totalSessionDuration += activity.details.sessionDuration;
        sessionCount++;
        
        if (activity.details.sessionDuration > stats.longestSessionDuration) {
          stats.longestSessionDuration = activity.details.sessionDuration;
        }
      }
    }
    
    // Calculate averages
    if (sessionCount > 0) {
      stats.averageSessionDuration = totalSessionDuration / sessionCount;
    }
    
    return stats;
  }

  // Override connection tracking to include activity
  userConnected(socket) {
    super.userConnected(socket);
    
    // Track connection activity
    this.trackActivity(socket.user.id, 'connect', {
      socketId: socket.id,
      device: socket.handshake.headers['user-agent'],
      ip: socket.handshake.address,
      userAgent: socket.handshake.headers['user-agent'],
      connectedAt: Date.now()
    });
  }

  // Override disconnection tracking
  userDisconnected(socket) {
    const userId = socket.user.id;
    const userPresence = this.users.get(userId);
    
    if (userPresence) {
      // Calculate session duration
      const sessionDuration = Date.now() - userPresence.metadata.connectedAt;
      
      // Track disconnection activity
      this.trackActivity(userId, 'disconnect', {
        socketId: socket.id,
        sessionDuration,
        disconnectedAt: Date.now(),
        reason: 'client-disconnect'
      });
    }
    
    super.userDisconnected(socket);
  }

  // Track message sending activity
  trackMessageActivity(userId, roomId, messageLength) {
    this.trackActivity(userId, 'send-message', {
      roomId,
      messageLength,
      timestamp: Date.now()
    });
  }

  // Track room join activity
  trackRoomJoinActivity(userId, roomId) {
    this.trackActivity(userId, 'join-room', {
      roomId,
      timestamp: Date.now()
    });
  }

  // Store activity in Redis
  async storeActivityInRedis(userId, activity) {
    const key = `activity:${userId}:${activity.id}`;
    const value = JSON.stringify(activity);
    
    await this.redis.setex(key, this.activityRetention / 1000, value);
    
    // Also add to activity list
    await this.redis.lPush(`activity-list:${userId}`, activity.id);
    await this.redis.lTrim(`activity-list:${userId}`, 0, 999); // Keep last 1000
  }

  // Store activity in database (stub)
  async storeActivityInDatabase(userId, activity) {
    // Implementation depends on your database
    // This would typically store in a time-series database or regular database
  }

  // Generate activity ID
  generateActivityId() {
    return `act_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Setup activity cleanup
  setupActivityCleanup() {
    // Cleanup old activities every hour
    setInterval(() => {
      this.cleanupOldActivities();
    }, 60 * 60 * 1000);
  }

  // Cleanup old activities
  async cleanupOldActivities() {
    const cutoffTime = Date.now() - this.activityRetention;
    
    for (const [userId, activities] of this.activityLogs) {
      // Remove old activities from memory
      const recentActivities = activities.filter(a => a.timestamp > cutoffTime);
      this.activityLogs.set(userId, recentActivities);
      
      // Cleanup Redis (Redis TTL will handle most of this)
      // We'll just trim the list
      await this.redis.lTrim(`activity-list:${userId}`, 0, 999);
    }
  }

  // Get system-wide activity statistics
  async getSystemActivityStats() {
    const stats = {
      totalOnline: this.getOnlineUsers().length,
      totalUsers: this.users.size,
      peakConcurrent: await this.getPeakConcurrent(),
      activityByHour: new Array(24).fill(0),
      messagesToday: 0,
      newUsersToday: 0
    };
    
    // Calculate activity by hour
    const now = new Date();
    const currentHour = now.getHours();
    
    for (let i = 0; i < 24; i++) {
      // This would typically query your database for historical data
      // For now, we'll use a simple estimation
      const hour = (currentHour - i + 24) % 24;
      stats.activityByHour[hour] = Math.floor(Math.random() * 100); // Placeholder
    }
    
    return stats;
  }

  async getPeakConcurrent() {
    // This would typically query your database for historical peak
    // For now, return current online count as placeholder
    return this.getOnlineUsers().length;
  }
}
```

#### 4. Presence Visualization and Monitoring
```javascript
class PresenceVisualization {
  constructor(presenceManager) {
    this.presenceManager = presenceManager;
    this.dashboardConnections = new Map(); // dashboardId -> socket
    this.setupDashboard();
  }

  setupDashboard() {
    // Setup WebSocket server for dashboard
    const dashboardIO = new Server(3001, {
      cors: {
        origin: process.env.DASHBOARD_URL,
        credentials: true
      }
    });
    
    dashboardIO.on('connection', (socket) => {
      console.log('Dashboard connected:', socket.id);
      
      const dashboardId = socket.handshake.query.dashboardId;
      this.dashboardConnections.set(dashboardId, socket);
      
      // Send initial data
      this.sendInitialData(socket);
      
      // Setup periodic updates
      const interval = setInterval(() => {
        this.sendLiveUpdates(socket);
      }, 5000); // Update every 5 seconds
      
      socket.on('disconnect', () => {
        clearInterval(interval);
        this.dashboardConnections.delete(dashboardId);
        console.log('Dashboard disconnected:', socket.id);
      });
      
      socket.on('request-data', (request) => {
        this.handleDataRequest(socket, request);
      });
    });
  }

  async sendInitialData(socket) {
    try {
      // Get system stats
      const systemStats = await this.presenceManager.getSystemActivityStats();
      
      // Get online users
      const onlineUsers = this.presenceManager.getOnlineUsers();
      
      // Get recent activities
      const recentActivities = await this.getRecentActivities(50);
      
      // Send initial data
      socket.emit('initial-data', {
        systemStats,
        onlineUsers: onlineUsers.slice(0, 100), // Limit to 100 users
        recentActivities,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Error sending initial data:', error);
      socket.emit('error', { message: 'Failed to load initial data' });
    }
  }

  async sendLiveUpdates(socket) {
    try {
      const updates = {
        onlineCount: this.presenceManager.getOnlineUsers().length,
        systemLoad: await this.getSystemLoad(),
        recentActivity: await this.getRecentActivities(10),
        timestamp: Date.now()
      };
      
      socket.emit('live-update', updates);
    } catch (error) {
      console.error('Error sending live updates:', error);
    }
  }

  async handleDataRequest(socket, request) {
    const { type, parameters } = request;
    
    try {
      let data;
      
      switch (type) {
        case 'user-details':
          data = await this.getUserDetails(parameters.userId);
          break;
          
        case 'activity-history':
          data = await this.presenceManager.getActivityHistory(
            parameters.userId,
            parameters.options
          );
          break;
          
        case 'user-sessions':
          data = await this.presenceManager.getUserSessions(
            parameters.userId,
            parameters.limit
          );
          break;
          
        case 'activity-stats':
          data = await this.presenceManager.getUserActivityStats(
            parameters.userId,
            parameters.period
          );
          break;
          
        case 'geographic-distribution':
          data = await this.getGeographicDistribution();
          break;
          
        case 'device-distribution':
          data = this.getDeviceDistribution();
          break;
          
        default:
          socket.emit('error', { message: 'Unknown request type' });
          return;
      }
      
      socket.emit('data-response', {
        requestId: request.requestId,
        type,
        data,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Data request error:', error);
      socket.emit('error', {
        requestId: request.requestId,
        message: 'Failed to process request'
      });
    }
  }

  async getUserDetails(userId) {
    const presence = this.presenceManager.getFullPresence(userId);
    
    if (!presence) {
      return { error: 'User not found' };
    }
    
    const sessions = await this.presenceManager.getUserSessions(userId, 10);
    const activityStats = await this.presenceManager.getUserActivityStats(userId, 'week');
    
    return {
      presence,
      recentSessions: sessions,
      activityStats,
      connectedAt: presence.metadata?.connectedAt,
      lastSeen: presence.lastSeen
    };
  }

  async getRecentActivities(limit) {
    // This would typically query your database
    // For now, return empty array
    return [];
  }

  async getSystemLoad() {
    // Get system metrics
    const memoryUsage = process.memoryUsage();
    const loadAvg = require('os').loadavg();
    
    return {
      memory: {
        used: memoryUsage.heapUsed,
        total: memoryUsage.heapTotal,
        rss: memoryUsage.rss
      },
      load: loadAvg,
      connections: this.presenceManager.users.size,
      uptime: process.uptime()
    };
  }

  async getGeographicDistribution() {
    // This would use IP geolocation
    // For now, return mock data
    return {
      regions: [
        { name: 'North America', count: 45 },
        { name: 'Europe', count: 30 },
        { name: 'Asia', count: 20 },
        { name: 'Other', count: 5 }
      ]
    };
  }

  getDeviceDistribution() {
    const devices = {};
    
    for (const presence of this.presenceManager.users.values()) {
      const device = presence.metadata?.device || 'unknown';
      
      // Categorize device
      let category = 'Other';
      
      if (device.includes('Mobile') || device.includes('Android') || device.includes('iPhone')) {
        category = 'Mobile';
      } else if (device.includes('Windows')) {
        category = 'Windows';
      } else if (device.includes('Mac')) {
        category = 'Mac';
      } else if (device.includes('Linux')) {
        category = 'Linux';
      }
      
      devices[category] = (devices[category] || 0) + 1;
    }
    
    return devices;
  }

  // Broadcast to all dashboards
  broadcastToDashboards(event, data) {
    for (const socket of this.dashboardConnections.values()) {
      if (socket.connected) {
        socket.emit(event, data);
      }
    }
  }

  // Send alert to dashboards
  sendAlert(level, message, details = {}) {
    const alert = {
      level, // 'info', 'warning', 'error'
      message,
      details,
      timestamp: Date.now(),
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
    };
    
    this.broadcastToDashboards('alert', alert);
    
    // Also log to console
    console.log(`[${level.toUpperCase()}] ${message}`, details);
  }
}
```

---

## 7. Interview Questions

### Socket.io Interview Questions

#### Junior to Mid-Level
1. **Q:** What is Socket.io and how does it differ from raw WebSockets?
   **A:** Socket.io is a library that provides real-time, bidirectional communication. It differs from raw WebSockets by providing automatic reconnection, rooms, namespaces, fallback to HTTP long-polling, and a higher-level API.

2. **Q:** How do you handle authentication in Socket.io?
   **A:** Use middleware with `io.use()` to verify tokens before allowing connections, and attach user data to the socket object.

3. **Q:** What are rooms in Socket.io and how do you use them?
   **A:** Rooms are channels that sockets can join/leave. Use `socket.join(roomId)` to add a socket to a room and `io.to(roomId).emit()` to broadcast to that room.

4. **Q:** How does Socket.io handle reconnection?
   **A:** Socket.io automatically attempts reconnection with exponential backoff. You can configure reconnection attempts, delays, and handle reconnection events.

5. **Q:** What are namespaces in Socket.io?
   **A:** Namespaces allow you to create separate communication channels on the same port. Useful for separating concerns like `/chat`, `/notifications`, `/admin`.

#### Senior Level
6. **Q:** How would you scale Socket.io to multiple servers?
   **A:** Use the Redis adapter (`@socket.io/redis-adapter`) to enable communication between multiple Socket.io server instances.

7. **Q:** Explain the Socket.io handshake process and protocol.
   **A:** Socket.io starts with an HTTP handshake, upgrades to WebSocket if possible, or falls back to polling. It uses Engine.io for transport and has its own packet protocol.

8. **Q:** How would you implement rate limiting for Socket.io connections?
   **A:** Track connection attempts per IP in Redis with a sliding window, and reject connections that exceed the limit in the middleware.

9. **Q:** What strategies would you use to handle very large rooms (10k+ users)?
   **A:** Implement room sharding, use Redis for pub/sub, consider peer-to-peer for some communications, and optimize message serialization.

10. **Q:** How do you ensure message delivery guarantees with Socket.io?
    **A:** Implement acknowledgement callbacks, sequence numbers, retry logic, and persistent message queues for critical messages.

### WebSockets Bare Implementation Interview Questions

#### Junior to Mid-Level
1. **Q:** What is the WebSocket protocol handshake process?
   **A:** Client sends an HTTP Upgrade request with `Upgrade: websocket` header, server responds with `101 Switching Protocols` if it accepts.

2. **Q:** How do you handle binary data with WebSockets?
   **A:** WebSocket protocol supports both text and binary frames. Use `ws.send(buffer)` for binary data and handle with `ws.on('message', (data) => {...})`.

3. **Q:** What are the different WebSocket ready states?
   **A:** CONNECTING (0), OPEN (1), CLOSING (2), CLOSED (3). Check with `ws.readyState`.

4. **Q:** How do you implement heartbeat/ping-pong in WebSockets?
   **A:** Use `ws.ping()` periodically and listen for `pong` events, or implement application-level ping/pong messages.

#### Senior Level
5. **Q:** How would you implement compression with WebSockets?
   **A:** Enable `perMessageDeflate` option in the WebSocket server, which uses the permessage-deflate extension for compression.

6. **Q:** What are the security considerations for WebSocket implementations?
   **A:** Validate origin headers, implement authentication, use WSS (TLS), rate limiting, input validation, and CSRF protection.

7. **Q:** How would you handle WebSocket frame fragmentation?
   **A:** Handle the `fin` flag in WebSocket frames - when false, more frames follow; when true, the message is complete.

8. **Q:** Explain how you'd implement a custom subprotocol for WebSockets.
   **A:** Negotiate subprotocol during handshake with `Sec-WebSocket-Protocol` header, then implement the agreed protocol.

### Redis Pub/Sub Interview Questions

#### Junior to Mid-Level
1. **Q:** What is Redis Pub/Sub and how does it work?
   **A:** A messaging pattern where publishers send messages to channels, and subscribers receive messages from channels they're subscribed to.

2. **Q:** How do pattern subscriptions work in Redis Pub/Sub?
   **A:** Use `PSUBSCRIBE` with patterns like `news:*` to subscribe to all channels matching the pattern.

3. **Q:** What happens if a message is published when no one is subscribed?
   **A:** The message is lost. Redis Pub/Sub doesn't persist messages.

4. **Q:** How do you handle reconnection with Redis Pub/Sub?
   **A:** Re-subscribe to channels after reconnection, track subscriptions locally, and handle `reconnecting` events.

#### Senior Level
5. **Q:** What are the limitations of Redis Pub/Sub for production systems?
   **A:** No message persistence, no acknowledgement, no queueing, memory pressure with many subscriptions, single-threaded nature.

6. **Q:** How would you implement reliable messaging with Redis?
   **A:** Use Redis Streams instead of Pub/Sub, implement consumer groups, message acknowledgement, and dead letter queues.

7. **Q:** How do you scale Redis Pub/Sub for high throughput?
   **A:** Use Redis Cluster with sharding, implement client-side batching, use connection pooling, and monitor memory usage.

8. **Q:** What alternatives to Redis Pub/Sub would you consider for different use cases?
   **A:** Kafka for persistent high-throughput, RabbitMQ for complex routing, NATS for simplicity and performance, AWS SNS/SQS for cloud.

### Broadcasting Events Interview Questions

#### Junior to Mid-Level
1. **Q:** What's the difference between `socket.emit`, `io.emit`, and `socket.broadcast.emit`?
   **A:** `socket.emit` sends to a specific socket, `io.emit` sends to all connected sockets, `socket.broadcast.emit` sends to all except the sender.

2. **Q:** How do you broadcast to a specific room?
   **A:** `io.to(roomId).emit(event, data)` broadcasts to all sockets in the room.

3. **Q:** What's the difference between `io.to(room).emit()` and `socket.to(room).emit()`?
   **A:** `io.to(room).emit()` sends from the server to the room, `socket.to(room).emit()` sends from a socket to others in the room.

#### Senior Level
4. **Q:** How would you implement priority-based broadcasting?
   **A:** Use multiple queues with different priorities, process high-priority messages first, implement rate limiting for low-priority.

5. **Q:** What strategies would you use to minimize bandwidth in broadcasting?
   **A:** Message compression, delta updates, batching, client-side caching, binary protocols like Protocol Buffers.

6. **Q:** How do you handle broadcast storms or denial of service via broadcasting?
   **A:** Implement rate limiting per user/room, validate messages before broadcasting, use message queues with backpressure.

7. **Q:** How would you implement geolocation-based broadcasting?
   **A:** Track user locations, use geospatial indexing (Redis Geo), broadcast to users within a radius, use CDN for regional broadcasts.

### Chat Applications Interview Questions

#### Junior to Mid-Level
1. **Q:** How would you implement typing indicators in a chat?
   **A:** Send `typing` event when user starts typing, set timeout to send `stopped-typing`, debounce rapid events.

2. **Q:** How do you handle message persistence in a chat app?
   **A:** Store messages in database (MongoDB, PostgreSQL), implement pagination for history, use Redis for caching recent messages.

3. **Q:** What's the strategy for showing "message read" receipts?
   **A:** Track when user views a message, send receipt to sender, store read status in database, handle race conditions.

#### Senior Level
4. **Q:** How would you design a chat system for 1 million concurrent users?
   **A:** Microservices architecture, Redis for pub/sub and caching, message queues for async processing, database sharding, CDN for media.

5. **Q:** How do you implement search in a chat application at scale?
   **A:** Use Elasticsearch for full-text search, index messages asynchronously, implement faceted search, cache frequent queries.

6. **Q:** What are the security considerations for a chat application?
   **A:** End-to-end encryption, message signing, rate limiting, input sanitization, audit logging, compliance with regulations.

7. **Q:** How would you implement offline messaging and synchronization?
   **A:** Store messages in queue when user offline, sync on reconnect, handle conflict resolution, implement read receipts for offline period.

### Online/Offline Presence Detection Interview Questions

#### Junior to Mid-Level
1. **Q:** How do you detect when a user goes offline?
   **A:** Track disconnect events, implement heartbeat/ping-pong, set timeout for inactivity, update status in database.

2. **Q:** What's the difference between "online", "away", and "offline" states?
   **A:** Online: actively connected; Away: connected but inactive; Offline: disconnected. Implement with activity tracking and timeouts.

3. **Q:** How do you handle user reconnection quickly?
   **A:** Use session recovery, keep connection state in Redis, restore rooms and subscriptions on reconnect.

#### Senior Level
4. **Q:** How would you implement a distributed presence system across multiple servers?
   **A:** Use Redis for shared state, implement gossip protocol or consistent hashing, handle network partitions with CRDTs.

5. **Q:** What strategies would you use to reduce false offline notifications?
   **A:** Implement grace periods, use heartbeat with adaptive timeouts, verify with multiple signals, handle network flapping.

6. **Q:** How do you scale presence tracking for millions of users?
   **A:** Shard by user ID, use probabilistic data structures like HyperLogLog for counts, implement lazy cleanup, use time-series databases.

7. **Q:** How would you implement "last seen" functionality respecting privacy?
   **A:** Granular privacy controls (exact time, today, this week, hidden), implement at database level, respect user preferences.

---

## 8. Real-World Scenarios

### Scenario 1: Large-Scale Trading Platform

**Context:** A stock trading platform with 500,000 concurrent users needing real-time price updates, order execution notifications, and market data.

**Requirements:**
- Sub-millisecond latency for price updates
- Reliable delivery of order execution notifications
- Market data broadcasting to specific user groups
- Connection stability during market volatility
- Regulatory compliance and audit trails

**Design Questions:**

1. **How would you architect the real-time system?**
   ```
   Answer:
   - Use WebSocket for low-latency price updates
   - Implement Redis Cluster for pub/sub with message partitioning
   - Use Kafka for reliable order notification delivery
   - Implement connection pools with circuit breakers
   - Use geographic load balancing for latency optimization
   - Implement message prioritization (price updates > orders > market data)
   ```

2. **How would you handle market opening/closing surges?**
   ```
   Answer:
   - Auto-scaling WebSocket servers based on connection count
   - Pre-warm connections before market open
   - Implement connection queuing with graceful degradation
   - Use CDN for static resources to reduce server load
   - Implement rate limiting per user with dynamic adjustments
   ```

3. **How would you ensure regulatory compliance?**
   ```
   Answer:
   - Full audit trail of all real-time communications
   - Message signing and non-repudiation
   - Data retention policies with immutable storage
   - Real-time monitoring and alerting for anomalies
   - Regular penetration testing and security audits
   ```

### Scenario 2: Real-time Collaboration Tool

**Context:** A Google Docs-like collaboration tool with 50,000 concurrent editors needing real-time synchronization, presence detection, and conflict resolution.

**Requirements:**
- Real-time document synchronization
- Presence detection (who's viewing/editing)
- Conflict resolution for concurrent edits
- Offline editing support
- Version history and rollback
- Large document support (100k+ lines)

**Design Questions:**

1. **How would you implement real-time document synchronization?**
   ```
   Answer:
   - Use Operational Transformation or CRDTs for conflict resolution
   - Implement delta updates to minimize data transfer
   - Use Redis for shared document state
   - Implement compression for large documents
   - Use WebSocket with fallback to Server-Sent Events
   ```

2. **How would you handle presence detection for large teams?**
   ```
   Answer:
   - Implement presence sharding by document ID
   - Use Redis HyperLogLog for approximate viewer counts
   - Implement cursor position broadcasting with throttling
   - Use presence aggregation for summary views
   - Implement privacy controls for presence visibility
   ```

3. **How would you support offline editing?**
   ```
   Answer:
   - Service Worker for offline caching
   - IndexedDB for local document storage
   - Conflict resolution queue for offline changes
   - Background sync for upload when online
   - Version vector clocks for offline/online merge
   ```

### Scenario 3: Multiplayer Game Server

**Context:** An MMORPG with 100,000 concurrent players needing real-time position updates, combat events, and world state synchronization.

**Requirements:**
- 60Hz update rate for player positions
- Reliable event delivery for combat actions
- World state synchronization across zones
- Cheat detection and prevention
- Lag compensation and prediction

**Design Questions:**

1. **How would you architect the game server?**
   ```
   Answer:
   - Zone-based server architecture with load balancing
   - UDP for position updates (with reliability layer)
   - WebSocket for chat and non-critical events
   - Redis for shared game state
   - Spatial partitioning for efficient neighbor updates
   - Prediction and reconciliation for client-side smoothing
   ```

2. **How would you handle player movement synchronization?**
   ```
   Answer:
   - Dead reckoning with client-side prediction
   - Server authoritative movement validation
   - Interpolation for smooth rendering
   - Lag compensation in hit detection
   - Optimistic updates with rollback on validation failure
   ```

3. **How would you implement anti-cheat measures?**
   ```
   Answer:
   - Server-side validation of all actions
   - Rate limiting and anomaly detection
   - Behavioral analysis for cheat patterns
   - Cryptographic signing of game state
   - Regular integrity checks and heartbeat validation
   ```

### Scenario 4: Real-time Analytics Dashboard

**Context:** A business analytics dashboard showing real-time metrics from 10,000 data sources with 100,000 concurrent viewers.

**Requirements:**
- Real-time metric updates (1-second intervals)
- Historical data streaming
- Alerting and notifications
- Dashboard personalization
- Data aggregation and roll-up

**Design Questions:**

1. **How would you stream real-time metrics efficiently?**
   ```
   Answer:
   - WebSocket connections for live data
   - Server-Sent Events for one-way streaming
   - Data compression and delta encoding
   - Client-side aggregation for high-frequency data
   - Priority-based updates (critical metrics first)
   ```

2. **How would you handle dashboard personalization?**
   ```
   Answer:
   - Per-user WebSocket channels
   - Dynamic subscription management
   - Client-side filtering and aggregation
   - Cached dashboard configurations
   - Real-time permission updates
   ```

3. **How would you implement real-time alerts?**
   ```
   Answer:
   - Rule engine with Webhook integration
   - Real-time pattern matching on data streams
   - Escalation policies and notification channels
   - Alert deduplication and correlation
   - Historical alert analysis and reporting
   ```

### Scenario 5: Live Video Streaming Chat

**Context:** A live streaming platform with chat for 1 million concurrent viewers during major events.

**Requirements:**
- Real-time chat message delivery
- Moderation and spam prevention
- Emote/effect synchronization with video
- User ranking and badge display
- Message rate limiting and throttling

**Design Questions:**

1. **How would you scale chat for 1 million concurrent users?**
   ```
   Answer:
   - Shard chat rooms by stream ID
   - Use Redis Cluster for message broadcasting
   - Implement message batching and compression
   - Edge computing for message distribution
   - Connection pooling and load balancing
   ```

2. **How would you implement real-time moderation?**
   ```
   Answer:
   - Automated moderation with ML models
   - Real-time keyword filtering
   - User reputation scoring
   - Moderator dashboard with live oversight
   - Appeal and review system
   ```

3. **How would you synchronize emotes with video playback?**
   ```
   Answer:
   - Timestamp-based emote triggering
   - WebSocket messages synchronized with video timestamps
   - Client-side buffering for synchronization
   - Backward compatibility for different latency clients
   - Emote effect prediction and preloading
   ```

### Scenario 6: IoT Device Management Platform

**Context:** A platform managing 500,000 IoT devices with real-time monitoring, command execution, and firmware updates.

**Requirements:**
- Real-time device status monitoring
- Reliable command execution with acknowledgement
- Over-the-air firmware updates
- Device grouping and bulk operations
- Network bandwidth optimization

**Design Questions:**

1. **How would you implement real-time device monitoring?**
   ```
   Answer:
   - MQTT for device communication (better for constrained devices)
   - WebSocket for web dashboard
   - Redis for real-time device state
   - Time-series database for historical data
   - Device heartbeat and connection monitoring
   ```

2. **How would you ensure reliable command execution?**
   ```
   Answer:
   - Message queuing with retry logic
   - Command acknowledgement and timeout handling
   - Idempotent command processing
   - Command status tracking and reporting
   - Fallback mechanisms for offline devices
   ```

3. **How would you handle firmware updates for 500k devices?**
   ```
   Answer:
   - Progressive rollout with canary testing
   - Delta updates to minimize bandwidth
   - Resumable downloads with checksum verification
   - Rollback capability on failure
   - Update status tracking and reporting
   ```

These scenarios and questions cover a wide range of real-time system challenges. The key principles across all scenarios are: appropriate protocol selection, efficient data structures, proper scaling strategies, reliability considerations, and comprehensive monitoring. Each use case requires balancing latency, reliability, scalability, and development complexity based on specific requirements.
>>>>>>> d0a590e89fef871f6721283530db2ba86930d6aa
