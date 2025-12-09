# API Architecture - Complete Guide

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

## Sorting

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

  buildFullResponse(resource) {
    return {
      ...resource,
      _links: this.links,
      _actions: this.actions,
      _metadata: {
        version: '1.0',
        timestamp: new Date().toISOString()
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

## Interview Questions

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