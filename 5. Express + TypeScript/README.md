# Express.js + TypeScript - Comprehensive Guide

## 📚 Table of Contents
- [Introduction](#introduction)
- [Setting up TypeScript Node Project](#setting-up-typescript-node-project)
- [tsconfig Configuration](#tsconfig-configuration)
- [Typing Request, Response, NextFunction](#typing-request-response-nextfunction)
- [Creating Types for Custom Payloads](#creating-types-for-custom-payloads)
- [Typing Middleware](#typing-middleware)
- [Typing Route Handlers](#typing-route-handlers)
- [Typing Error Handlers](#typing-error-handlers)
- [Custom Interfaces for DB Models](#custom-interfaces-for-db-models)
- [Enums for Constants](#enums-for-constants)
- [DTO Patterns (Data Transfer Objects)](#dto-patterns-data-transfer-objects)
- [Interview Questions](#interview-questions)
- [Real-World Scenarios](#real-world-scenarios)

## Introduction

TypeScript brings static typing to Express.js, enabling better developer experience, early error detection, and improved code maintainability. This guide covers production-grade TypeScript patterns for Express.js applications.

## Setting up TypeScript Node Project

### 🚀 Project Initialization

```bash
# Create project directory
mkdir express-ts-project
cd express-ts-project

# Initialize npm project
npm init -y

# Install TypeScript and types
npm install -D typescript ts-node @types/node
npm install -D ts-node-dev nodemon

# Install Express with types
npm install express
npm install -D @types/express

# Install additional useful types
npm install -D @types/cors @types/helmet @types/morgan @types/multer
```

### 📁 Project Structure

```
src/
├── app.ts                  # Express app initialization
├── server.ts              # Server entry point
├── types/                 # TypeScript type definitions
│   ├── express.d.ts      # Extended Express types
│   ├── models/          # Database models
│   ├── dto/             # Data Transfer Objects
│   └── enums/           # Enums and constants
├── config/               # Configuration
│   └── index.ts
├── middleware/           # Custom middleware
├── controllers/          # Route controllers
├── services/             # Business logic
├── routes/               # Route definitions
├── utils/                # Utilities
├── validators/           # Request validation
└── tests/                # Tests
```

### 📝 Initial TypeScript Configuration

```json
// package.json
{
  "name": "express-ts-project",
  "version": "1.0.0",
  "main": "dist/server.js",
  "scripts": {
    "dev": "ts-node-dev --respawn --transpile-only src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "lint": "eslint src --ext .ts",
    "test": "jest",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/node": "^20.11.5",
    "ts-node": "^10.9.2",
    "ts-node-dev": "^2.0.0",
    "typescript": "^5.3.3"
  }
}
```

### 🔧 Development Setup

```json
// .editorconfig
root = true

[*]
indent_style = space
indent_size = 2
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[*.ts]
quote_type = single
```

```json
// .vscode/settings.json
{
  "typescript.preferences.importModuleSpecifier": "relative",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.organizeImports": true
  },
  "editor.formatOnSave": true,
  "typescript.format.enable": true,
  "files.eol": "\n"
}
```

## tsconfig Configuration

### ⚙️ Basic Configuration

```json
// tsconfig.json
{
  "compilerOptions": {
    /* Basic Options */
    "target": "ES2022",
    "module": "CommonJS",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    
    /* Strict Type-Checking */
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "useUnknownInCatchVariables": true,
    "alwaysStrict": true,
    
    /* Additional Checks */
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "noPropertyAccessFromIndexSignature": true,
    
    /* Module Resolution */
    "moduleResolution": "node",
    "baseUrl": "./src",
    "paths": {
      "@/*": ["./*"],
      "@types/*": ["types/*"],
      "@controllers/*": ["controllers/*"],
      "@middleware/*": ["middleware/*"],
      "@services/*": ["services/*"],
      "@utils/*": ["utils/*"]
    },
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true,
    
    /* Source Map */
    "sourceMap": true,
    "declaration": true,
    "declarationMap": true,
    
    /* Experimental */
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    
    /* Advanced */
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "importsNotUsedAsValues": "remove"
  },
  "include": [
    "src/**/*",
    "types/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
```

### 🎯 Advanced Configuration Variants

```json
// tsconfig.build.json - For production builds
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "sourceMap": false,
    "declaration": false,
    "declarationMap": false,
    "incremental": false,
    "tsBuildInfoFile": null,
    "noEmitOnError": true
  },
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts",
    "**/*.e2e.ts",
    "scripts"
  ]
}
```

```json
// tsconfig.test.json - For testing environment
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "types": ["jest", "node"],
    "noImplicitAny": false,
    "strictNullChecks": true
  },
  "include": [
    "src/**/*",
    "tests/**/*"
  ]
}
```

### 🔧 Strict Mode Benefits

```typescript
// With strict: true, TypeScript catches these errors:

// 1. noImplicitAny
function greet(name) {  // Error: Parameter has implicit 'any' type
  return `Hello ${name}`;
}

// 2. strictNullChecks
let name: string;
name = null;  // Error: Type 'null' is not assignable to type 'string'

// 3. strictFunctionTypes
type Handler = (x: string) => void;
let handler: Handler = (x: boolean) => {};  // Error

// 4. strictPropertyInitialization
class User {
  name: string;  // Error: Property has no initializer
}

// 5. noImplicitReturns
function getUser(id: number): User {
  if (id > 0) {
    return new User();
  }
  // Error: Function lacks ending return statement
}

// 6. useUnknownInCatchVariables
try {
  // ...
} catch (error) {
  // error is 'unknown' instead of 'any'
  if (error instanceof Error) {
    console.log(error.message);
  }
}

// 7. noUncheckedIndexedAccess
const array: string[] = [];
const first = array[0];  // Type is string | undefined

// 8. noPropertyAccessFromIndexSignature
interface Config {
  [key: string]: string;
  default: string;
}

const config: Config = getConfig();
config.default;  // OK
config.unknown;  // Error: Property doesn't exist
```

### 🛠️ Path Aliases Configuration

```json
// tsconfig.json - Path aliases
{
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"],
      "@controllers/*": ["controllers/*"],
      "@middleware/*": ["middleware/*"],
      "@services/*": ["services/*"],
      "@utils/*": ["utils/*"],
      "@types/*": ["types/*"],
      "@config/*": ["config/*"],
      "@validators/*": ["validators/*"]
    }
  }
}
```

```javascript
// For runtime path resolution
// Install module-alias
npm install module-alias

// package.json
{
  "_moduleAliases": {
    "@": "dist",
    "@controllers": "dist/controllers",
    "@middleware": "dist/middleware",
    "@services": "dist/services",
    "@utils": "dist/utils"
  }
}

// src/server.ts
import 'module-alias/register';
```

## Typing Request, Response, NextFunction

### 📝 Express Type Definitions

```typescript
// types/express.d.ts
import { JwtPayload } from 'jsonwebtoken';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
      requestId: string;
      validatedData?: any;
      transaction?: any;
      file?: Multer.File;
      files?: { [fieldname: string]: Multer.File[] };
    }

    interface Response {
      success(data?: any, message?: string): Response;
      error(error: Error | string, statusCode?: number): Response;
      paginate(data: any[], total: number, page: number, limit: number): Response;
    }
  }
}

// User payload from JWT
export interface UserPayload extends JwtPayload {
  id: string;
  email: string;
  role: UserRole;
  permissions: string[];
}

// Request context
export interface RequestContext {
  requestId: string;
  user?: UserPayload;
  ip: string;
  userAgent: string;
  timestamp: Date;
}

// Typed request parameters
export interface TypedRequestParams<T = any> extends Express.Request {
  body: T;
}

export interface TypedRequestQuery<T = any> extends Express.Request {
  query: T;
}

export interface TypedRequest<TBody = any, TQuery = any, TParams = any> 
  extends Express.Request {
  body: TBody;
  query: TQuery;
  params: TParams;
}
```

### 🎯 Request Typing Examples

```typescript
import { Request, Response, NextFunction } from 'express';
import { 
  TypedRequest, 
  TypedRequestParams, 
  TypedRequestQuery,
  UserPayload 
} from '@/types/express';

// 1. Basic typed request
interface CreateUserBody {
  name: string;
  email: string;
  password: string;
  age?: number;
}

export const createUser = (
  req: TypedRequest<CreateUserBody>,
  res: Response,
  next: NextFunction
) => {
  // req.body is fully typed
  const { name, email, password, age } = req.body;
  
  // TypeScript knows age is optional
  if (age && age < 18) {
    throw new Error('Must be 18 or older');
  }
  
  // ...
};

// 2. Typed query parameters
interface PaginationQuery {
  page?: string;
  limit?: string;
  sort?: 'asc' | 'desc';
  search?: string;
}

export const getUsers = (
  req: TypedRequest<{}, PaginationQuery>,
  res: Response,
  next: NextFunction
) => {
  const { page = '1', limit = '20', sort = 'asc', search } = req.query;
  
  // TypeScript knows these are strings or undefined
  const pageNum = parseInt(page);
  const limitNum = parseInt(limit);
  
  // ...
};

// 3. Typed route parameters
interface UserParams {
  userId: string;
}

export const getUser = (
  req: TypedRequest<{}, {}, UserParams>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.params;
  
  // TypeScript knows userId is a string
  if (!isValidObjectId(userId)) {
    throw new Error('Invalid user ID');
  }
  
  // ...
};

// 4. Combined typing
interface UpdateUserRequest {
  body: {
    name?: string;
    email?: string;
  };
  params: {
    id: string;
  };
  query: {
    force?: string;
  };
}

export const updateUser = (
  req: TypedRequest<
    UpdateUserRequest['body'],
    UpdateUserRequest['query'],
    UpdateUserRequest['params']
  >,
  res: Response,
  next: NextFunction
) => {
  const { name, email } = req.body;
  const { id } = req.params;
  const { force } = req.query;
  
  // All properties are properly typed
  // ...
};
```

### 🔧 Response Typing Extensions

```typescript
// middleware/responseFormatter.ts
import { Request, Response, NextFunction } from 'express';

// Extend Response prototype
declare global {
  namespace Express {
    interface Response {
      success<T = any>(data?: T, message?: string): Response;
      error(error: Error | string, statusCode?: number): Response;
      paginate<T = any>(
        data: T[], 
        total: number, 
        page: number, 
        limit: number
      ): Response;
    }
  }
}

export const responseFormatter = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Success response
  res.success = function<T = any>(data?: T, message: string = 'Success') {
    return this.status(200).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    });
  };

  // Error response
  res.error = function(error: Error | string, statusCode: number = 500) {
    const message = error instanceof Error ? error.message : error;
    
    return this.status(statusCode).json({
      success: false,
      message,
      error: process.env.NODE_ENV === 'development' 
        ? error instanceof Error ? error.stack : undefined 
        : undefined,
      timestamp: new Date().toISOString()
    });
  };

  // Paginated response
  res.paginate = function<T = any>(
    data: T[], 
    total: number, 
    page: number, 
    limit: number
  ) {
    const totalPages = Math.ceil(total / limit);
    
    return this.status(200).json({
      success: true,
      data,
      pagination: {
        total,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      },
      timestamp: new Date().toISOString()
    });
  };

  next();
};

// Usage in controllers
export const getUsers = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const { data, total } = await userService.getUsers(
      Number(page),
      Number(limit)
    );
    
    // Typed response
    return res.paginate(data, total, Number(page), Number(limit));
  } catch (error) {
    next(error);
  }
};
```

## Creating Types for Custom Payloads

### 📦 Payload Type Patterns

```typescript
// types/payloads.ts
import { Request } from 'express';

// Authentication payloads
export interface LoginPayload {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RegisterPayload extends LoginPayload {
  name: string;
  confirmPassword: string;
  termsAccepted: boolean;
}

// User management payloads
export interface CreateUserPayload {
  name: string;
  email: string;
  password: string;
  role: UserRole;
  departmentId?: string;
  metadata?: Record<string, any>;
}

export interface UpdateUserPayload {
  name?: string;
  email?: string;
  role?: UserRole;
  departmentId?: string;
  metadata?: Record<string, any>;
}

// Pagination payload
export interface PaginationPayload {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  search?: string;
  filters?: Record<string, any>;
}

// File upload payload
export interface FileUploadPayload {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  destination: string;
  filename: string;
  path: string;
  buffer?: Buffer;
}

// Webhook payload
export interface WebhookPayload<T = any> {
  event: string;
  data: T;
  timestamp: Date;
  signature?: string;
}

// Generic API response payload
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: Date;
  requestId?: string;
}

// Typed request with payload
export type TypedRequestBody<T> = Request<{}, {}, T>;
export type TypedRequestParams<T> = Request<T>;
export type TypedRequestQuery<T> = Request<{}, {}, {}, T>;
```

### 🎯 Advanced Payload Types with Validation

```typescript
// types/validated-payloads.ts
import { z } from 'zod';
import { Request } from 'express';

// Define schemas with Zod
export const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  rememberMe: z.boolean().optional()
});

export const registerSchema = loginSchema.extend({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  confirmPassword: z.string(),
  termsAccepted: z.boolean().refine(val => val === true, {
    message: 'You must accept the terms and conditions'
  })
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword']
});

export const paginationSchema = z.object({
  page: z.string().transform(val => parseInt(val, 10)).optional(),
  limit: z.string().transform(val => parseInt(val, 10)).optional(),
  sort: z.string().optional(),
  order: z.enum(['asc', 'desc']).optional(),
  search: z.string().optional()
});

// Infer TypeScript types from Zod schemas
export type LoginPayload = z.infer<typeof loginSchema>;
export type RegisterPayload = z.infer<typeof registerSchema>;
export type PaginationPayload = z.infer<typeof paginationSchema>;

// Typed request with validated body
export interface ValidatedRequest<T> extends Request {
  validatedData: T;
}

// Usage example
export const loginHandler = async (
  req: ValidatedRequest<LoginPayload>,
  res: Response
) => {
  // req.validatedData is fully typed and validated
  const { email, password } = req.validatedData;
  
  // Type-safe usage
  const user = await authService.login(email, password);
  return res.success(user);
};
```

### 🔄 Generic Payload Patterns

```typescript
// types/generics.ts

// Generic response wrapper
export interface ApiResponse<T = any, E = string> {
  success: boolean;
  data?: T;
  error?: E;
  message?: string;
  meta?: Record<string, any>;
}

// Generic pagination response
export interface PaginatedResponse<T = any> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Generic filter interface
export interface FilterOptions<T = Record<string, any>> {
  where?: Partial<T>;
  order?: Record<string, 'ASC' | 'DESC'>;
  limit?: number;
  offset?: number;
  include?: any[];
}

// Generic CRUD operations
export interface CrudOperations<T, CreateDto, UpdateDto> {
  create(data: CreateDto): Promise<T>;
  findById(id: string): Promise<T | null>;
  findAll(options?: FilterOptions<T>): Promise<T[]>;
  update(id: string, data: UpdateDto): Promise<T>;
  delete(id: string): Promise<boolean>;
}

// Generic service interface
export interface Service<T, CreateDto, UpdateDto> extends CrudOperations<T, CreateDto, UpdateDto> {
  // Additional business logic methods
  search(query: string): Promise<T[]>;
  batchCreate(items: CreateDto[]): Promise<T[]>;
  softDelete(id: string): Promise<T>;
}

// Generic repository interface
export interface Repository<T> {
  create(entity: Partial<T>): Promise<T>;
  findById(id: string): Promise<T | null>;
  findOne(criteria: Partial<T>): Promise<T | null>;
  findAll(criteria?: Partial<T>): Promise<T[]>;
  update(id: string, entity: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
  count(criteria?: Partial<T>): Promise<number>;
}
```

## Typing Middleware

### 🔧 Basic Middleware Typing

```typescript
// middleware/types.ts
import { Request, Response, NextFunction } from 'express';

// Basic middleware type
export type Middleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

// Error middleware type
export type ErrorMiddleware = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => void;

// Async middleware type
export type AsyncMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void>;

// Middleware with configuration
export type ConfigurableMiddleware<T = any> = (
  config?: T
) => Middleware;

// Guard middleware (returns boolean)
export type GuardMiddleware = (
  req: Request
) => boolean | Promise<boolean>;
```

### 🛠️ Typed Middleware Examples

```typescript
// middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserPayload } from '@/types/express';

export interface AuthMiddlewareConfig {
  required?: boolean;
  roles?: string[];
  permissions?: string[];
}

// Type for authenticated request
export interface AuthenticatedRequest extends Request {
  user: UserPayload;
}

export const authMiddleware = (
  config: AuthMiddlewareConfig = {}
): AsyncMiddleware => {
  const { required = true, roles = [], permissions = [] } = config;
  
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        if (required) {
          throw new Error('Authentication required');
        }
        return next();
      }
      
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET!
      ) as UserPayload;
      
      // Type assertion to AuthenticatedRequest
      (req as AuthenticatedRequest).user = decoded;
      
      // Check roles
      if (roles.length > 0 && !roles.includes(decoded.role)) {
        throw new Error('Insufficient permissions');
      }
      
      // Check permissions
      if (permissions.length > 0) {
        const hasPermission = permissions.every(permission => 
          decoded.permissions.includes(permission)
        );
        
        if (!hasPermission) {
          throw new Error('Missing required permissions');
        }
      }
      
      next();
    } catch (error) {
      if (required) {
        res.status(401).json({ error: 'Authentication failed' });
      } else {
        next();
      }
    }
  };
};

// Usage
app.get(
  '/admin/dashboard',
  authMiddleware({ required: true, roles: ['admin'] }),
  adminController.getDashboard
);
```

### 🎯 Advanced Middleware Patterns

```typescript
// middleware/validation.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';

export const validate = <T extends AnyZodObject>(
  schema: T,
  source: 'body' | 'query' | 'params' = 'body'
) => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // Validate based on source
      const validatedData = await schema.parseAsync(req[source]);
      
      // Attach validated data to request
      req.validatedData = validatedData;
      
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        res.status(400).json({
          error: 'Validation failed',
          details: error.errors
        });
      } else {
        next(error);
      }
    }
  };
};

// middleware/rate-limit.middleware.ts
import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';

export interface RateLimitConfig {
  windowMs: number;
  max: number;
  message?: string;
  skip?: (req: Request) => boolean;
}

export const createRateLimiter = (
  config: RateLimitConfig
): AsyncMiddleware => {
  const limiter = rateLimit({
    windowMs: config.windowMs,
    max: config.max,
    message: config.message,
    skip: config.skip,
    standardHeaders: true,
    legacyHeaders: false
  });
  
  return async (req: Request, res: Response, next: NextFunction) => {
    return limiter(req, res, next);
  };
};

// middleware/logging.middleware.ts
import { Request, Response, NextFunction } from 'express';
import logger from '@/utils/logger';

export interface LoggingConfig {
  level: 'info' | 'warn' | 'error';
  excludePaths?: string[];
  includeBody?: boolean;
}

export const createLogger = (
  config: LoggingConfig
): Middleware => {
  const { level = 'info', excludePaths = [], includeBody = false } = config;
  
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip excluded paths
    if (excludePaths.includes(req.path)) {
      return next();
    }
    
    const start = Date.now();
    
    // Log request
    logger[level]({
      message: 'Incoming request',
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      ...(includeBody && { body: req.body })
    });
    
    // Log response
    res.on('finish', () => {
      const duration = Date.now() - start;
      
      logger[level]({
        message: 'Request completed',
        method: req.method,
        url: req.url,
        status: res.statusCode,
        duration,
        user: (req as any).user?.id
      });
    });
    
    next();
  };
};

// middleware/transaction.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';

export interface TransactionalRequest extends Request {
  transaction?: any;
}

export const transactionMiddleware = (
  sequelize: Sequelize
): AsyncMiddleware => {
  return async (req: TransactionalRequest, res: Response, next: NextFunction) => {
    const transaction = await sequelize.transaction();
    
    req.transaction = transaction;
    
    // Commit on success
    res.on('finish', async () => {
      if (res.statusCode < 400) {
        await transaction.commit();
      } else {
        await transaction.rollback();
      }
    });
    
    // Rollback on error
    res.on('error', async () => {
      await transaction.rollback();
    });
    
    next();
  };
};
```

### 🔄 Middleware Composition

```typescript
// middleware/compose.middleware.ts
import { Request, Response, NextFunction, Handler } from 'express';

// Compose multiple middleware into one
export const composeMiddleware = (
  ...middlewares: Handler[]
): Handler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    let middlewareIndex = 0;
    
    const runNext = async (err?: any) => {
      if (err) {
        return next(err);
      }
      
      if (middlewareIndex >= middlewares.length) {
        return next();
      }
      
      const middleware = middlewares[middlewareIndex++];
      
      try {
        if (middleware.length === 4) {
          // Error handling middleware
          await middleware(err, req, res, runNext);
        } else {
          // Regular middleware
          await middleware(req, res, runNext);
        }
      } catch (error) {
        runNext(error);
      }
    };
    
    await runNext();
  };
};

// Conditional middleware
export const conditionalMiddleware = (
  condition: (req: Request) => boolean | Promise<boolean>,
  trueMiddleware: Handler,
  falseMiddleware?: Handler
): Handler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await condition(req);
      
      if (result) {
        await trueMiddleware(req, res, next);
      } else if (falseMiddleware) {
        await falseMiddleware(req, res, next);
      } else {
        next();
      }
    } catch (error) {
      next(error);
    }
  };
};

// Pipeline pattern
export const createPipeline = <T extends Record<string, any>>(
  ...transformers: Array<(data: T) => T | Promise<T>>
) => {
  return async (initialData: T): Promise<T> => {
    let result = initialData;
    
    for (const transformer of transformers) {
      result = await transformer(result);
    }
    
    return result;
  };
};

// Usage example
export const userProcessingPipeline = createPipeline(
  (data) => ({ ...data, email: data.email.toLowerCase() }),
  (data) => ({ ...data, name: data.name.trim() }),
  async (data) => {
    // Async transformation
    const hashedPassword = await hashPassword(data.password);
    return { ...data, password: hashedPassword };
  }
);
```

## Typing Route Handlers

### 🗺️ Basic Route Handler Typing

```typescript
// types/handlers.ts
import { Request, Response, NextFunction } from 'express';

// Basic handler types
export type RouteHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

export type ErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => void;

// Typed handler with request type
export type TypedRouteHandler<TRequest = Request> = (
  req: TRequest,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

// Handler with return type
export type ReturningHandler<T = any> = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<T>;

// Handler factory
export type HandlerFactory<T = any> = (
  ...args: any[]
) => RouteHandler;
```

### 🎯 Controller Pattern with Typing

```typescript
// controllers/base.controller.ts
import { Request, Response, NextFunction } from 'express';
import { Service } from '@/types/generics';

export abstract class BaseController<T, CreateDto, UpdateDto> {
  protected service: Service<T, CreateDto, UpdateDto>;
  
  constructor(service: Service<T, CreateDto, UpdateDto>) {
    this.service = service;
  }
  
  // Typed handler methods
  abstract create(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void>;
  
  abstract findAll(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void>;
  
  abstract findOne(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void>;
  
  abstract update(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void>;
  
  abstract delete(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void>;
  
  // Common response methods
  protected success(
    res: Response,
    data?: any,
    message: string = 'Success'
  ): Response {
    return res.status(200).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    });
  }
  
  protected created(
    res: Response,
    data?: any,
    message: string = 'Created'
  ): Response {
    return res.status(201).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    });
  }
  
  protected error(
    res: Response,
    error: Error | string,
    statusCode: number = 500
  ): Response {
    const message = error instanceof Error ? error.message : error;
    
    return res.status(statusCode).json({
      success: false,
      message,
      timestamp: new Date().toISOString()
    });
  }
}

// controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { BaseController } from './base.controller';
import { UserService } from '@/services/user.service';
import { 
  CreateUserDto, 
  UpdateUserDto, 
  UserResponse 
} from '@/types/dto/user.dto';
import { validate } from '@/middleware/validation.middleware';
import { userSchemas } from '@/validators/user.validator';

export class UserController extends BaseController<
  UserResponse,
  CreateUserDto,
  UpdateUserDto
> {
  constructor(private userService: UserService) {
    super(userService);
  }
  
  async create(
    req: Request<{}, {}, CreateUserDto>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = await this.userService.create(req.body);
      this.created(res, user, 'User created successfully');
    } catch (error) {
      next(error);
    }
  }
  
  async findAll(
    req: Request<{}, {}, {}, { page?: string; limit?: string; search?: string }>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const page = req.query.page ? parseInt(req.query.page) : 1;
      const limit = req.query.limit ? parseInt(req.query.limit) : 20;
      const search = req.query.search;
      
      const result = await this.userService.findAll({
        page,
        limit,
        search
      });
      
      this.success(res, result);
    } catch (error) {
      next(error);
    }
  }
  
  async findOne(
    req: Request<{ id: string }>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = await this.userService.findById(req.params.id);
      
      if (!user) {
        return this.error(res, 'User not found', 404);
      }
      
      this.success(res, user);
    } catch (error) {
      next(error);
    }
  }
  
  async update(
    req: Request<{ id: string }, {}, UpdateUserDto>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = await this.userService.update(req.params.id, req.body);
      this.success(res, user, 'User updated successfully');
    } catch (error) {
      next(error);
    }
  }
  
  async delete(
    req: Request<{ id: string }>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      await this.userService.delete(req.params.id);
      this.success(res, null, 'User deleted successfully');
    } catch (error) {
      next(error);
    }
  }
  
  // Additional custom methods
  async getProfile(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const userId = (req as any).user.id;
      const profile = await this.userService.getProfile(userId);
      this.success(res, profile);
    } catch (error) {
      next(error);
    }
  }
  
  async updateProfile(
    req: Request<{}, {}, UpdateUserDto>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const userId = (req as any).user.id;
      const updated = await this.userService.update(userId, req.body);
      this.success(res, updated, 'Profile updated successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export factory function
export const createUserController = (): UserController => {
  const userService = new UserService();
  return new UserController(userService);
};
```

### 🔄 Functional Route Handlers

```typescript
// handlers/user.handlers.ts
import { Request, Response, NextFunction } from 'express';
import { UserService } from '@/services/user.service';
import { 
  CreateUserDto, 
  UpdateUserDto,
  UserResponse
} from '@/types/dto/user.dto';
import { ApiResponse } from '@/types/generics';

// Handler factory type
type HandlerFactory<T = any> = (
  service: UserService
) => (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void>;

// Create user handler
export const createUserHandler: HandlerFactory = (service) => {
  return async (
    req: Request<{}, {}, CreateUserDto>,
    res: Response<ApiResponse<UserResponse>>,
    next: NextFunction
  ): Promise<void> => {
    try {
      const user = await service.create(req.body);
      
      const response: ApiResponse<UserResponse> = {
        success: true,
        data: user,
        message: 'User created successfully',
        timestamp: new Date()
      };
      
      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  };
};

// Get user handler with typed params
export const getUserHandler: HandlerFactory = (service) => {
  return async (
    req: Request<{ id: string }>,
    res: Response<ApiResponse<UserResponse>>,
    next: NextFunction
  ): Promise<void> => {
    try {
      const user = await service.findById(req.params.id);
      
      if (!user) {
        const response: ApiResponse = {
          success: false,
          error: 'User not found',
          timestamp: new Date()
        };
        
        return res.status(404).json(response);
      }
      
      const response: ApiResponse<UserResponse> = {
        success: true,
        data: user,
        timestamp: new Date()
      };
      
      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  };
};

// Paginated users handler
interface PaginationQuery {
  page?: string;
  limit?: string;
  sort?: string;
  search?: string;
}

export const getUsersHandler: HandlerFactory = (service) => {
  return async (
    req: Request<{}, {}, {}, PaginationQuery>,
    res: Response<ApiResponse<UserResponse[]>>,
    next: NextFunction
  ): Promise<void> => {
    try {
      const page = req.query.page ? parseInt(req.query.page) : 1;
      const limit = req.query.limit ? parseInt(req.query.limit) : 20;
      const sort = req.query.sort || 'createdAt';
      const search = req.query.search;
      
      const { users, total } = await service.getPaginated({
        page,
        limit,
        sort,
        search
      });
      
      const response: ApiResponse<UserResponse[]> = {
        success: true,
        data: users,
        meta: {
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
          }
        },
        timestamp: new Date()
      };
      
      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  };
};

// Handler composition
export const composeHandlers = (service: UserService) => ({
  createUser: createUserHandler(service),
  getUser: getUserHandler(service),
  getUsers: getUsersHandler(service),
  updateUser: updateUserHandler(service),
  deleteUser: deleteUserHandler(service)
});

// Usage
const userService = new UserService();
const userHandlers = composeHandlers(userService);

router.post('/users', userHandlers.createUser);
router.get('/users/:id', userHandlers.getUser);
router.get('/users', userHandlers.getUsers);
```

### 🏗️ Advanced Handler Patterns

```typescript
// handlers/advanced.handlers.ts
import { Request, Response, NextFunction } from 'express';

// Handler with dependency injection
type HandlerDependencies = Record<string, any>;

export const createHandler = <T extends HandlerDependencies>(
  dependencies: T,
  handler: (
    deps: T,
    req: Request,
    res: Response,
    next: NextFunction
  ) => Promise<void>
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await handler(dependencies, req, res, next);
    } catch (error) {
      next(error);
    }
  };
};

// Handler with before/after hooks
export const createHookedHandler = (
  handler: RouteHandler,
  beforeHooks: RouteHandler[] = [],
  afterHooks: RouteHandler[] = []
): RouteHandler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Run before hooks
      for (const hook of beforeHooks) {
        await hook(req, res, (err) => {
          if (err) throw err;
        });
      }
      
      // Run main handler
      await handler(req, res, next);
      
      // Run after hooks
      for (const hook of afterHooks) {
        await hook(req, res, (err) => {
          if (err) console.error('After hook error:', err);
        });
      }
    } catch (error) {
      next(error);
    }
  };
};

// Handler with timeout
export const withTimeout = (
  handler: RouteHandler,
  timeoutMs: number
): RouteHandler => {
  return (req: Request, res: Response, next: NextFunction) => {
    const timeout = setTimeout(() => {
      next(new Error(`Handler timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    
    const cleanup = () => clearTimeout(timeout);
    
    handler(req, res, (err) => {
      cleanup();
      next(err);
    });
    
    // Cleanup on response finish
    res.on('finish', cleanup);
  };
};

// Handler with retry logic
export const withRetry = (
  handler: RouteHandler,
  maxRetries: number = 3,
  delayMs: number = 100
): RouteHandler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    let lastError: Error;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        await handler(req, res, next);
        return; // Success
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on client errors
        if ((error as any).statusCode && (error as any).statusCode < 500) {
          break;
        }
        
        if (attempt < maxRetries - 1) {
          await new Promise(resolve => 
            setTimeout(resolve, delayMs * Math.pow(2, attempt))
          );
        }
      }
    }
    
    next(lastError);
  };
};

// Transaction handler
export const withTransaction = (
  handler: RouteHandler,
  getTransaction: (req: Request) => Promise<any>
): RouteHandler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const transaction = await getTransaction(req);
    
    // Attach transaction to request
    (req as any).transaction = transaction;
    
    const originalJson = res.json;
    const originalStatus = res.status;
    
    let committed = false;
    
    // Override json to commit transaction on success
    res.json = function(body) {
      if (!committed && res.statusCode < 400) {
        transaction.commit().catch(console.error);
        committed = true;
      }
      return originalJson.call(this, body);
    };
    
    // Override status to track status changes
    res.status = function(code) {
      if (code >= 400 && !committed) {
        transaction.rollback().catch(console.error);
        committed = true;
      }
      return originalStatus.call(this, code);
    };
    
    // Handle errors
    try {
      await handler(req, res, next);
      
      // If response already sent without json/status override
      if (!committed && res.headersSent && res.statusCode < 400) {
        await transaction.commit();
        committed = true;
      }
    } catch (error) {
      if (!committed) {
        await transaction.rollback();
        committed = true;
      }
      next(error);
    }
  };
};
```

## Typing Error Handlers

### 🚨 Error Type Definitions

```typescript
// types/errors.ts
export abstract class AppError extends Error {
  abstract statusCode: number;
  abstract isOperational: boolean;
  
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
  
  abstract serialize(): {
    message: string;
    details?: any;
    code?: string;
  };
}

// Validation Error
export class ValidationError extends AppError {
  statusCode = 400;
  isOperational = true;
  
  constructor(
    public errors: Record<string, string[]> | string[],
    message: string = 'Validation failed'
  ) {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      details: this.errors,
      code: 'VALIDATION_ERROR'
    };
  }
}

// Authentication Error
export class AuthenticationError extends AppError {
  statusCode = 401;
  isOperational = true;
  
  constructor(message: string = 'Authentication required') {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'AUTHENTICATION_ERROR'
    };
  }
}

// Authorization Error
export class AuthorizationError extends AppError {
  statusCode = 403;
  isOperational = true;
  
  constructor(message: string = 'Insufficient permissions') {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'AUTHORIZATION_ERROR'
    };
  }
}

// Not Found Error
export class NotFoundError extends AppError {
  statusCode = 404;
  isOperational = true;
  
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'NOT_FOUND_ERROR'
    };
  }
}

// Conflict Error
export class ConflictError extends AppError {
  statusCode = 409;
  isOperational = true;
  
  constructor(message: string = 'Resource conflict') {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'CONFLICT_ERROR'
    };
  }
}

// Rate Limit Error
export class RateLimitError extends AppError {
  statusCode = 429;
  isOperational = true;
  
  constructor(
    message: string = 'Too many requests',
    public retryAfter?: number
  ) {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      retryAfter: this.retryAfter,
      code: 'RATE_LIMIT_ERROR'
    };
  }
}

// Database Error
export class DatabaseError extends AppError {
  statusCode = 500;
  isOperational = true;
  
  constructor(
    message: string = 'Database error occurred',
    public originalError?: Error
  ) {
    super(message);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'DATABASE_ERROR',
      ...(process.env.NODE_ENV === 'development' && {
        originalError: this.originalError?.message
      })
    };
  }
}

// External Service Error
export class ExternalServiceError extends AppError {
  statusCode = 502;
  isOperational = true;
  
  constructor(
    service: string,
    public originalError?: Error
  ) {
    super(`${service} service unavailable`);
  }
  
  serialize() {
    return {
      message: this.message,
      code: 'EXTERNAL_SERVICE_ERROR',
      ...(process.env.NODE_ENV === 'development' && {
        originalError: this.originalError?.message
      })
    };
  }
}

// Type guard for AppError
export const isAppError = (error: unknown): error is AppError => {
  return error instanceof AppError;
};

// Type guard for specific error
export const isValidationError = (error: unknown): error is ValidationError => {
  return error instanceof ValidationError;
};
```

### 🏗️ Error Handler Middleware

```typescript
// middleware/error.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { 
  AppError, 
  isAppError, 
  ValidationError,
  DatabaseError 
} from '@/types/errors';
import logger from '@/utils/logger';

export interface ErrorResponse {
  success: boolean;
  error: {
    message: string;
    code?: string;
    details?: any;
    requestId?: string;
    timestamp: string;
  };
}

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Default error values
  let statusCode = 500;
  let message = 'Internal server error';
  let code: string | undefined;
  let details: any;
  let isOperational = false;
  
  // Handle AppError instances
  if (isAppError(error)) {
    statusCode = error.statusCode;
    message = error.message;
    code = error.constructor.name.replace('Error', '').toUpperCase();
    details = error.serialize().details;
    isOperational = error.isOperational;
  }
  
  // Handle Zod validation errors
  if (error.name === 'ZodError') {
    statusCode = 400;
    message = 'Validation failed';
    code = 'VALIDATION_ERROR';
    details = (error as any).errors;
    isOperational = true;
  }
  
  // Handle JWT errors
  if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
    code = 'INVALID_TOKEN';
    isOperational = true;
  }
  
  if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
    code = 'TOKEN_EXPIRED';
    isOperational = true;
  }
  
  // Log error
  const logLevel = statusCode >= 500 ? 'error' : 'warn';
  
  logger[logLevel]({
    message: error.message,
    name: error.name,
    stack: error.stack,
    statusCode,
    method: req.method,
    url: req.url,
    ip: req.ip,
    user: (req as any).user?.id,
    requestId: (req as any).requestId,
    isOperational
  });
  
  // Send response
  const errorResponse: ErrorResponse = {
    success: false,
    error: {
      message,
      code,
      timestamp: new Date().toISOString(),
      requestId: (req as any).requestId
    }
  };
  
  // Add details in development or for operational errors
  if (details || process.env.NODE_ENV === 'development') {
    errorResponse.error.details = details;
  }
  
  // Add stack trace in development for non-operational errors
  if (!isOperational && process.env.NODE_ENV === 'development') {
    errorResponse.error.details = {
      ...errorResponse.error.details,
      stack: error.stack
    };
  }
  
  res.status(statusCode).json(errorResponse);
};

// Async error handler wrapper
export const catchAsync = <T extends Array<any>>(
  fn: (...args: T) => Promise<void>
) => {
  return (...args: T): void => {
    const next = args[args.length - 1] as NextFunction;
    
    fn(...args).catch(next);
  };
};

// Error handler factory
export const createErrorHandler = (
  options: {
    logErrors?: boolean;
    includeStack?: boolean;
    formatError?: (error: Error) => any;
  } = {}
) => {
  const {
    logErrors = true,
    includeStack = process.env.NODE_ENV === 'development',
    formatError
  } = options;
  
  return (
    error: Error,
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    if (logErrors) {
      logger.error({
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
      });
    }
    
    const formattedError = formatError 
      ? formatError(error) 
      : {
          message: error.message,
          ...(includeStack && { stack: error.stack })
        };
    
    res.status(500).json({
      success: false,
      error: formattedError
    });
  };
};
```

### 🔄 Advanced Error Handling Patterns

```typescript
// utils/error.utils.ts
import { AppError, isAppError } from '@/types/errors';

// Error boundary for async operations
export const withErrorBoundary = <T extends Array<any>, R>(
  fn: (...args: T) => Promise<R>,
  errorHandler?: (error: Error) => AppError
): ((...args: T) => Promise<R>) => {
  return async (...args: T): Promise<R> => {
    try {
      return await fn(...args);
    } catch (error) {
      if (errorHandler) {
        throw errorHandler(error as Error);
      }
      
      if (isAppError(error)) {
        throw error;
      }
      
      throw new AppError(
        error instanceof Error ? error.message : 'Unknown error occurred'
      );
    }
  };
};

// Retry with error classification
export const retryWithErrorHandling = async <T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    retryableErrors?: (error: Error) => boolean;
    onRetry?: (attempt: number, error: Error) => void;
  } = {}
): Promise<T> => {
  const {
    maxRetries = 3,
    retryableErrors = () => true,
    onRetry
  } = options;
  
  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      
      // Check if error is retryable
      if (!retryableErrors(lastError) || attempt === maxRetries) {
        break;
      }
      
      // Call onRetry callback
      onRetry?.(attempt, lastError);
      
      // Exponential backoff
      const delay = Math.pow(2, attempt) * 100;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw lastError!;
};

// Error aggregator for batch operations
export class ErrorAggregator extends Error {
  constructor(
    public errors: Error[],
    message: string = 'Multiple errors occurred'
  ) {
    super(message);
    this.name = 'ErrorAggregator';
  }
  
  static async aggregate<T>(
    operations: (() => Promise<T>)[],
    options: {
      stopOnFirstError?: boolean;
      maxErrors?: number;
    } = {}
  ): Promise<{ results: T[]; errors: Error[] }> {
    const { stopOnFirstError = false, maxErrors } = options;
    const results: T[] = [];
    const errors: Error[] = [];
    
    for (const operation of operations) {
      try {
        const result = await operation();
        results.push(result);
      } catch (error) {
        errors.push(error as Error);
        
        if (stopOnFirstError || (maxErrors && errors.length >= maxErrors)) {
          break;
        }
      }
    }
    
    return { results, errors };
  }
}

// Circuit breaker with error tracking
export class CircuitBreaker {
  private failures = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private nextAttempt = 0;
  
  constructor(
    private options: {
      failureThreshold: number;
      resetTimeout: number;
      halfOpenSuccessThreshold: number;
    }
  ) {}
  
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() >= this.nextAttempt) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await operation();
      
      if (this.state === 'HALF_OPEN') {
        this.failures = 0;
        this.state = 'CLOSED';
      }
      
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  private onFailure(): void {
    this.failures++;
    
    if (this.failures >= this.options.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.options.resetTimeout;
    }
  }
}
```

## Custom Interfaces for DB Models

### 🗄️ Database Model Interfaces

```typescript
// types/models/base.model.ts
export interface Timestamps {
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date;
}

export interface SoftDelete {
  isDeleted: boolean;
  deletedAt?: Date;
}

export interface Auditable {
  createdBy?: string;
  updatedBy?: string;
  deletedBy?: string;
}

// Base model interface
export interface BaseModel extends Timestamps, Auditable {
  id: string;
  version: number;
}

// Base entity with common fields
export interface BaseEntity extends BaseModel, SoftDelete {}

// Pagination model
export interface PaginatedModel<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}
```

### 🎯 User Model Interfaces

```typescript
// types/models/user.model.ts
import { BaseEntity } from './base.model';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
  MODERATOR = 'moderator',
  SUPER_ADMIN = 'super_admin'
}

export enum UserStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  BANNED = 'banned'
}

export interface UserPreferences {
  theme: 'light' | 'dark';
  language: string;
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  timezone: string;
}

export interface UserProfile {
  firstName?: string;
  lastName?: string;
  avatar?: string;
  bio?: string;
  phone?: string;
  address?: {
    street: string;
    city: string;
    state: string;
    country: string;
    zipCode: string;
  };
  socialLinks?: {
    twitter?: string;
    github?: string;
    linkedin?: string;
  };
}

// Main user interface
export interface User extends BaseEntity {
  email: string;
  username: string;
  passwordHash: string;
  salt: string;
  role: UserRole;
  status: UserStatus;
  emailVerified: boolean;
  lastLoginAt?: Date;
  loginAttempts: number;
  lockedUntil?: Date;
  
  // Optional relationships
  profile?: UserProfile;
  preferences?: UserPreferences;
  metadata?: Record<string, any>;
  
  // Virtual/computed properties
  fullName?: string;
  isActive?: boolean;
  isAdmin?: boolean;
}

// User creation input (without generated fields)
export interface UserCreateInput {
  email: string;
  username: string;
  password: string;
  role?: UserRole;
  status?: UserStatus;
  profile?: Partial<UserProfile>;
  preferences?: Partial<UserPreferences>;
}

// User update input
export interface UserUpdateInput {
  email?: string;
  username?: string;
  password?: string;
  role?: UserRole;
  status?: UserStatus;
  profile?: Partial<UserProfile>;
  preferences?: Partial<UserPreferences>;
  metadata?: Record<string, any>;
}

// User query options
export interface UserQueryOptions {
  where?: Partial<User>;
  include?: ('profile' | 'preferences')[];
  sort?: keyof User;
  order?: 'ASC' | 'DESC';
  page?: number;
  limit?: number;
  search?: string;
}

// User with relationships
export interface UserWithRelations extends User {
  profile?: UserProfile;
  preferences?: UserPreferences;
  posts?: Post[];
  comments?: Comment[];
}
```

### 🏗️ Advanced Model Patterns

```typescript
// types/models/advanced.models.ts

// Generic entity interface
export interface Entity<T extends string> {
  id: string;
  entityType: T;
  createdAt: Date;
  updatedAt: Date;
}

// Polymorphic relationships
export interface Commentable {
  commentableId: string;
  commentableType: 'post' | 'video' | 'product';
}

export interface Likeable {
  likeableId: string;
  likeableType: 'post' | 'comment' | 'video';
}

// Auditable with user tracking
export interface FullAuditable {
  createdBy: string;
  updatedBy: string;
  deletedBy?: string;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date;
}

// Versioned model
export interface VersionedModel {
  version: number;
  previousVersionId?: string;
  isLatest: boolean;
}

// Soft delete with archive
export interface Archivable {
  isArchived: boolean;
  archivedAt?: Date;
  archivedBy?: string;
}

// Status machine interface
export interface StatusMachine<T extends string> {
  status: T;
  previousStatus?: T;
  statusChangedAt: Date;
  statusChangedBy?: string;
  statusHistory: Array<{
    status: T;
    changedAt: Date;
    changedBy?: string;
    reason?: string;
  }>;
}

// Multi-tenant model
export interface TenantAware {
  tenantId: string;
  tenant?: Tenant;
}

// Localization model
export interface Localizable<T> {
  locale: string;
  defaultLocale: string;
  translations: Record<string, Partial<T>>;
}

// Tree structure model
export interface TreeModel {
  parentId?: string;
  path: string; // Materialized path
  depth: number;
  children?: TreeModel[];
  ancestors?: TreeModel[];
}

// Example: Product with all advanced features
export interface Product extends Entity<'product'>, FullAuditable, VersionedModel, Archivable {
  sku: string;
  name: string;
  description: string;
  price: number;
  currency: string;
  status: ProductStatus;
  categoryId: string;
  inventory: ProductInventory;
  
  // Polymorphic
  comments?: Comment[];
  likes?: Like[];
  
  // Tree structure
  parentId?: string;
  variants?: ProductVariant[];
  
  // Localization
  locale: string;
  translations: Record<string, {
    name?: string;
    description?: string;
  }>;
  
  // Metadata
  metadata: Record<string, any>;
  tags: string[];
}

// Generic repository interface
export interface Repository<T> {
  create(data: Partial<T>): Promise<T>;
  findById(id: string): Promise<T | null>;
  findOne(criteria: Partial<T>): Promise<T | null>;
  findMany(criteria?: Partial<T>): Promise<T[]>;
  update(id: string, data: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
  softDelete(id: string): Promise<T>;
  restore(id: string): Promise<T>;
  count(criteria?: Partial<T>): Promise<number>;
  exists(criteria: Partial<T>): Promise<boolean>;
}

// Generic service interface
export interface Service<T, CreateDto, UpdateDto> {
  create(dto: CreateDto): Promise<T>;
  findById(id: string): Promise<T>;
  findMany(options?: any): Promise<T[]>;
  update(id: string, dto: UpdateDto): Promise<T>;
  delete(id: string): Promise<void>;
}
```

### 🔄 Database-Specific Interfaces

```typescript
// types/models/mongodb.models.ts
import { Document, Types } from 'mongoose';

// MongoDB specific types
export type ObjectId = Types.ObjectId;
export type DocumentId = string | ObjectId;

// MongoDB document interface
export interface MongoDocument extends Document {
  _id: ObjectId;
  id: string;
  createdAt: Date;
  updatedAt: Date;
  __v: number;
}

// User model for MongoDB
export interface UserDocument extends MongoDocument {
  email: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  status: UserStatus;
  profile?: UserProfile;
  preferences?: UserPreferences;
  lastLoginAt?: Date;
  loginAttempts: number;
  lockedUntil?: Date;
  isDeleted: boolean;
  deletedAt?: Date;
}

// Reference types
export interface Ref<T> {
  _id: ObjectId;
  populate?: () => Promise<T>;
}

// Population types
export type Populated<T, K extends keyof T> = Omit<T, K> & {
  [P in K]: Exclude<T[P], Ref<any>>;
};

// Example usage
export interface PostDocument extends MongoDocument {
  title: string;
  content: string;
  author: Ref<UserDocument>;
  comments: Ref<CommentDocument>[];
  tags: string[];
}

export type PopulatedPost = Populated<PostDocument, 'author' | 'comments'>;
```

```typescript
// types/models/postgres.models.ts
import { PoolClient } from 'pg';

// PostgreSQL specific types
export interface PgConnection {
  client: PoolClient;
  release: () => void;
}

// Row types
export interface PgRow {
  [key: string]: any;
}

// Query result types
export interface PgQueryResult<T = PgRow> {
  rows: T[];
  rowCount: number;
  command: string;
  oid: number;
  fields: any[];
}

// Transaction context
export interface TransactionContext {
  client: PoolClient;
  commit: () => Promise<void>;
  rollback: () => Promise<void>;
}

// User model for PostgreSQL
export interface PgUser {
  id: string;
  email: string;
  username: string;
  password_hash: string;
  role: UserRole;
  status: UserStatus;
  profile: UserProfile | null;
  preferences: UserPreferences | null;
  last_login_at: Date | null;
  login_attempts: number;
  locked_until: Date | null;
  is_deleted: boolean;
  deleted_at: Date | null;
  created_at: Date;
  updated_at: Date;
  created_by: string | null;
  updated_by: string | null;
  deleted_by: string | null;
}

// JSONB column types
export interface JsonbColumn<T = any> {
  toJSON(): T;
  valueOf(): T;
}

// Array column types
export type PgArray<T> = T[];
```

## Enums for Constants

### 🎯 Basic Enum Patterns

```typescript
// types/enums/common.enums.ts

// String enums
export enum HttpStatus {
  OK = 200,
  CREATED = 201,
  ACCEPTED = 202,
  NO_CONTENT = 204,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409,
  INTERNAL_SERVER_ERROR = 500,
  SERVICE_UNAVAILABLE = 503
}

export enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  PATCH = 'PATCH',
  DELETE = 'DELETE',
  OPTIONS = 'OPTIONS',
  HEAD = 'HEAD'
}

// Numeric enums
export enum UserRole {
  SUPER_ADMIN = 1000,
  ADMIN = 100,
  MODERATOR = 50,
  USER = 10,
  GUEST = 1
}

// Heterogeneous enums (mixed values)
export enum ApiErrorCode {
  // Validation errors (1000-1999)
  VALIDATION_ERROR = 1000,
  REQUIRED_FIELD = 1001,
  INVALID_FORMAT = 1002,
  
  // Authentication errors (2000-2999)
  AUTHENTICATION_FAILED = 2000,
  INVALID_TOKEN = 2001,
  TOKEN_EXPIRED = 2002,
  
  // Authorization errors (3000-3999)
  INSUFFICIENT_PERMISSIONS = 3000,
  ACCESS_DENIED = 3001,
  
  // Resource errors (4000-4999)
  RESOURCE_NOT_FOUND = 4000,
  RESOURCE_CONFLICT = 4001,
  
  // System errors (5000-5999)
  INTERNAL_ERROR = 5000,
  DATABASE_ERROR = 5001,
  EXTERNAL_SERVICE_ERROR = 5002
}

// Const enums (removed during compilation)
export const enum CacheKey {
  USER = 'user',
  SESSION = 'session',
  CONFIG = 'config'
}

// Enum with computed values
export enum Environment {
  DEVELOPMENT = 'development',
  TESTING = 'testing',
  STAGING = 'staging',
  PRODUCTION = 'production'
}

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
  TRACE = 4
}
```

### 🏗️ Advanced Enum Patterns

```typescript
// types/enums/advanced.enums.ts

// Enum with metadata
export enum UserStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  BANNED = 'banned'
}

export namespace UserStatus {
  export const metadata: Record<UserStatus, {
    label: string;
    color: string;
    canLogin: boolean;
    transitions: UserStatus[];
  }> = {
    [UserStatus.PENDING]: {
      label: 'Pending',
      color: 'yellow',
      canLogin: false,
      transitions: [UserStatus.ACTIVE, UserStatus.BANNED]
    },
    [UserStatus.ACTIVE]: {
      label: 'Active',
      color: 'green',
      canLogin: true,
      transitions: [UserStatus.SUSPENDED, UserStatus.BANNED]
    },
    [UserStatus.SUSPENDED]: {
      label: 'Suspended',
      color: 'orange',
      canLogin: false,
      transitions: [UserStatus.ACTIVE, UserStatus.BANNED]
    },
    [UserStatus.BANNED]: {
      label: 'Banned',
      color: 'red',
      canLogin: false,
      transitions: []
    }
  };
  
  export function canTransition(from: UserStatus, to: UserStatus): boolean {
    return metadata[from].transitions.includes(to);
  }
  
  export function getLabel(status: UserStatus): string {
    return metadata[status].label;
  }
}

// Enum with type guards
export enum NotificationType {
  EMAIL = 'email',
  PUSH = 'push',
  SMS = 'sms',
  IN_APP = 'in_app'
}

export namespace NotificationType {
  export function isRealTime(type: NotificationType): boolean {
    return [NotificationType.PUSH, NotificationType.IN_APP].includes(type);
  }
  
  export function requiresTemplate(type: NotificationType): boolean {
    return type === NotificationType.EMAIL;
  }
}

// Enum union types
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export const HttpMethods = {
  GET: 'GET' as HttpMethod,
  POST: 'POST' as HttpMethod,
  PUT: 'PUT' as HttpMethod,
  PATCH: 'PATCH' as HttpMethod,
  DELETE: 'DELETE' as HttpMethod,
  OPTIONS: 'OPTIONS' as HttpMethod,
  HEAD: 'HEAD' as HttpMethod
} as const;

// String literal union with helper functions
export type SortOrder = 'asc' | 'desc';

export const SortOrder = {
  ASC: 'asc' as SortOrder,
  DESC: 'desc' as SortOrder,
  
  parse(value: string): SortOrder {
    const normalized = value.toLowerCase();
    return normalized === 'desc' ? this.DESC : this.ASC;
  },
  
  reverse(order: SortOrder): SortOrder {
    return order === this.ASC ? this.DESC : this.ASC;
  }
};

// Enum with validation
export enum Currency {
  USD = 'USD',
  EUR = 'EUR',
  GBP = 'GBP',
  JPY = 'JPY',
  CAD = 'CAD'
}

export namespace Currency {
  export function isValid(currency: string): currency is Currency {
    return Object.values(Currency).includes(currency as Currency);
  }
  
  export function getSymbol(currency: Currency): string {
    const symbols: Record<Currency, string> = {
      [Currency.USD]: '$',
      [Currency.EUR]: '€',
      [Currency.GBP]: '£',
      [Currency.JPY]: '¥',
      [Currency.CAD]: 'C$'
    };
    
    return symbols[currency];
  }
}
```

### 🔄 Enum Utilities and Patterns

```typescript
// utils/enum.utils.ts

// Enum iteration utilities
export class EnumUtils {
  // Get all values of an enum
  static getValues<T extends Record<string, string | number>>(enumObj: T): Array<T[keyof T]> {
    return Object.values(enumObj).filter(
      (value): value is T[keyof T] => typeof value === 'string' || typeof value === 'number'
    );
  }
  
  // Get all keys of an enum
  static getKeys<T extends Record<string, string | number>>(enumObj: T): Array<keyof T> {
    return Object.keys(enumObj).filter(
      key => isNaN(Number(key))
    ) as Array<keyof T>;
  }
  
  // Check if value exists in enum
  static hasValue<T extends Record<string, string | number>>(
    enumObj: T, 
    value: string | number
  ): boolean {
    return Object.values(enumObj).includes(value);
  }
  
  // Get key by value
  static getKeyByValue<T extends Record<string, string | number>>(
    enumObj: T,
    value: string | number
  ): keyof T | undefined {
    return Object.keys(enumObj).find(key => enumObj[key] === value) as keyof T;
  }
  
  // Create map from enum
  static toMap<T extends Record<string, string | number>, U>(
    enumObj: T,
    mapper: (key: keyof T, value: T[keyof T]) => U
  ): Map<keyof T, U> {
    const map = new Map<keyof T, U>();
    
    this.getKeys(enumObj).forEach(key => {
      map.set(key, mapper(key, enumObj[key]));
    });
    
    return map;
  }
}

// Usage examples
enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  GUEST = 'guest'
}

const roleValues = EnumUtils.getValues(UserRole); // ['admin', 'user', 'guest']
const roleKeys = EnumUtils.getKeys(UserRole); // ['ADMIN', 'USER', 'GUEST']
const hasAdmin = EnumUtils.hasValue(UserRole, 'admin'); // true
const key = EnumUtils.getKeyByValue(UserRole, 'user'); // 'USER'

// Enum serialization/deserialization
export class EnumSerializer {
  static serialize<T extends Record<string, string | number>>(enumObj: T, value: T[keyof T]): string {
    const key = EnumUtils.getKeyByValue(enumObj, value);
    if (!key) {
      throw new Error(`Invalid enum value: ${value}`);
    }
    return key;
  }
  
  static deserialize<T extends Record<string, string | number>>(
    enumObj: T, 
    key: string
  ): T[keyof T] {
    const value = enumObj[key as keyof T];
    if (value === undefined) {
      throw new Error(`Invalid enum key: ${key}`);
    }
    return value;
  }
}

// Runtime type checking for enums
export function createEnumGuard<T extends Record<string, string | number>>(enumObj: T) {
  const values = new Set(Object.values(enumObj));
  
  return (value: unknown): value is T[keyof T] => {
    return values.has(value as T[keyof T]);
  };
}

// Usage
const isUserRole = createEnumGuard(UserRole);
const isValid = isUserRole('admin'); // true
const isInvalid = isUserRole('invalid'); // false

// Enum with bitwise flags
export enum Permission {
  NONE = 0,
  READ = 1 << 0,    // 1
  WRITE = 1 << 1,   // 2
  DELETE = 1 << 2,  // 4
  ADMIN = 1 << 3,   // 8
  ALL = READ | WRITE | DELETE | ADMIN // 15
}

export namespace Permission {
  export function has(permissions: number, permission: Permission): boolean {
    return (permissions & permission) === permission;
  }
  
  export function add(permissions: number, permission: Permission): number {
    return permissions | permission;
  }
  
  export function remove(permissions: number, permission: Permission): number {
    return permissions & ~permission;
  }
  
  export function list(permissions: number): Permission[] {
    return [
      Permission.READ,
      Permission.WRITE,
      Permission.DELETE,
      Permission.ADMIN
    ].filter(permission => has(permissions, permission));
  }
}

// Usage
let userPermissions = Permission.NONE;
userPermissions = Permission.add(userPermissions, Permission.READ);
userPermissions = Permission.add(userPermissions, Permission.WRITE);

const canRead = Permission.has(userPermissions, Permission.READ); // true
const canDelete = Permission.has(userPermissions, Permission.DELETE); // false
```

## DTO Patterns (Data Transfer Objects)

### 📦 Basic DTO Patterns

```typescript
// types/dto/base.dto.ts

// Base DTO interface
export interface BaseDto {
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

// Generic response DTO
export interface ApiResponseDto<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  meta?: Record<string, any>;
  timestamp: Date;
}

// Paginated response DTO
export interface PaginatedResponseDto<T = any> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
  meta?: Record<string, any>;
}

// Error response DTO
export interface ErrorResponseDto {
  success: boolean;
  error: {
    message: string;
    code?: string;
    details?: any;
    timestamp: Date;
  };
}

// Validation error DTO
export interface ValidationErrorDto {
  field: string;
  message: string;
  code?: string;
  value?: any;
}
```

### 🎯 User DTO Examples

```typescript
// types/dto/user.dto.ts
import { UserRole, UserStatus } from '@/types/enums/user.enums';

// Request DTOs (Input)
export interface CreateUserDto {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
  role?: UserRole;
  firstName?: string;
  lastName?: string;
  phone?: string;
}

export interface UpdateUserDto {
  email?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  avatar?: string;
  bio?: string;
}

export interface ChangePasswordDto {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface LoginDto {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface ForgotPasswordDto {
  email: string;
}

export interface ResetPasswordDto {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

// Response DTOs (Output)
export interface UserResponseDto {
  id: string;
  email: string;
  username: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  avatar?: string;
  bio?: string;
  phone?: string;
  role: UserRole;
  status: UserStatus;
  emailVerified: boolean;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserProfileResponseDto extends UserResponseDto {
  preferences?: {
    theme: 'light' | 'dark';
    language: string;
    notifications: {
      email: boolean;
      push: boolean;
      sms: boolean;
    };
  };
  stats?: {
    postsCount: number;
    commentsCount: number;
    likesCount: number;
  };
}

export interface LoginResponseDto {
  user: UserResponseDto;
  token: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface AuthUserResponseDto {
  user: UserResponseDto;
  permissions: string[];
  roles: string[];
}

// Internal DTOs (Service layer)
export interface UserCreateData {
  email: string;
  username: string;
  passwordHash: string;
  salt: string;
  role: UserRole;
  status: UserStatus;
  profile?: {
    firstName?: string;
    lastName?: string;
    phone?: string;
  };
}

export interface UserUpdateData {
  email?: string;
  username?: string;
  profile?: {
    firstName?: string;
    lastName?: string;
    phone?: string;
    avatar?: string;
    bio?: string;
  };
  status?: UserStatus;
  role?: UserRole;
}

// Query DTOs
export interface UserQueryDto {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  search?: string;
  role?: UserRole;
  status?: UserStatus;
  emailVerified?: boolean;
}

// DTO transformers
export class UserDtoTransformer {
  static toResponse(user: any): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.profile?.firstName,
      lastName: user.profile?.lastName,
      fullName: user.profile ? 
        `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() : 
        undefined,
      avatar: user.profile?.avatar,
      bio: user.profile?.bio,
      phone: user.profile?.phone,
      role: user.role,
      status: user.status,
      emailVerified: user.emailVerified,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  static toCreateData(dto: CreateUserDto, passwordHash: string, salt: string): UserCreateData {
    return {
      email: dto.email.toLowerCase().trim(),
      username: dto.username.trim(),
      passwordHash,
      salt,
      role: dto.role || UserRole.USER,
      status: UserStatus.PENDING,
      profile: {
        firstName: dto.firstName?.trim(),
        lastName: dto.lastName?.trim(),
        phone: dto.phone?.trim()
      }
    };
  }
  
  static toUpdateData(dto: UpdateUserDto): UserUpdateData {
    return {
      email: dto.email?.toLowerCase().trim(),
      username: dto.username?.trim(),
      profile: {
        firstName: dto.firstName?.trim(),
        lastName: dto.lastName?.trim(),
        phone: dto.phone?.trim(),
        avatar: dto.avatar?.trim(),
        bio: dto.bio?.trim()
      }
    };
  }
}
```

### 🏗️ Advanced DTO Patterns

```typescript
// types/dto/advanced.dto.ts
import { Type } from 'class-transformer';
import { 
  IsString, 
  IsEmail, 
  IsOptional, 
  MinLength, 
  MaxLength,
  IsEnum,
  IsNumber,
  IsBoolean,
  IsArray,
  ValidateNested,
  Matches,
  IsDate,
  IsUUID
} from 'class-validator';

// Class-based DTO with validation decorators
export class CreateUserDto {
  @IsEmail()
  @MaxLength(255)
  email!: string;
  
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username can only contain letters, numbers and underscores'
  })
  username!: string;
  
  @IsString()
  @MinLength(8)
  @MaxLength(100)
  password!: string;
  
  @IsString()
  confirmPassword!: string;
  
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
  
  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;
  
  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;
}

// Nested DTOs
export class AddressDto {
  @IsString()
  @MaxLength(255)
  street!: string;
  
  @IsString()
  @MaxLength(100)
  city!: string;
  
  @IsString()
  @MaxLength(100)
  state!: string;
  
  @IsString()
  @MaxLength(100)
  country!: string;
  
  @IsString()
  @MaxLength(20)
  zipCode!: string;
}

export class CreateOrderDto {
  @IsUUID()
  userId!: string;
  
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OrderItemDto)
  items!: OrderItemDto[];
  
  @ValidateNested()
  @Type(() => AddressDto)
  shippingAddress!: AddressDto;
  
  @ValidateNested()
  @Type(() => AddressDto)
  billingAddress!: AddressDto;
}

export class OrderItemDto {
  @IsUUID()
  productId!: string;
  
  @IsNumber()
  @Min(1)
  quantity!: number;
  
  @IsNumber()
  @Min(0)
  price!: number;
}

// Partial DTO for updates
export class UpdateUserDto {
  @IsOptional()
  @IsEmail()
  @MaxLength(255)
  email?: string;
  
  @IsOptional()
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  username?: string;
  
  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;
  
  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;
}

// Query DTO with transformations
export class UserQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  page?: number = 1;
  
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 20;
  
  @IsOptional()
  @IsString()
  sort?: string = 'createdAt';
  
  @IsOptional()
  @IsEnum(['asc', 'desc'])
  order?: 'asc' | 'desc' = 'desc';
  
  @IsOptional()
  @IsString()
  @MaxLength(100)
  search?: string;
  
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
  
  @IsOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;
  
  @IsOptional()
  @IsBoolean()
  @Type(() => Boolean)
  emailVerified?: boolean;
}

// Generic DTO builder
export class DtoBuilder<T> {
  private dto: Partial<T> = {};
  
  set<K extends keyof T>(key: K, value: T[K]): this {
    this.dto[key] = value;
    return this;
  }
  
  build(): T {
    return this.dto as T;
  }
  
  static create<T>(): DtoBuilder<T> {
    return new DtoBuilder<T>();
  }
}

// Usage
const userDto = DtoBuilder.create<UserResponseDto>()
  .set('id', '123')
  .set('email', 'user@example.com')
  .set('username', 'johndoe')
  .build();

// DTO with transformation
export class TransformDto {
  @IsString()
  @Transform(({ value }) => value?.toLowerCase().trim())
  email!: string;
  
  @IsString()
  @Transform(({ value }) => value?.trim())
  username!: string;
  
  @IsOptional()
  @IsDate()
  @Type(() => Date)
  createdAt?: Date;
}

// Factory pattern for DTO creation
export class DtoFactory {
  static createUserResponse(user: any): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      // ... other fields
    };
  }
  
  static createPaginatedResponse<T>(
    data: T[],
    total: number,
    page: number,
    limit: number
  ): PaginatedResponseDto<T> {
    return {
      data,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    };
  }
}
```

### 🔄 DTO Validation and Transformation

```typescript
// utils/dto.utils.ts
import { plainToInstance, ClassConstructor } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';
import { ValidationErrorDto } from '@/types/dto/base.dto';

// Generic DTO validator
export async function validateDto<T extends object>(
  dtoClass: ClassConstructor<T>,
  plainObject: any,
  options: {
    skipMissingProperties?: boolean;
    whitelist?: boolean;
    forbidNonWhitelisted?: boolean;
  } = {}
): Promise<{ valid: boolean; errors: ValidationErrorDto[]; dto?: T }> {
  const {
    skipMissingProperties = false,
    whitelist = true,
    forbidNonWhitelisted = true
  } = options;
  
  // Transform plain object to class instance
  const dtoInstance = plainToInstance(dtoClass, plainObject, {
    excludeExtraneousValues: true,
    enableImplicitConversion: true
  });
  
  // Validate
  const errors = await validate(dtoInstance, {
    skipMissingProperties,
    whitelist,
    forbidNonWhitelisted
  });
  
  if (errors.length > 0) {
    const validationErrors: ValidationErrorDto[] = errors.flatMap(error => 
      mapValidationError(error)
    );
    
    return { valid: false, errors: validationErrors };
  }
  
  return { valid: true, errors: [], dto: dtoInstance };
}

// Map validation error to DTO
function mapValidationError(error: ValidationError): ValidationErrorDto[] {
  if (error.constraints) {
    return Object.entries(error.constraints).map(([code, message]) => ({
      field: error.property,
      message,
      code,
      value: error.value
    }));
  }
  
  if (error.children && error.children.length > 0) {
    return error.children.flatMap(child => 
      mapValidationError(child).map(childError => ({
        ...childError,
        field: `${error.property}.${childError.field}`
      }))
    );
  }
  
  return [];
}

// DTO transformer with validation
export class DtoTransformer {
  static async transformAndValidate<T extends object>(
    dtoClass: ClassConstructor<T>,
    data: any,
    options?: any
  ): Promise<T> {
    const result = await validateDto(dtoClass, data, options);
    
    if (!result.valid || !result.dto) {
      throw new Error('Validation failed');
    }
    
    return result.dto;
  }
  
  // Transform multiple objects
  static async transformMany<T extends object>(
    dtoClass: ClassConstructor<T>,
    dataArray: any[],
    options?: any
  ): Promise<T[]> {
    const results = await Promise.all(
      dataArray.map(data => this.transformAndValidate(dtoClass, data, options))
    );
    
    return results;
  }
  
  // Partial transformation for updates
  static async transformPartial<T extends object>(
    dtoClass: ClassConstructor<T>,
    data: any,
    options?: any
  ): Promise<Partial<T>> {
    const instance = plainToInstance(dtoClass, data, {
      excludeExtraneousValues: true,
      enableImplicitConversion: true
    });
    
    // Validate only provided properties
    const errors = await validate(instance, {
      skipMissingProperties: true,
      whitelist: true,
      forbidNonWhitelisted: true
    });
    
    if (errors.length > 0) {
      throw new Error('Validation failed');
    }
    
    return instance;
  }
}

// DTO middleware for Express
export function validateDtoMiddleware<T extends object>(
  dtoClass: ClassConstructor<T>,
  source: 'body' | 'query' | 'params' = 'body',
  options?: any
) {
  return async (req: any, res: any, next: any) => {
    try {
      const result = await validateDto(dtoClass, req[source], options);
      
      if (!result.valid) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: result.errors
        });
      }
      
      // Attach validated DTO to request
      req.validatedData = result.dto;
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Usage in routes
import { CreateUserDto } from '@/types/dto/user.dto';

router.post(
  '/users',
  validateDtoMiddleware(CreateUserDto, 'body'),
  userController.create
);
```

## Interview Questions

### 🚀 Setting up TypeScript Node Project

**Basic:**
1. What are the essential dependencies for a TypeScript + Express project?
2. How do you configure TypeScript to work with Node.js?
3. What's the difference between `tsc`, `ts-node`, and `ts-node-dev`?

**Advanced:**
4. Explain the project structure for a large TypeScript Express application.
5. How would you set up path aliases in TypeScript?
6. What are the benefits of using `module-alias` package?

**Senior Level:**
7. Design a build pipeline for TypeScript Express app with multiple environments.
8. How would you handle type definitions for third-party libraries without types?
9. Explain strategies for incremental TypeScript adoption in an existing JavaScript codebase.

### ⚙️ tsconfig Configuration

**Basic:**
1. What does `strict: true` enable in tsconfig?
2. Explain the purpose of `noImplicitAny` and `strictNullChecks`.
3. What are the differences between `CommonJS` and `ESNext` modules?

**Advanced:**
4. How does `skipLibCheck` affect compilation performance and safety?
5. Explain the `paths` configuration for module resolution.
6. What are declaration files (`.d.ts`) and when are they needed?

**Senior Level:**
7. Design tsconfig for a monorepo with shared types and multiple packages.
8. How would you configure TypeScript to catch common runtime errors at compile time?
9. Explain the trade-offs between different `target` and `lib` configurations.

### 📝 Typing Request, Response, NextFunction

**Basic:**
1. How do you add custom properties to Express Request object in TypeScript?
2. What's the difference between extending interfaces and using declaration merging?
3. How do you type middleware that modifies the Request object?

**Advanced:**
4. Explain how to create type-safe request handlers with typed parameters.
5. How would you implement response formatting with proper typing?
6. What are the challenges of typing dynamic middleware?

**Senior Level:**
7. Design a type-safe middleware pipeline with conditional execution.
8. How would you implement generic typed request handlers for CRUD operations?
9. Explain strategies for handling union types in request/response objects.

### 📦 Creating Types for Custom Payloads

**Basic:**
1. What are the different patterns for typing request payloads?
2. How do you handle optional vs required fields in payload types?
3. What's the difference between interfaces and type aliases for payloads?

**Advanced:**
4. Explain how to create discriminated unions for different request types.
5. How would you implement type guards for runtime payload validation?
6. What are the benefits of using template literal types for payload patterns?

**Senior Level:**
7. Design a type system for polymorphic payloads (e.g., different event types).
8. How would you implement automatic type inference from validation schemas?
9. Explain strategies for versioning payload types in evolving APIs.

### 🔧 Typing Middleware

**Basic:**
1. What are the different ways to type Express middleware?
2. How do you type async middleware properly?
3. What's the difference between `RequestHandler` and custom middleware types?

**Advanced:**
4. Explain how to create configurable middleware with type safety.
5. How would you type middleware that depends on request state?
6. What are the challenges of typing error-handling middleware?

**Senior Level:**
7. Design a type-safe middleware composition system.
8. How would you implement conditional middleware with type inference?
9. Explain strategies for typing middleware that modifies response objects.

### 🗺️ Typing Route Handlers

**Basic:**
1. How do you type route parameters and query strings?
2. What are the patterns for typing controller methods?
3. How do you handle async errors in typed route handlers?

**Advanced:**
4. Explain the Controller-Service pattern with TypeScript typing.
5. How would you implement dependency injection with type safety?
6. What are the benefits of using functional route handlers vs class-based?

**Senior Level:**
7. Design a type-safe routing system with middleware composition.
8. How would you implement automatic OpenAPI/Swagger generation from typed routes?
9. Explain strategies for handling polymorphic route handlers.

### 🚨 Typing Error Handlers

**Basic:**
1. How do you create custom error classes in TypeScript?
2. What's the difference between `Error` and custom error types?
3. How do you type error-handling middleware?

**Advanced:**
4. Explain how to create a type-safe error hierarchy.
5. How would you implement error serialization with type safety?
6. What are the patterns for typed error recovery?

**Senior Level:**
7. Design an error handling system with automatic error classification.
8. How would you implement circuit breaker pattern with typed errors?
9. Explain strategies for error aggregation in batch operations.

### 🗄️ Custom Interfaces for DB Models

**Basic:**
1. What are the common patterns for typing database models?
2. How do you handle optional vs required fields in database types?
3. What's the difference between input types and output types for models?

**Advanced:**
4. Explain how to type relationships and associations between models.
5. How would you implement soft delete patterns with typing?
6. What are the challenges of typing polymorphic relationships?

**Senior Level:**
7. Design a type system for multi-tenant database models.
8. How would you implement versioned models with type safety?
9. Explain strategies for handling database migrations with type changes.

### 🎯 Enums for Constants

**Basic:**
1. What are the different types of enums in TypeScript?
2. When should you use string enums vs numeric enums?
3. How do you iterate over enum values?

**Advanced:**
4. Explain how to add metadata to enums.
5. How would you implement type-safe enum parsing?
6. What are the benefits of const enums?

**Senior Level:**
7. Design an enum system with runtime validation and serialization.
8. How would you implement bitwise flags with type safety?
9. Explain strategies for internationalizing enum values.

### 📊 DTO Patterns

**Basic:**
1. What are DTOs and why are they useful in TypeScript?
2. How do you transform between entity types and DTOs?
3. What's the difference between request DTOs and response DTOs?

**Advanced:**
4. Explain how to use class-validator with DTOs.
5. How would you implement nested DTOs with validation?
6. What are the patterns for partial DTOs (for updates)?

**Senior Level:**
7. Design a DTO transformation system with automatic mapping.
8. How would you implement DTO versioning for API evolution?
9. Explain strategies for DTO validation in distributed systems.

## Real-World Scenarios

### 🎯 Scenario 1: Large Enterprise Application Migration
**Situation:** Migrating a large JavaScript Express application (100K+ lines) to TypeScript while maintaining zero downtime and supporting gradual migration.

**Tasks:**
1. Design migration strategy
2. Set up TypeScript configuration
3. Create type definitions for existing code
4. Implement gradual type adoption
5. Add build and deployment pipeline

**Solution Approach:**
```typescript
// 1. Gradual migration with allowJs
// tsconfig.json
{
  "compilerOptions": {
    "allowJs": true,
    "checkJs": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}

// 2. Type definition strategy
// types/legacy.d.ts - For untyped JavaScript modules
declare module 'legacy-module' {
  const value: any;
  export default value;
}

// 3. Migration phases
const migrationPhases = {
  phase1: {
    // Add TypeScript with allowJs
    // Enable basic strict checks
    // Add type definitions for core modules
  },
  phase2: {
    // Convert utility functions to TypeScript
    // Add interface definitions
    // Enable stricter type checking
  },
  phase3: {
    // Convert business logic
    // Add DTO patterns
    // Enable all strict checks
  },
  phase4: {
    // Complete migration
    // Remove allowJs
    // Add advanced TypeScript features
  }
};

// 4. Type safety gate in CI
// Add type checking to CI pipeline
// "type-check": "tsc --noEmit --skipLibCheck"

// 5. Runtime type validation for critical paths
import { validateDto } from '@/utils/dto.utils';

export const safeHandler = async (req: Request, res: Response) => {
  // Runtime validation for untyped paths
  const validation = await validateDto(UserDto, req.body);
  if (!validation.valid) {
    // Handle validation errors
  }
  
  // Proceed with typed data
  const user = await userService.create(validation.dto!);
  res.json(user);
};
```

### 🏗️ Scenario 2: High-Performance API with Complex Types
**Situation:** Building a financial trading API with complex business logic, real-time data, and strict type safety requirements.

**Tasks:**
1. Design type hierarchy for financial instruments
2. Implement type-safe validation rules
3. Add runtime type checking for external data
4. Create performance-optimized DTOs
5. Implement audit logging with typed events

**Solution Template:**
```typescript
// types/financial.types.ts
export enum InstrumentType {
  STOCK = 'stock',
  OPTION = 'option',
  FUTURE = 'future',
  BOND = 'bond'
}

export enum OrderType {
  MARKET = 'market',
  LIMIT = 'limit',
  STOP = 'stop',
  STOP_LIMIT = 'stop_limit'
}

export enum OrderSide {
  BUY = 'buy',
  SELL = 'sell'
}

// Discriminated union for different order types
export type Order = 
  | MarketOrder
  | LimitOrder
  | StopOrder
  | StopLimitOrder;

export interface BaseOrder {
  id: string;
  instrumentId: string;
  side: OrderSide;
  quantity: number;
  timestamp: Date;
}

export interface MarketOrder extends BaseOrder {
  type: OrderType.MARKET;
}

export interface LimitOrder extends BaseOrder {
  type: OrderType.LIMIT;
  limitPrice: number;
}

export interface StopOrder extends BaseOrder {
  type: OrderType.STOP;
  stopPrice: number;
}

export interface StopLimitOrder extends BaseOrder {
  type: OrderType.STOP_LIMIT;
  stopPrice: number;
  limitPrice: number;
}

// Type guards
export const isMarketOrder = (order: Order): order is MarketOrder => 
  order.type === OrderType.MARKET;

export const isLimitOrder = (order: Order): order is LimitOrder => 
  order.type === OrderType.LIMIT;

// Runtime validation with Zod
import { z } from 'zod';

const marketOrderSchema = z.object({
  type: z.literal(OrderType.MARKET),
  instrumentId: z.string().uuid(),
  side: z.nativeEnum(OrderSide),
  quantity: z.number().positive(),
  timestamp: z.date()
});

const limitOrderSchema = marketOrderSchema.extend({
  type: z.literal(OrderType.LIMIT),
  limitPrice: z.number().positive()
});

// Type inference from schema
export type MarketOrderDto = z.infer<typeof marketOrderSchema>;
export type LimitOrderDto = z.infer<typeof limitOrderSchema>;

// Performance-optimized DTO
export class CompactOrderDto {
  // Using numbers for enums to reduce payload size
  readonly t: number; // type
  readonly i: string; // instrumentId
  readonly s: number; // side
  readonly q: number; // quantity
  readonly p?: number; // price (optional)
  
  constructor(order: Order) {
    this.t = this.encodeOrderType(order.type);
    this.i = order.instrumentId;
    this.s = this.encodeOrderSide(order.side);
    this.q = order.quantity;
    
    if (isLimitOrder(order)) {
      this.p = order.limitPrice;
    }
  }
  
  private encodeOrderType(type: OrderType): number {
    const encoding: Record<OrderType, number> = {
      [OrderType.MARKET]: 1,
      [OrderType.LIMIT]: 2,
      [OrderType.STOP]: 3,
      [OrderType.STOP_LIMIT]: 4
    };
    return encoding[type];
  }
  
  private encodeOrderSide(side: OrderSide): number {
    return side === OrderSide.BUY ? 1 : 2;
  }
}
```

### 🔄 Scenario 3: Microservices Communication with Type Safety
**Situation:** Building a microservices architecture where services communicate via HTTP/REST and need to maintain type contracts between services.

**Tasks:**
1. Design shared type definitions
2. Implement type-safe HTTP clients
3. Add contract testing
4. Handle versioning of types
5. Implement schema registry

**Type-Safe HTTP Client:**
```typescript
// types/shared/contracts.ts
// Shared between services
export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}

export interface CreateUserRequest {
  email: string;
  name: string;
  password: string;
}

export interface CreateUserResponse {
  user: User;
  token: string;
}

// HTTP client with type safety
export class TypedHttpClient {
  constructor(
    private baseUrl: string,
    private options: {
      timeout?: number;
      retries?: number;
    } = {}
  ) {}
  
  async request<TRequest, TResponse>(
    endpoint: string,
    method: string,
    data?: TRequest
  ): Promise<TResponse> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': generateRequestId()
      },
      body: data ? JSON.stringify(data) : undefined,
      signal: AbortSignal.timeout(this.options.timeout || 5000)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const responseData = await response.json();
    
    // Runtime type validation
    return this.validateResponse<TResponse>(responseData);
  }
  
  private validateResponse<T>(data: any): T {
    // Implement runtime validation using Zod or similar
    // This ensures type safety at runtime
    return data as T;
  }
  
  // Typed methods
  async get<TResponse>(endpoint: string): Promise<TResponse> {
    return this.request<never, TResponse>(endpoint, 'GET');
  }
  
  async post<TRequest, TResponse>(
    endpoint: string,
    data: TRequest
  ): Promise<TResponse> {
    return this.request<TRequest, TResponse>(endpoint, 'POST', data);
  }
}

// Service client with contract
export class UserServiceClient {
  private client: TypedHttpClient;
  
  constructor(baseUrl: string) {
    this.client = new TypedHttpClient(baseUrl);
  }
  
  async createUser(
    request: CreateUserRequest
  ): Promise<CreateUserResponse> {
    return this.client.post<CreateUserRequest, CreateUserResponse>(
      '/users',
      request
    );
  }
  
  async getUser(id: string): Promise<User> {
    return this.client.get<User>(`/users/${id}`);
  }
}

// Contract testing
import { Pact } from '@pact-foundation/pact';

describe('User Service Contract', () => {
  const provider = new Pact({
    consumer: 'OrderService',
    provider: 'UserService',
    // ... other config
  });
  
  beforeAll(() => provider.setup());
  
  it('should create user', async () => {
    await provider.addInteraction({
      state: 'no users exist',
      uponReceiving: 'a request to create a user',
      withRequest: {
        method: 'POST',
        path: '/users',
        body: {
          email: 'test@example.com',
          name: 'Test User',
          password: 'password123'
        }
      },
      willRespondWith: {
        status: 201,
        body: {
          user: {
            id: Matchers.uuid(),
            email: 'test@example.com',
            name: 'Test User',
            role: 'user'
          },
          token: Matchers.string()
        }
      }
    });
    
    const client = new UserServiceClient(provider.mockService.baseUrl);
    const response = await client.createUser({
      email: 'test@example.com',
      name: 'Test User',
      password: 'password123'
    });
    
    expect(response.user.email).toBe('test@example.com');
  });
});
```

### 🛡️ Scenario 4: Security-First API with Runtime Type Validation
**Situation:** Building a banking API where runtime type safety is critical for security. Need to prevent type confusion attacks and ensure data integrity.

**Tasks:**
1. Implement runtime type validation for all inputs
2. Add schema validation at API boundaries
3. Create audit trails with typed events
4. Implement input sanitization with types
5. Add security headers with TypeScript

**Security-First Type System:**
```typescript
// utils/secureValidation.ts
import { z } from 'zod';
import { createHash } from 'crypto';

// Runtime type validation with security checks
export class SecureValidator {
  private static schemas = new Map<string, z.ZodSchema>();
  
  static registerSchema<T extends z.ZodSchema>(
    name: string,
    schema: T
  ): void {
    this.schemas.set(name, schema);
  }
  
  static async validateSecure<T>(
    schemaName: string,
    data: unknown,
    context: {
      ip?: string;
      user?: string;
      operation?: string;
    } = {}
  ): Promise<{ valid: boolean; data?: T; errors?: string[] }> {
    const schema = this.schemas.get(schemaName);
    
    if (!schema) {
      throw new Error(`Schema ${schemaName} not found`);
    }
    
    // Deep clone to prevent mutation
    const clonedData = JSON.parse(JSON.stringify(data));
    
    // Add security checks
    await this.runSecurityChecks(clonedData, context);
    
    // Validate schema
    const result = schema.safeParse(clonedData);
    
    if (!result.success) {
      // Log validation failures for security auditing
      await this.logValidationFailure(
        schemaName,
        clonedData,
        result.error,
        context
      );
      
      return {
        valid: false,
        errors: result.error.errors.map(e => e.message)
      };
    }
    
    // Additional security validation
    const securityResult = await this.validateSecurityConstraints(
      result.data,
      context
    );
    
    if (!securityResult.valid) {
      return {
        valid: false,
        errors: securityResult.errors
      };
    }
    
    return {
      valid: true,
      data: result.data as T
    };
  }
  
  private static async runSecurityChecks(
    data: any,
    context: any
  ): Promise<void> {
    // Check for prototype pollution
    this.checkForPrototypePollution(data);
    
    // Check for circular references
    this.checkForCircularReferences(data);
    
    // Sanitize strings
    this.sanitizeStrings(data);
  }
  
  private static checkForPrototypePollution(obj: any): void {
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    
    const checkObject = (obj: any, path: string = ''): void => {
      if (obj && typeof obj === 'object') {
        for (const key in obj) {
          if (dangerousKeys.includes(key)) {
            throw new Error(`Potential prototype pollution at ${path}.${key}`);
          }
          
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            checkObject(obj[key], `${path}.${key}`);
          }
        }
      }
    };
    
    checkObject(obj);
  }
  
  private static sanitizeStrings(data: any): void {
    const sanitize = (value: any): any => {
      if (typeof value === 'string') {
        // Remove control characters
        return value.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
      }
      
      if (Array.isArray(value)) {
        return value.map(sanitize);
      }
      
      if (value && typeof value === 'object') {
        const sanitized: any = {};
        for (const key in value) {
          sanitized[key] = sanitize(value[key]);
        }
        return sanitized;
      }
      
      return value;
    };
    
    return sanitize(data);
  }
}

// Typed security middleware
export const secureValidationMiddleware = <T>(
  schemaName: string
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const validation = await SecureValidator.validateSecure<T>(
        schemaName,
        req.body,
        {
          ip: req.ip,
          user: (req as any).user?.id,
          operation: `${req.method} ${req.path}`
        }
      );
      
      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: validation.errors
        });
      }
      
      // Attach validated and sanitized data
      (req as any).validatedData = validation.data;
      next();
    } catch (error) {
      // Security violation detected
      await securityLogger.logViolation({
        type: 'validation_security_violation',
        ip: req.ip,
        userAgent: req.get('user-agent'),
        payload: req.body,
        error: error.message
      });
      
      res.status(400).json({
        success: false,
        error: 'Security validation failed'
      });
    }
  };
};

// Usage
SecureValidator.registerSchema(
  'transfer',
  z.object({
    fromAccount: z.string().regex(/^ACC\d{10}$/),
    toAccount: z.string().regex(/^ACC\d{10}$/),
    amount: z.number().positive().max(1000000),
    currency: z.enum(['USD', 'EUR', 'GBP']),
    reference: z.string().max(100)
  })
);

app.post(
  '/transfer',
  secureValidationMiddleware<TransferRequest>('transfer'),
  transferController.execute
);
```

### 🔄 Scenario 5: Real-Time Collaboration with Type Safety
**Situation:** Building a collaborative document editor with real-time updates, conflict resolution, and offline support. Need strong typing for operational transformations and synchronization.

**Tasks:**
1. Design types for operational transformations
2. Implement type-safe conflict resolution
3. Add offline synchronization with typed operations
4. Create real-time communication protocols
5. Implement versioning with types

**Real-Time Type System:**
```typescript
// types/collaboration.types.ts
export enum OperationType {
  INSERT = 'insert',
  DELETE = 'delete',
  UPDATE = 'update',
  FORMAT = 'format'
}

export interface BaseOperation {
  id: string;
  type: OperationType;
  timestamp: number;
  author: string;
  version: number;
}

export interface InsertOperation extends BaseOperation {
  type: OperationType.INSERT;
  position: number;
  content: string;
}

export interface DeleteOperation extends BaseOperation {
  type: OperationType.DELETE;
  position: number;
  length: number;
}

export interface UpdateOperation extends BaseOperation {
  type: OperationType.UPDATE;
  path: string[];
  oldValue: any;
  newValue: any;
}

export interface FormatOperation extends BaseOperation {
  type: OperationType.FORMAT;
  range: [number, number];
  format: {
    bold?: boolean;
    italic?: boolean;
    color?: string;
    // ... other formats
  };
}

export type Operation = 
  | InsertOperation 
  | DeleteOperation 
  | UpdateOperation 
  | FormatOperation;

// Type guards
export const isInsertOperation = (op: Operation): op is InsertOperation => 
  op.type === OperationType.INSERT;

export const isDeleteOperation = (op: Operation): op is DeleteOperation => 
  op.type === OperationType.DELETE;

// Operational Transformation
export class OperationTransformer {
  static transform(
    operation: Operation,
    against: Operation[]
  ): Operation {
    return against.reduce((transformed, concurrentOp) => {
      return this.transformPair(transformed, concurrentOp);
    }, operation);
  }
  
  private static transformPair(
    op1: Operation,
    op2: Operation
  ): Operation {
    // Type-safe transformation logic
    if (isInsertOperation(op1) && isInsertOperation(op2)) {
      return this.transformInsertInsert(op1, op2);
    }
    
    if (isInsertOperation(op1) && isDeleteOperation(op2)) {
      return this.transformInsertDelete(op1, op2);
    }
    
    if (isDeleteOperation(op1) && isInsertOperation(op2)) {
      return this.transformDeleteInsert(op1, op2);
    }
    
    if (isDeleteOperation(op1) && isDeleteOperation(op2)) {
      return this.transformDeleteDelete(op1, op2);
    }
    
    // Default: return original
    return op1;
  }
  
  private static transformInsertInsert(
    op1: InsertOperation,
    op2: InsertOperation
  ): InsertOperation {
    if (op2.position < op1.position) {
      return {
        ...op1,
        position: op1.position + op2.content.length
      };
    }
    
    return op1;
  }
  
  // ... other transformation methods
}

// Real-time synchronization
export class CollaborationSession {
  private operations: Operation[] = [];
  private pendingOperations: Map<string, Operation> = new Map();
  
  applyOperation(operation: Operation): void {
    // Transform against concurrent operations
    const transformed = OperationTransformer.transform(
      operation,
      this.getConcurrentOperations(operation)
    );
    
    // Apply to document
    this.applyToDocument(transformed);
    
    // Store in history
    this.operations.push(transformed);
    
    // Broadcast to other clients
    this.broadcastOperation(transformed);
  }
  
  private getConcurrentOperations(operation: Operation): Operation[] {
    return this.operations.filter(op => 
      op.timestamp > operation.timestamp - 1000 && // Within last second
      op.author !== operation.author && // From different authors
      this.operationsConflict(op, operation)
    );
  }
  
  private operationsConflict(op1: Operation, op2: Operation): boolean {
    // Type-safe conflict detection
    if (isInsertOperation(op1) && isInsertOperation(op2)) {
      return Math.abs(op1.position - op2.position) < op1.content.length;
    }
    
    // ... other conflict checks
    return false;
  }
}

// WebSocket communication with types
export interface WebSocketMessage<T = any> {
  type: string;
  data: T;
  timestamp: number;
  requestId?: string;
}

export interface OperationMessage extends WebSocketMessage<Operation> {
  type: 'operation';
  documentId: string;
}

export interface SyncRequestMessage extends WebSocketMessage {
  type: 'sync_request';
  documentId: string;
  lastKnownVersion: number;
}

export interface SyncResponseMessage extends WebSocketMessage<Operation[]> {
  type: 'sync_response';
  documentId: string;
  currentVersion: number;
}

export type CollaborationMessage = 
  | OperationMessage
  | SyncRequestMessage
  | SyncResponseMessage;

// Type-safe WebSocket handler
export class CollaborationWebSocketHandler {
  handleMessage(message: CollaborationMessage): void {
    switch (message.type) {
      case 'operation':
        this.handleOperation(message);
        break;
      case 'sync_request':
        this.handleSyncRequest(message);
        break;
      case 'sync_response':
        this.handleSyncResponse(message);
        break;
      default:
        // Exhaustiveness check
        const _exhaustiveCheck: never = message;
        throw new Error(`Unknown message type: ${(message as any).type}`);
    }
  }
  
  private handleOperation(message: OperationMessage): void {
    const session = this.getSession(message.documentId);
    session.applyOperation(message.data);
  }
  
  // ... other handlers
}
```

---

## 📚 Additional Resources

### Documentation
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)
- [Express TypeScript Guide](https://expressjs.com/en/guide/using-middleware.html)
- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)

### Tools & Libraries
- [Zod](https://github.com/colinhacks/zod) - TypeScript-first schema validation
- [class-validator](https://github.com/typestack/class-validator) - Decorator-based validation
- [class-transformer](https://github.com/typestack/class-transformer) - Object transformation
- [ts-node-dev](https://github.com/wclr/ts-node-dev) - Development server
- [tsup](https://github.com/egoist/tsup) - TypeScript bundler

### Testing
- [ts-jest](https://github.com/kulshekhar/ts-jest) - TypeScript Jest preset
- [supertest](https://github.com/visionmedia/supertest) - HTTP testing
- [typefest](https://github.com/sindresorhus/type-fest) - TypeScript utility types

### Best Practices
1. Always enable strict mode in tsconfig
2. Use interfaces for public APIs, type aliases for complex types
3. Prefer const assertions for literal values
4. Use discriminated unions for state management
5. Implement runtime validation for external data
6. Keep type definitions close to their usage
7. Use path aliases for cleaner imports
8. Regularly audit type definitions for accuracy

---

