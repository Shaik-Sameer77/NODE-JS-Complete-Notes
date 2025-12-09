# PostgreSQL with Prisma & Sequelize: Complete Guide

## Table of Contents
- [Introduction to PostgreSQL ORMs](#introduction-to-postgresql-orms)
- [Prisma](#prisma)
  - [Prisma Schema](#prisma-schema)
  - [Relations](#relations)
  - [Enums](#enums)
  - [Middlewares](#middlewares)
- [Sequelize](#sequelize)
  - [Models & Migrations](#models--migrations)
  - [Associations](#associations)
  - [Hooks](#hooks)
  - [Scopes](#scopes)
- [Joins](#joins)
  - [Prisma Joins](#prisma-joins)
  - [Sequelize Joins](#sequelize-joins)
  - [Raw SQL Joins](#raw-sql-joins)
- [Transactions](#transactions)
  - [Prisma Transactions](#prisma-transactions)
  - [Sequelize Transactions](#sequelize-transactions)
  - [Nested Transactions](#nested-transactions)
- [Raw SQL Queries](#raw-sql-queries)
  - [Prisma Raw Queries](#prisma-raw-queries)
  - [Sequelize Raw Queries](#sequelize-raw-queries)
  - [Query Building](#query-building)
- [Connection Pooling](#connection-pooling)
  - [Prisma Pooling](#prisma-pooling)
  - [Sequelize Pooling](#sequelize-pooling)
  - [Connection Management](#connection-management)
- [Performance Optimization](#performance-optimization)
  - [Query Optimization](#query-optimization)
  - [Indexing Strategies](#indexing-strategies)
  - [Connection Pool Tuning](#connection-pool-tuning)
- [Interview Questions](#interview-questions)
  - [Junior to Mid-Level](#junior-to-mid-level)
  - [Senior Level](#senior-level)
  - [Real-World Scenarios](#real-world-scenarios)

---

## Introduction to PostgreSQL ORMs

### Prisma vs Sequelize: Key Differences

**Prisma:**
- Type-safe database client
- Schema-first approach
- Auto-generated migrations
- Native TypeScript support
- Modern query API

**Sequelize:**
- Mature ORM with long history
- Model-first approach
- Manual migration control
- Supports both JS and TS
- Traditional ORM patterns

### When to Use Each

**Choose Prisma when:**
- You want type safety
- Working with modern TypeScript projects
- Need auto-generated migrations
- Prefer declarative schema

**Choose Sequelize when:**
- Need fine-grained control over migrations
- Working with legacy codebases
- Require extensive plugin ecosystem
- Need advanced query capabilities

---

## Prisma

### Prisma Schema

The Prisma Schema Language (PSL) is the foundation of Prisma. It defines your database schema, relations, and generates the Prisma Client.

```prisma
// schema.prisma
generator client {
  provider = "prisma-client-js"
  previewFeatures = ["metrics"] // Enable preview features
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
  directUrl = env("DIRECT_URL") // For connection pooling
  shadowDatabaseUrl = env("SHADOW_DATABASE_URL") // For migrations
}

// Base model with common fields
model BaseModel {
  id        String   @id @default(cuid())
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  @@map("base_models")
}

// User model with advanced features
model User {
  // ID fields
  id        String   @id @default(uuid())
  externalId String? @unique
  
  // Scalar fields
  email     String   @unique
  name      String?
  age       Int?
  balance   Decimal  @default(0) @db.Decimal(10, 2)
  metadata  Json?    // JSON field for flexible data
  settings  Json?    @default("{}")
  
  // Enums
  role      UserRole @default(USER)
  status    UserStatus @default(ACTIVE)
  
  // Relations
  profile   Profile?
  posts     Post[]
  comments  Comment[]
  likes     Like[]
  
  // Arrays (PostgreSQL specific)
  tags      String[] // Array of strings
  scores    Int[]    // Array of integers
  
  // Timestamps
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  deletedAt DateTime? @map("deleted_at")
  
  // Indexes
  @@index([email])
  @@index([createdAt])
  @@unique([email, status])
  
  // Composite unique constraint
  @@unique([externalId, role], name: "user_external_identity")
  
  // Full-text search index
  @@fulltext([name, email])
  
  // Map to custom table name
  @@map("users")
  
  // Add comment to table
  @@comment("Table storing user information")
}

// Profile model (1:1 relationship)
model Profile {
  id        String   @id @default(cuid())
  bio       String?
  avatar    String?
  userId    String   @unique
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@map("profiles")
}

// Post model (1:N relationship)
model Post {
  id          String   @id @default(cuid())
  title       String
  content     String?
  published   Boolean  @default(false)
  
  // Author relation
  authorId    String
  author      User     @relation(fields: [authorId], references: [id], onDelete: Cascade)
  
  // Categories (N:M relationship via join table)
  categories  Category[]
  
  // Comments (1:N)
  comments    Comment[]
  
  // Timestamps
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  
  // Indexes
  @@index([authorId])
  @@index([createdAt])
  @@fulltext([title, content])
  
  @@map("posts")
}

// Category model (N:M relationship)
model Category {
  id    String @id @default(cuid())
  name  String @unique
  slug  String @unique
  posts Post[]
  
  @@map("categories")
}

// Comment model with self-relation
model Comment {
  id        String   @id @default(cuid())
  content   String
  postId    String
  post      Post     @relation(fields: [postId], references: [id], onDelete: Cascade)
  authorId  String
  author    User     @relation(fields: [authorId], references: [id])
  
  // Self-referencing for nested comments
  parentId  String?
  parent    Comment? @relation("CommentToComment", fields: [parentId], references: [id])
  replies   Comment[] @relation("CommentToComment")
  
  createdAt DateTime @default(now())
  
  @@index([postId])
  @@index([parentId])
  
  @@map("comments")
}

// Like model for many-to-many with extra fields
model Like {
  id        String   @id @default(cuid())
  postId    String
  userId    String
  post      Post     @relation(fields: [postId], references: [id], onDelete: Cascade)
  user      User     @relation(fields: [userId], references: [id])
  createdAt DateTime @default(now())
  
  // Composite unique constraint
  @@unique([postId, userId])
  
  @@map("likes")
}
```

### Relations

Prisma supports all standard database relations:

#### 1:1 Relationships
```prisma
model User {
  id      String  @id @default(cuid())
  profile Profile?
}

model Profile {
  id     String @id @default(cuid())
  userId String @unique
  user   User   @relation(fields: [userId], references: [id])
}
```

#### 1:N Relationships
```prisma
model User {
  id    String @id @default(cuid())
  posts Post[]
}

model Post {
  id       String @id @default(cuid())
  authorId String
  author   User   @relation(fields: [authorId], references: [id])
}
```

#### N:M Relationships
```prisma
// Implicit many-to-many
model Post {
  id         String     @id @default(cuid())
  categories Category[]
}

model Category {
  id    String @id @default(cuid())
  posts Post[]
}

// Explicit many-to-many (with additional fields)
model Post {
  id         String       @id @default(cuid())
  categories PostCategory[]
}

model Category {
  id    String       @id @default(cuid())
  posts PostCategory[]
}

model PostCategory {
  id         String   @id @default(cuid())
  postId     String
  categoryId String
  assignedAt DateTime @default(now())
  assignedBy String?
  
  post     Post     @relation(fields: [postId], references: [id])
  category Category @relation(fields: [categoryId], references: [id])
  
  @@unique([postId, categoryId])
}
```

#### Self-Relations
```prisma
model Employee {
  id          String     @id @default(cuid())
  name        String
  managerId   String?
  manager     Employee?  @relation("EmployeeToManager", fields: [managerId], references: [id])
  subordinates Employee[] @relation("EmployeeToManager")
}
```

### Enums

```prisma
// Define enums at schema level
enum UserRole {
  USER
  ADMIN
  MODERATOR
  SUPER_ADMIN
}

enum OrderStatus {
  PENDING
  PROCESSING
  SHIPPED
  DELIVERED
  CANCELLED
  REFUNDED
}

enum Priority {
  LOW
  MEDIUM
  HIGH
  CRITICAL
}

// Use enums in models
model Order {
  id     String      @id @default(cuid())
  status OrderStatus @default(PENDING)
  priority Priority @default(MEDIUM)
}

model Notification {
  id     String                 @id @default(cuid())
  type   NotificationType
  status NotificationStatus @default(UNREAD)
}

enum NotificationType {
  EMAIL
  SMS
  PUSH
  IN_APP
}

enum NotificationStatus {
  SENT
  DELIVERED
  READ
  UNREAD
  FAILED
}
```

### Middlewares

Prisma Middleware (now called Client Extensions) allow you to intercept and modify queries.

```typescript
// prisma/middleware.ts
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// Soft delete middleware
prisma.$use(async (params, next) => {
  // Check incoming query type
  if (params.model === 'User') {
    if (params.action === 'delete') {
      // Change delete to update
      params.action = 'update'
      params.args['data'] = { deletedAt: new Date() }
    }
    
    if (params.action === 'deleteMany') {
      params.action = 'updateMany'
      if (params.args.data !== undefined) {
        params.args.data['deletedAt'] = new Date()
      } else {
        params.args['data'] = { deletedAt: new Date() }
      }
    }
    
    // Filter out deleted records
    if (params.action === 'findUnique' || params.action === 'findFirst') {
      params.action = 'findFirst'
      params.args.where['deletedAt'] = null
    }
    
    if (params.action === 'findMany') {
      if (params.args.where) {
        if (params.args.where.deletedAt === undefined) {
          params.args.where['deletedAt'] = null
        }
      } else {
        params.args['where'] = { deletedAt: null }
      }
    }
  }
  
  return next(params)
})

// Logging middleware
prisma.$use(async (params, next) => {
  const start = Date.now()
  const result = await next(params)
  const duration = Date.now() - start
  
  console.log({
    model: params.model,
    action: params.action,
    duration: `${duration}ms`,
    timestamp: new Date()
  })
  
  return result
})

// Validation middleware
prisma.$use(async (params, next) => {
  if (params.model === 'User' && params.action === 'create') {
    const userData = params.args.data
    
    // Validate email format
    if (userData.email && !isValidEmail(userData.email)) {
      throw new Error('Invalid email format')
    }
    
    // Validate age
    if (userData.age && (userData.age < 0 || userData.age > 150)) {
      throw new Error('Age must be between 0 and 150')
    }
  }
  
  return next(params)
})

// Audit logging middleware
prisma.$use(async (params, next) => {
  const result = await next(params)
  
  // Log sensitive operations
  const sensitiveActions = ['create', 'update', 'delete', 'updateMany', 'deleteMany']
  
  if (sensitiveActions.includes(params.action)) {
    await AuditLog.create({
      action: params.action,
      model: params.model,
      args: JSON.stringify(params.args),
      timestamp: new Date(),
      userId: getCurrentUserId() // Get from context
    })
  }
  
  return result
})

// Query timeout middleware
prisma.$use(async (params, next) => {
  const timeout = 10000 // 10 seconds
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Query timeout')), timeout)
  })
  
  return Promise.race([
    next(params),
    timeoutPromise
  ]) as Promise<any>
})

// Caching middleware
const cache = new Map()

prisma.$use(async (params, next) => {
  // Only cache read operations
  if (params.action !== 'findUnique' && params.action !== 'findFirst') {
    return next(params)
  }
  
  const cacheKey = JSON.stringify(params)
  
  if (cache.has(cacheKey)) {
    console.log('Cache hit')
    return cache.get(cacheKey)
  }
  
  const result = await next(params)
  cache.set(cacheKey, result)
  
  // Set cache expiry
  setTimeout(() => cache.delete(cacheKey), 60000) // 1 minute
  
  return result
})

// Data transformation middleware
prisma.$use(async (params, next) => {
  const result = await next(params)
  
  // Transform result before returning
  if (params.model === 'User' && result) {
    if (Array.isArray(result)) {
      return result.map(user => ({
        ...user,
        fullName: `${user.firstName} ${user.lastName}`,
        initials: `${user.firstName?.[0] || ''}${user.lastName?.[0] || ''}`
      }))
    } else if (result) {
      return {
        ...result,
        fullName: `${result.firstName} ${result.lastName}`,
        initials: `${result.firstName?.[0] || ''}${result.lastName?.[0] || ''}`
      }
    }
  }
  
  return result
})
```

### Prisma Client Extensions

```typescript
// prisma/extensions.ts
import { Prisma } from '@prisma/client'

// Type-safe extensions
const prisma = new PrismaClient().$extends({
  name: 'userExtensions',
  
  // Model extensions
  model: {
    user: {
      async findByEmail(email: string) {
        return prisma.user.findUnique({
          where: { email }
        })
      },
      
      async findActive() {
        return prisma.user.findMany({
          where: { 
            status: 'ACTIVE',
            deletedAt: null
          }
        })
      },
      
      async updateBalance(userId: string, amount: number) {
        return prisma.$transaction(async (tx) => {
          const user = await tx.user.findUnique({
            where: { id: userId },
            select: { balance: true }
          })
          
          if (!user) throw new Error('User not found')
          
          const newBalance = user.balance.plus(amount)
          
          if (newBalance.lessThan(0)) {
            throw new Error('Insufficient funds')
          }
          
          return tx.user.update({
            where: { id: userId },
            data: { balance: newBalance }
          })
        })
      }
    }
  },
  
  // Query extensions
  query: {
    user: {
      async create({ args, query }) {
        // Hash password before creating user
        if (args.data.password) {
          args.data.password = await hashPassword(args.data.password)
        }
        
        // Set default values
        args.data = {
          ...args.data,
          emailVerified: false,
          status: 'PENDING_VERIFICATION'
        }
        
        return query(args)
      },
      
      async update({ args, query }) {
        // Prevent updating certain fields
        if (args.data.password) {
          args.data.password = await hashPassword(args.data.password)
        }
        
        // Remove fields that shouldn't be updated
        delete args.data.id
        delete args.data.createdAt
        
        return query(args)
      }
    }
  },
  
  // Result extensions
  result: {
    user: {
      fullName: {
        needs: { firstName: true, lastName: true },
        compute(user) {
          return `${user.firstName} ${user.lastName}`
        }
      },
      
      initials: {
        needs: { firstName: true, lastName: true },
        compute(user) {
          return `${user.firstName?.[0] || ''}${user.lastName?.[0] || ''}`
        }
      },
      
      isAdult: {
        needs: { age: true },
        compute(user) {
          return user.age ? user.age >= 18 : false
        }
      }
    }
  }
})

// Usage
const user = await prisma.user.findUnique({ where: { id: '1' } })
console.log(user.fullName) // Computed property
console.log(user.initials) // Computed property
console.log(user.isAdult)  // Computed property

// Use extended methods
const activeUsers = await prisma.user.findActive()
const userByEmail = await prisma.user.findByEmail('test@example.com')
await prisma.user.updateBalance('1', 100)
```

---

## Sequelize

### Models & Migrations

```javascript
// models/user.js
const { Model, DataTypes } = require('sequelize');

class User extends Model {
  static associate(models) {
    // Define associations here
    this.hasOne(models.Profile, { foreignKey: 'userId', as: 'profile' });
    this.hasMany(models.Post, { foreignKey: 'authorId', as: 'posts' });
    this.hasMany(models.Comment, { foreignKey: 'authorId', as: 'comments' });
    this.belongsToMany(models.Role, {
      through: 'UserRoles',
      foreignKey: 'userId',
      otherKey: 'roleId',
      as: 'roles'
    });
  }
  
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true,
          notEmpty: true
        }
      },
      username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          len: [3, 30],
          is: /^[a-zA-Z0-9_]+$/ // Alphanumeric and underscores
        }
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [8, 100]
        }
      },
      firstName: {
        type: DataTypes.STRING,
        allowNull: true,
        field: 'first_name' // Map to snake_case column
      },
      lastName: {
        type: DataTypes.STRING,
        allowNull: true,
        field: 'last_name'
      },
      age: {
        type: DataTypes.INTEGER,
        allowNull: true,
        validate: {
          min: 0,
          max: 150
        }
      },
      balance: {
        type: DataTypes.DECIMAL(10, 2),
        defaultValue: 0,
        validate: {
          min: 0
        }
      },
      metadata: {
        type: DataTypes.JSONB, // PostgreSQL JSONB type
        defaultValue: {}
      },
      tags: {
        type: DataTypes.ARRAY(DataTypes.STRING), // PostgreSQL array
        defaultValue: []
      },
      status: {
        type: DataTypes.ENUM('ACTIVE', 'INACTIVE', 'SUSPENDED', 'DELETED'),
        defaultValue: 'ACTIVE'
      },
      role: {
        type: DataTypes.ENUM('USER', 'ADMIN', 'MODERATOR'),
        defaultValue: 'USER'
      },
      lastLoginAt: {
        type: DataTypes.DATE,
        field: 'last_login_at'
      },
      emailVerifiedAt: {
        type: DataTypes.DATE,
        field: 'email_verified_at'
      },
      deletedAt: {
        type: DataTypes.DATE,
        field: 'deleted_at'
      }
    }, {
      sequelize,
      modelName: 'User',
      tableName: 'users',
      underscored: true, // Convert camelCase to snake_case
      paranoid: true, // Soft deletes
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
      defaultScope: {
        attributes: { exclude: ['password', 'deletedAt'] }
      },
      scopes: {
        withPassword: {
          attributes: { include: ['password'] }
        },
        active: {
          where: { status: 'ACTIVE' }
        },
        inactive: {
          where: { status: 'INACTIVE' }
        }
      },
      indexes: [
        {
          unique: true,
          fields: ['email']
        },
        {
          unique: true,
          fields: ['username']
        },
        {
          fields: ['status', 'created_at']
        },
        {
          fields: ['last_login_at']
        },
        {
          type: 'FULLTEXT',
          fields: ['first_name', 'last_name', 'email']
        }
      ],
      hooks: {
        beforeCreate: (user) => {
          if (user.password) {
            user.password = hashPassword(user.password);
          }
        },
        beforeUpdate: (user) => {
          if (user.changed('password')) {
            user.password = hashPassword(user.password);
          }
        }
      }
    });
  }
  
  // Instance methods
  getFullName() {
    return `${this.firstName} ${this.lastName}`;
  }
  
  async verifyPassword(password) {
    return comparePassword(password, this.password);
  }
  
  // Static methods
  static findByEmail(email) {
    return this.findOne({ where: { email } });
  }
  
  static findActive() {
    return this.scope('active').findAll();
  }
}

module.exports = User;
```

### Migrations

```javascript
// migrations/20240101000000-create-users.js
'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
      },
      username: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
      },
      password: {
        type: Sequelize.STRING,
        allowNull: false
      },
      first_name: {
        type: Sequelize.STRING,
        allowNull: true
      },
      last_name: {
        type: Sequelize.STRING,
        allowNull: true
      },
      age: {
        type: Sequelize.INTEGER,
        allowNull: true
      },
      balance: {
        type: Sequelize.DECIMAL(10, 2),
        defaultValue: 0
      },
      metadata: {
        type: Sequelize.JSONB,
        defaultValue: {}
      },
      tags: {
        type: Sequelize.ARRAY(Sequelize.STRING),
        defaultValue: []
      },
      status: {
        type: Sequelize.ENUM('ACTIVE', 'INACTIVE', 'SUSPENDED', 'DELETED'),
        defaultValue: 'ACTIVE'
      },
      role: {
        type: Sequelize.ENUM('USER', 'ADMIN', 'MODERATOR'),
        defaultValue: 'USER'
      },
      last_login_at: {
        type: Sequelize.DATE,
        allowNull: true
      },
      email_verified_at: {
        type: Sequelize.DATE,
        allowNull: true
      },
      deleted_at: {
        type: Sequelize.DATE,
        allowNull: true
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      }
    });

    // Create indexes
    await queryInterface.addIndex('users', ['email'], {
      name: 'users_email_idx',
      unique: true
    });

    await queryInterface.addIndex('users', ['username'], {
      name: 'users_username_idx',
      unique: true
    });

    await queryInterface.addIndex('users', ['status', 'created_at'], {
      name: 'users_status_created_at_idx'
    });

    await queryInterface.addIndex('users', ['last_login_at'], {
      name: 'users_last_login_at_idx'
    });

    // Add full-text search index
    await queryInterface.sequelize.query(`
      CREATE INDEX users_fulltext_idx ON users 
      USING GIN (to_tsvector('english', first_name || ' ' || last_name || ' ' || email))
    `);
  },

  down: async (queryInterface) => {
    await queryInterface.dropTable('users');
  }
};
```

### Associations

```javascript
// models/index.js - Setting up associations
const User = require('./user');
const Profile = require('./profile');
const Post = require('./post');
const Comment = require('./comment');
const Category = require('./category');
const PostCategory = require('./postcategory');

// 1:1 Association
User.hasOne(Profile, {
  foreignKey: 'userId',
  as: 'profile',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE'
});

Profile.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user'
});

// 1:N Association
User.hasMany(Post, {
  foreignKey: 'authorId',
  as: 'posts',
  onDelete: 'CASCADE'
});

Post.belongsTo(User, {
  foreignKey: 'authorId',
  as: 'author'
});

// N:M Association (with through table)
Post.belongsToMany(Category, {
  through: PostCategory,
  foreignKey: 'postId',
  otherKey: 'categoryId',
  as: 'categories',
  onDelete: 'CASCADE'
});

Category.belongsToMany(Post, {
  through: PostCategory,
  foreignKey: 'categoryId',
  otherKey: 'postId',
  as: 'posts',
  onDelete: 'CASCADE'
});

// Self-referencing association
Post.hasMany(Comment, {
  foreignKey: 'postId',
  as: 'comments',
  onDelete: 'CASCADE'
});

Comment.belongsTo(Post, {
  foreignKey: 'postId',
  as: 'post'
});

Comment.belongsTo(User, {
  foreignKey: 'authorId',
  as: 'author'
});

User.hasMany(Comment, {
  foreignKey: 'authorId',
  as: 'comments'
});

// Polymorphic associations (using type column)
const Image = sequelize.define('image', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  url: DataTypes.STRING,
  imageableId: DataTypes.UUID,
  imageableType: DataTypes.STRING // 'user' or 'post'
});

User.hasMany(Image, {
  foreignKey: 'imageableId',
  constraints: false,
  scope: {
    imageableType: 'user'
  }
});

Image.belongsTo(User, {
  foreignKey: 'imageableId',
  constraints: false,
  as: 'user'
});

Post.hasMany(Image, {
  foreignKey: 'imageableId',
  constraints: false,
  scope: {
    imageableType: 'post'
  }
});

Image.belongsTo(Post, {
  foreignKey: 'imageableId',
  constraints: false,
  as: 'post'
});
```

### Hooks (Lifecycle Events)

```javascript
// Model-level hooks
User.init({
  // ... fields
}, {
  hooks: {
    // Before hooks
    beforeValidate: (user, options) => {
      if (user.email) {
        user.email = user.email.toLowerCase();
      }
    },
    
    beforeCreate: async (user, options) => {
      // Hash password
      if (user.password) {
        user.password = await hashPassword(user.password);
      }
      
      // Generate verification token
      user.verificationToken = generateToken();
      user.verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    },
    
    beforeUpdate: async (user, options) => {
      // Track changes
      if (user.changed('email')) {
        user.emailVerified = false;
        user.emailVerifiedAt = null;
      }
      
      // Hash password if changed
      if (user.changed('password')) {
        user.password = await hashPassword(user.password);
        user.passwordChangedAt = new Date();
      }
      
      // Update search vector for full-text search
      if (user.changed('firstName') || user.changed('lastName') || user.changed('email')) {
        user.searchVector = sequelize.literal(`
          to_tsvector('english', 
            COALESCE(${sequelize.escape(user.firstName || '')}, '') || ' ' ||
            COALESCE(${sequelize.escape(user.lastName || '')}, '') || ' ' ||
            COALESCE(${sequelize.escape(user.email || '')}, '')
          )
        `);
      }
    },
    
    beforeDestroy: (user, options) => {
      // Backup before deletion
      return DeletedUser.create({
        userId: user.id,
        data: user.get({ plain: true }),
        deletedBy: options.deletedBy || 'system',
        deletedAt: new Date()
      });
    },
    
    // After hooks
    afterCreate: async (user, options) => {
      // Send welcome email
      await sendWelcomeEmail(user.email);
      
      // Create audit log
      await AuditLog.create({
        action: 'CREATE',
        model: 'User',
        recordId: user.id,
        changes: user.get({ plain: true }),
        userId: options.userId || null
      });
      
      // Create default profile
      await Profile.create({
        userId: user.id,
        bio: '',
        avatar: getDefaultAvatar()
      });
    },
    
    afterUpdate: async (user, options) => {
      // Create audit log
      const changes = user.previous();
      await AuditLog.create({
        action: 'UPDATE',
        model: 'User',
        recordId: user.id,
        changes: changes,
        userId: options.userId || null
      });
      
      // Send email verification if email changed
      if (user.changed('email')) {
        await sendVerificationEmail(user.email, user.verificationToken);
      }
    },
    
    afterDestroy: async (user, options) => {
      // Clean up related data
      await Profile.destroy({ where: { userId: user.id } });
      await Post.update(
        { authorId: null },
        { where: { authorId: user.id } }
      );
      
      // Create audit log
      await AuditLog.create({
        action: 'DELETE',
        model: 'User',
        recordId: user.id,
        userId: options.userId || null
      });
    },
    
    // Association hooks
    afterAssociationCreate: {
      posts: async (user, post, options) => {
        // Update user's post count
        await user.increment('postCount');
        
        // Send notification to followers
        const followers = await user.getFollowers();
        followers.forEach(follower => {
          sendNotification(follower.id, `${user.username} created a new post`);
        });
      }
    }
  }
});

// Instance-level hooks (can be added dynamically)
User.addHook('beforeSave', 'normalizeUsername', (user, options) => {
  if (user.username) {
    user.username = user.username.toLowerCase().replace(/[^a-z0-9_]/g, '');
  }
});

// Global hooks
sequelize.addHook('beforeDefine', (attributes, options) => {
  // Add timestamps to all models
  options.timestamps = true;
  options.underscored = true;
});

sequelize.addHook('afterConnect', (connection, config) => {
  console.log('Database connected');
  // Set session variables
  return connection.query("SET TIME ZONE 'UTC'");
});

sequelize.addHook('beforeDisconnect', (connection) => {
  console.log('Disconnecting from database');
});
```

### Scopes

```javascript
// Model scopes
User.init({
  // ... fields
}, {
  scopes: {
    // Default scope (applied automatically)
    defaultScope: {
      attributes: { exclude: ['password', 'deletedAt'] },
      where: { deletedAt: null }
    },
    
    // Named scopes
    withPassword: {
      attributes: { include: ['password'] }
    },
    
    active: {
      where: { status: 'ACTIVE' }
    },
    
    verified: {
      where: {
        emailVerifiedAt: { [Op.ne]: null }
      }
    },
    
    recentlyActive: {
      where: {
        lastLoginAt: {
          [Op.gte]: sequelize.literal("NOW() - INTERVAL '7 days'")
        }
      }
    },
    
    withPosts: {
      include: [{
        model: Post,
        as: 'posts',
        required: false
      }]
    },
    
    withProfile: {
      include: [{
        model: Profile,
        as: 'profile',
        required: false
      }]
    },
    
    // Dynamic scope
    byStatus(status) {
      return {
        where: { status }
      };
    },
    
    createdAfter(date) {
      return {
        where: {
          createdAt: { [Op.gte]: date }
        }
      };
    },
    
    // Complex scope with joins
    withPostCount: {
      attributes: {
        include: [
          [
            sequelize.literal(`(
              SELECT COUNT(*) FROM posts 
              WHERE posts.author_id = "User".id
            )`),
            'postCount'
          ]
        ]
      }
    },
    
    // Scope combining other scopes
    activeAndVerified: {
      where: {
        [Op.and]: [
          { status: 'ACTIVE' },
          { emailVerifiedAt: { [Op.ne]: null } }
        ]
      }
    }
  }
});

// Using scopes
// Apply single scope
const activeUsers = await User.scope('active').findAll();

// Apply multiple scopes
const verifiedUsersWithPosts = await User.scope(['verified', 'withPosts']).findAll();

// Apply dynamic scope
const pendingUsers = await User.scope({ method: ['byStatus', 'PENDING'] }).findAll();

// Remove default scope
const allUsersIncludingDeleted = await User.unscoped().findAll();

// Scope with parameters
const recentUsers = await User.scope({ method: ['createdAfter', '2024-01-01'] }).findAll();

// Chain scopes with other query options
const users = await User.scope('active')
  .findAll({
    where: { age: { [Op.gte]: 18 } },
    order: [['createdAt', 'DESC']],
    limit: 10
  });

// Association scopes
Post.init({
  // ... fields
}, {
  scopes: {
    published: {
      where: { published: true }
    },
    
    byAuthor(authorId) {
      return {
        where: { authorId }
      };
    },
    
    withComments: {
      include: [{
        model: Comment,
        as: 'comments',
        required: false
      }]
    }
  }
});

// Using association scopes
const userWithPublishedPosts = await User.scope('active').findOne({
  include: [{
    model: Post.scope('published'),
    as: 'posts'
  }]
});
```

---

## Joins

### Prisma Joins

```typescript
// Basic include (JOIN equivalent)
const userWithPosts = await prisma.user.findUnique({
  where: { id: '1' },
  include: {
    posts: true,
    profile: true,
    comments: true
  }
});

// Nested includes
const postWithDetails = await prisma.post.findUnique({
  where: { id: '1' },
  include: {
    author: {
      select: {
        id: true,
        name: true,
        email: true
      }
    },
    categories: true,
    comments: {
      include: {
        author: {
          select: {
            id: true,
            name: true
          }
        }
      },
      where: {
        createdAt: {
          gte: new Date('2024-01-01')
        }
      },
      orderBy: {
        createdAt: 'desc'
      },
      take: 10
    }
  }
});

// Multiple nested includes
const userWithEverything = await prisma.user.findUnique({
  where: { id: '1' },
  include: {
    profile: true,
    posts: {
      include: {
        categories: true,
        comments: {
          include: {
            author: true
          }
        }
      },
      where: {
        published: true
      }
    },
    comments: {
      include: {
        post: {
          select: {
            title: true,
            id: true
          }
        }
      }
    }
  }
});

// Conditional includes
const getUserWithRelations = async (userId: string, options: { includePosts?: boolean, includeComments?: boolean }) => {
  return prisma.user.findUnique({
    where: { id: userId },
    include: {
      posts: options.includePosts ? {
        where: { published: true },
        take: 10
      } : false,
      comments: options.includeComments ? {
        take: 5,
        orderBy: { createdAt: 'desc' }
      } : false,
      profile: true
    }
  });
};

// Using select with include
const userWithPostCount = await prisma.user.findUnique({
  where: { id: '1' },
  select: {
    id: true,
    name: true,
    email: true,
    _count: {
      select: {
        posts: true,
        comments: true,
        likes: true
      }
    }
  }
});

// Aggregation with joins
const userStats = await prisma.user.findUnique({
  where: { id: '1' },
  select: {
    id: true,
    name: true,
    posts: {
      select: {
        id: true,
        title: true,
        _count: {
          select: {
            comments: true,
            likes: true
          }
        }
      }
    },
    _count: {
      select: {
        posts: {
          where: { published: true }
        },
        comments: true
      }
    }
  }
});

// Many-to-many joins with extra fields
const postsWithCategories = await prisma.post.findMany({
  include: {
    categories: {
      include: {
        category: true
      }
    }
  }
});

// Self-referencing joins
const categoryTree = await prisma.category.findMany({
  where: { parentId: null },
  include: {
    children: {
      include: {
        children: {
          include: {
            children: true // 3 levels deep
          }
        }
      }
    }
  }
});

// Using raw SQL for complex joins
const complexJoin = await prisma.$queryRaw`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(DISTINCT p.id) as post_count,
    COUNT(DISTINCT c.id) as comment_count,
    AVG(p_likes.like_count) as avg_likes_per_post
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
  LEFT JOIN comments c ON u.id = c.author_id
  LEFT JOIN (
    SELECT post_id, COUNT(*) as like_count
    FROM likes
    GROUP BY post_id
  ) p_likes ON p.id = p_likes.post_id
  WHERE u.deleted_at IS NULL
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(DISTINCT p.id) > 0
  ORDER BY post_count DESC
  LIMIT 100
`;
```

### Sequelize Joins

```javascript
// Basic includes (JOINs)
const userWithPosts = await User.findByPk('1', {
  include: [{
    model: Post,
    as: 'posts'
  }, {
    model: Profile,
    as: 'profile'
  }]
});

// Nested includes
const postWithDetails = await Post.findByPk('1', {
  include: [{
    model: User,
    as: 'author',
    attributes: ['id', 'name', 'email']
  }, {
    model: Category,
    as: 'categories',
    through: { attributes: [] } // Exclude join table attributes
  }, {
    model: Comment,
    as: 'comments',
    include: [{
      model: User,
      as: 'author',
      attributes: ['id', 'name']
    }],
    where: {
      createdAt: {
        [Op.gte]: new Date('2024-01-01')
      }
    },
    order: [['createdAt', 'DESC']],
    limit: 10,
    separate: true // Run as separate query (better performance)
  }]
});

// Multiple nested includes
const userWithEverything = await User.findByPk('1', {
  include: [{
    model: Profile,
    as: 'profile'
  }, {
    model: Post,
    as: 'posts',
    include: [{
      model: Category,
      as: 'categories'
    }, {
      model: Comment,
      as: 'comments',
      include: [{
        model: User,
        as: 'author'
      }]
    }],
    where: {
      published: true
    }
  }, {
    model: Comment,
    as: 'comments',
    include: [{
      model: Post,
      as: 'post',
      attributes: ['id', 'title']
    }]
  }]
});

// Raw SQL joins
const rawJoinResults = await sequelize.query(`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(DISTINCT p.id) as post_count,
    COUNT(DISTINCT c.id) as comment_count,
    COALESCE(AVG(pl.like_count), 0) as avg_likes_per_post
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
  LEFT JOIN comments c ON u.id = c.author_id
  LEFT JOIN (
    SELECT post_id, COUNT(*) as like_count
    FROM likes
    GROUP BY post_id
  ) pl ON p.id = pl.post_id
  WHERE u.deleted_at IS NULL
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(DISTINCT p.id) > 0
  ORDER BY post_count DESC
  LIMIT 100
`, {
  type: QueryTypes.SELECT,
  model: User,
  mapToModel: true
});

// Complex joins with subqueries
const usersWithStats = await User.findAll({
  attributes: {
    include: [
      [
        sequelize.literal(`(
          SELECT COUNT(*) 
          FROM posts p 
          WHERE p.author_id = "User".id 
          AND p.published = true
        )`),
        'publishedPostCount'
      ],
      [
        sequelize.literal(`(
          SELECT COUNT(*) 
          FROM comments c 
          WHERE c.author_id = "User".id
          AND c.created_at >= NOW() - INTERVAL '30 days'
        )`),
        'recentComments'
      ]
    ]
  },
  include: [{
    model: Post,
    as: 'posts',
    attributes: [],
    required: false,
    where: { published: true }
  }],
  group: ['User.id'],
  having: sequelize.literal('COUNT(posts.id) > 0'),
  order: [[sequelize.literal('publishedPostCount'), 'DESC']]
});

// Join with through table attributes
const postsWithCategoryDetails = await Post.findAll({
  include: [{
    model: Category,
    as: 'categories',
    through: {
      attributes: ['assignedAt', 'assignedBy'] // Include join table attributes
    }
  }]
});

// Self-join (hierarchical data)
const categoryHierarchy = await Category.findAll({
  where: { parentId: null },
  include: [{
    model: Category,
    as: 'children',
    include: [{
      model: Category,
      as: 'children'
    }]
  }]
});

// Polymorphic associations
const imagesWithOwners = await Image.findAll({
  include: [{
    model: User,
    as: 'user',
    required: false
  }, {
    model: Post,
    as: 'post',
    required: false
  }],
  where: {
    [Op.or]: [
      { imageableType: 'user' },
      { imageableType: 'post' }
    ]
  }
});

// Join with custom ON clause
const customJoin = await User.findAll({
  include: [{
    model: Post,
    as: 'posts',
    on: {
      authorId: sequelize.where(
        sequelize.col('User.id'),
        '=',
        sequelize.col('posts.author_id')
      ),
      published: true
    },
    required: false
  }]
});

// Multiple associations with same model
const postWithAuthorAndLikers = await Post.findByPk('1', {
  include: [{
    model: User,
    as: 'author'
  }, {
    model: User,
    as: 'likers',
    through: {
      attributes: [] // Exclude Like table attributes
    }
  }]
});

// Using raw: true for performance
const usersRaw = await User.findAll({
  include: [{
    model: Post,
    as: 'posts',
    attributes: ['id', 'title'],
    required: false
  }],
  raw: true, // Returns plain objects (faster)
  nest: true  // Nests included models
});

// Subquery includes for performance
const usersWithPostCount = await User.findAll({
  attributes: {
    include: [
      [sequelize.literal('(SELECT COUNT(*) FROM posts WHERE posts.author_id = "User".id)'), 'postCount']
    ]
  },
  where: sequelize.where(
    sequelize.literal('(SELECT COUNT(*) FROM posts WHERE posts.author_id = "User".id)'),
    '>',
    0
  )
});
```

### Raw SQL Joins

```sql
-- INNER JOIN
SELECT 
  u.id,
  u.name,
  p.title,
  p.created_at
FROM users u
INNER JOIN posts p ON u.id = p.author_id
WHERE u.status = 'ACTIVE'
  AND p.published = true;

-- LEFT JOIN
SELECT 
  u.id,
  u.name,
  COUNT(p.id) as post_count,
  COUNT(c.id) as comment_count
FROM users u
LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
LEFT JOIN comments c ON u.id = c.author_id
GROUP BY u.id, u.name;

-- RIGHT JOIN
SELECT 
  p.title,
  c.content,
  u.name as commenter_name
FROM posts p
RIGHT JOIN comments c ON p.id = c.post_id
RIGHT JOIN users u ON c.author_id = u.id;

-- FULL OUTER JOIN
SELECT 
  u.name as user_name,
  p.title as post_title,
  c.content as comment_content
FROM users u
FULL OUTER JOIN posts p ON u.id = p.author_id
FULL OUTER JOIN comments c ON p.id = c.post_id;

-- CROSS JOIN (Cartesian product)
SELECT 
  u.name,
  p.title
FROM users u
CROSS JOIN posts p
WHERE u.id = '1';

-- SELF JOIN
SELECT 
  e1.name as employee_name,
  e2.name as manager_name
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;

-- NATURAL JOIN (joins on columns with same name)
SELECT *
FROM users
NATURAL JOIN profiles;

-- JOIN with USING clause (when column names match)
SELECT 
  u.name,
  p.title
FROM users u
JOIN posts p USING (id); -- Assuming both have 'id' column

-- LATERAL JOIN (correlated subquery in FROM clause)
SELECT 
  u.name,
  recent_posts.title
FROM users u,
LATERAL (
  SELECT title
  FROM posts p
  WHERE p.author_id = u.id
  ORDER BY p.created_at DESC
  LIMIT 3
) recent_posts;

-- Recursive CTE for hierarchical data
WITH RECURSIVE category_tree AS (
  -- Anchor member
  SELECT 
    id,
    name,
    parent_id,
    1 as level,
    ARRAY[id] as path
  FROM categories
  WHERE parent_id IS NULL
  
  UNION ALL
  
  -- Recursive member
  SELECT 
    c.id,
    c.name,
    c.parent_id,
    ct.level + 1,
    ct.path || c.id
  FROM categories c
  INNER JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT * FROM category_tree
ORDER BY path;

-- Window functions with joins
SELECT 
  u.name,
  p.title,
  p.created_at,
  COUNT(*) OVER (PARTITION BY u.id) as user_post_count,
  ROW_NUMBER() OVER (PARTITION BY u.id ORDER BY p.created_at DESC) as post_rank
FROM users u
JOIN posts p ON u.id = p.author_id
WHERE p.published = true;

-- JSON operations with joins
SELECT 
  u.name,
  u.metadata->>'preferences' as user_preferences,
  p.title,
  p.content->>'summary' as post_summary
FROM users u
JOIN posts p ON u.id = p.author_id
WHERE u.metadata @> '{"newsletter": true}'
  AND p.content ? 'summary';
```

---

## Transactions

### Prisma Transactions

```typescript
// Interactive transactions
const transferFunds = async (fromAccountId: string, toAccountId: string, amount: number) => {
  return prisma.$transaction(async (tx) => {
    // 1. Verify from account has sufficient funds
    const fromAccount = await tx.account.findUnique({
      where: { id: fromAccountId },
      select: { balance: true }
    });
    
    if (!fromAccount || fromAccount.balance < amount) {
      throw new Error('Insufficient funds');
    }
    
    // 2. Debit from account
    await tx.account.update({
      where: { id: fromAccountId },
      data: { 
        balance: { decrement: amount }
      }
    });
    
    // 3. Credit to account
    await tx.account.update({
      where: { id: toAccountId },
      data: { 
        balance: { increment: amount }
      }
    });
    
    // 4. Create transaction record
    const transaction = await tx.transaction.create({
      data: {
        fromAccountId,
        toAccountId,
        amount,
        type: 'TRANSFER',
        status: 'COMPLETED',
        reference: `TRX-${Date.now()}`
      }
    });
    
    // 5. Update account transaction history
    await tx.account.update({
      where: { id: fromAccountId },
      data: {
        transactions: {
          connect: { id: transaction.id }
        }
      }
    });
    
    await tx.account.update({
      where: { id: toAccountId },
      data: {
        transactions: {
          connect: { id: transaction.id }
        }
      }
    });
    
    return transaction;
  }, {
    maxWait: 5000,    // Maximum time to wait for transaction
    timeout: 10000,   // Maximum time for transaction to complete
    isolationLevel: Prisma.TransactionIsolationLevel.Serializable // Highest isolation
  });
};

// Batch transactions
const batchOperations = async () => {
  const [updatedUser, createdPost, deletedComment] = await prisma.$transaction([
    prisma.user.update({
      where: { id: '1' },
      data: { name: 'Updated Name' }
    }),
    prisma.post.create({
      data: {
        title: 'New Post',
        content: 'Content',
        authorId: '1'
      }
    }),
    prisma.comment.delete({
      where: { id: 'old-comment-id' }
    })
  ], {
    isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted
  });
  
  return { updatedUser, createdPost, deletedComment };
};

// Nested transactions (requires PostgreSQL 11+)
const nestedTransaction = async () => {
  return prisma.$transaction(async (tx1) => {
    // Outer transaction
    
    const user = await tx1.user.create({
      data: {
        email: 'user@example.com',
        name: 'Test User'
      }
    });
    
    // Nested transaction (savepoint)
    try {
      await tx1.$transaction(async (tx2) => {
        // Inner transaction
        await tx2.profile.create({
          data: {
            userId: user.id,
            bio: 'Test bio'
          }
        });
        
        // This will be rolled back if error occurs
        throw new Error('Intentional error in nested transaction');
      });
    } catch (error) {
      console.log('Nested transaction failed, but outer continues');
    }
    
    // This will still execute
    await tx1.post.create({
      data: {
        title: 'User Post',
        authorId: user.id
      }
    });
    
    return user;
  });
};

// Transaction with retry logic
const executeWithRetry = async <T>(
  operation: (tx: Prisma.TransactionClient) => Promise<T>,
  maxRetries = 3
): Promise<T> => {
  let lastError: Error;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await prisma.$transaction(operation, {
        maxWait: 5000,
        timeout: 30000,
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable
      });
    } catch (error) {
      lastError = error as Error;
      
      // Check if error is retryable
      if (isRetryableError(error) && attempt < maxRetries - 1) {
        // Exponential backoff
        const delay = Math.pow(2, attempt) * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      break;
    }
  }
  
  throw lastError;
};

// Complex e-commerce transaction
const createOrder = async (userId: string, cartItems: CartItem[], paymentInfo: PaymentInfo) => {
  return prisma.$transaction(async (tx) => {
    // 1. Validate and reserve inventory
    for (const item of cartItems) {
      const product = await tx.product.findUnique({
        where: { 
          id: item.productId,
          status: 'ACTIVE',
          stock: { gte: item.quantity }
        }
      });
      
      if (!product) {
        throw new Error(`Product ${item.productId} unavailable`);
      }
      
      // Reserve inventory
      await tx.product.update({
        where: { id: item.productId },
        data: {
          stock: { decrement: item.quantity },
          reserved: { increment: item.quantity }
        }
      });
    }
    
    // 2. Calculate totals
    const itemsWithDetails = await Promise.all(
      cartItems.map(async (item) => {
        const product = await tx.product.findUnique({
          where: { id: item.productId },
          select: { price: true, name: true }
        });
        
        return {
          ...item,
          unitPrice: product.price,
          name: product.name,
          subtotal: product.price * item.quantity
        };
      })
    );
    
    const subtotal = itemsWithDetails.reduce((sum, item) => sum + item.subtotal, 0);
    const tax = subtotal * 0.08; // 8% tax
    const shipping = 10; // Flat rate
    const total = subtotal + tax + shipping;
    
    // 3. Create order
    const order = await tx.order.create({
      data: {
        userId,
        subtotal,
        tax,
        shipping,
        total,
        status: 'PENDING',
        items: {
          create: itemsWithDetails.map(item => ({
            productId: item.productId,
            quantity: item.quantity,
            unitPrice: item.unitPrice,
            subtotal: item.subtotal
          }))
        }
      },
      include: {
        items: true
      }
    });
    
    // 4. Process payment
    const paymentResult = await processPayment(paymentInfo, total);
    
    if (!paymentResult.success) {
      throw new Error(`Payment failed: ${paymentResult.error}`);
    }
    
    await tx.payment.create({
      data: {
        orderId: order.id,
        amount: total,
        method: paymentInfo.method,
        transactionId: paymentResult.transactionId,
        status: 'COMPLETED'
      }
    });
    
    // 5. Update order status
    await tx.order.update({
      where: { id: order.id },
      data: {
        status: 'PROCESSING',
        paymentStatus: 'PAID'
      }
    });
    
    // 6. Clear cart
    await tx.cartItem.deleteMany({
      where: { userId }
    });
    
    // 7. Send notification (outside transaction for reliability)
    // This happens after transaction commits
    queue.notification.add({
      type: 'ORDER_CONFIRMATION',
      userId,
      orderId: order.id
    });
    
    return order;
  }, {
    isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    timeout: 30000 // 30 seconds for complex transaction
  });
};

// Optimistic concurrency control
const updateWithOptimisticLock = async (productId: string, update: any) => {
  return prisma.$transaction(async (tx) => {
    // 1. Read current version
    const product = await tx.product.findUnique({
      where: { id: productId },
      select: { version: true }
    });
    
    if (!product) {
      throw new Error('Product not found');
    }
    
    // 2. Attempt update with version check
    const updated = await tx.product.update({
      where: { 
        id: productId,
        version: product.version
      },
      data: {
        ...update,
        version: { increment: 1 }
      }
    });
    
    if (!updated) {
      throw new Error('Concurrent modification detected');
    }
    
    return updated;
  });
};
```

### Sequelize Transactions

```javascript
// Managed transaction (auto-commit/rollback)
const result = await sequelize.transaction(async (t) => {
  // Transaction object `t` will be used for all queries
  
  const user = await User.create({
    username: 'test',
    email: 'test@example.com'
  }, { transaction: t });
  
  await Profile.create({
    userId: user.id,
    bio: 'Test bio'
  }, { transaction: t });
  
  return user;
});

// Unmanaged transaction
const t = await sequelize.transaction();

try {
  const user = await User.create({
    username: 'test',
    email: 'test@example.com'
  }, { transaction: t });
  
  await Profile.create({
    userId: user.id,
    bio: 'Test bio'
  }, { transaction: t });
  
  // Commit transaction
  await t.commit();
  
  return user;
} catch (error) {
  // Rollback transaction on error
  await t.rollback();
  throw error;
}

// Transaction with isolation levels
const transaction = await sequelize.transaction({
  isolationLevel: Transaction.ISOLATION_LEVELS.SERIALIZABLE,
  type: Transaction.TYPES.DEFERRED, // DEFERRED, IMMEDIATE, EXCLUSIVE
  autocommit: false
});

// Nested transactions (savepoints)
const outerTransaction = await sequelize.transaction();

try {
  const user = await User.create({
    username: 'test',
    email: 'test@example.com'
  }, { transaction: outerTransaction });
  
  // Create savepoint
  const innerTransaction = await outerTransaction.savepoint('SP1');
  
  try {
    await Profile.create({
      userId: user.id,
      bio: 'Test bio'
    }, { transaction: innerTransaction });
    
    // Commit savepoint
    await outerTransaction.releaseSavepoint('SP1');
  } catch (error) {
    // Rollback to savepoint
    await outerTransaction.rollbackSavepoint('SP1');
    console.log('Inner transaction failed, continuing outer');
  }
  
  // This will still execute
  await Post.create({
    title: 'First Post',
    authorId: user.id
  }, { transaction: outerTransaction });
  
  await outerTransaction.commit();
  return user;
} catch (error) {
  await outerTransaction.rollback();
  throw error;
}

// Complex e-commerce transaction
const createOrder = async (userId, cartItems, paymentInfo) => {
  const transaction = await sequelize.transaction({
    isolationLevel: Transaction.ISOLATION_LEVELS.REPEATABLE_READ
  });
  
  try {
    // 1. Validate and reserve inventory
    for (const item of cartItems) {
      const product = await Product.findOne({
        where: {
          id: item.productId,
          status: 'ACTIVE',
          stock: { [Op.gte]: item.quantity }
        },
        transaction
      });
      
      if (!product) {
        throw new Error(`Product ${item.productId} unavailable`);
      }
      
      // Reserve inventory
      await Product.update({
        stock: sequelize.literal(`stock - ${item.quantity}`),
        reserved: sequelize.literal(`reserved + ${item.quantity}`)
      }, {
        where: { id: item.productId },
        transaction
      });
    }
    
    // 2. Calculate totals
    const itemsWithDetails = await Promise.all(
      cartItems.map(async (item) => {
        const product = await Product.findOne({
          where: { id: item.productId },
          attributes: ['price', 'name'],
          transaction
        });
        
        return {
          ...item,
          unitPrice: product.price,
          name: product.name,
          subtotal: product.price * item.quantity
        };
      })
    );
    
    const subtotal = itemsWithDetails.reduce((sum, item) => sum + item.subtotal, 0);
    const tax = subtotal * 0.08;
    const shipping = 10;
    const total = subtotal + tax + shipping;
    
    // 3. Create order
    const order = await Order.create({
      userId,
      subtotal,
      tax,
      shipping,
      total,
      status: 'PENDING'
    }, { transaction });
    
    // 4. Create order items
    await OrderItem.bulkCreate(
      itemsWithDetails.map(item => ({
        orderId: order.id,
        productId: item.productId,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        subtotal: item.subtotal
      })),
      { transaction }
    );
    
    // 5. Process payment
    const paymentResult = await processPayment(paymentInfo, total);
    
    if (!paymentResult.success) {
      throw new Error(`Payment failed: ${paymentResult.error}`);
    }
    
    await Payment.create({
      orderId: order.id,
      amount: total,
      method: paymentInfo.method,
      transactionId: paymentResult.transactionId,
      status: 'COMPLETED'
    }, { transaction });
    
    // 6. Update order status
    await Order.update({
      status: 'PROCESSING',
      paymentStatus: 'PAID'
    }, {
      where: { id: order.id },
      transaction
    });
    
    // 7. Clear cart
    await CartItem.destroy({
      where: { userId },
      transaction
    });
    
    // Commit transaction
    await transaction.commit();
    
    // 8. Send notification (outside transaction)
    await Notification.create({
      userId,
      type: 'ORDER_CONFIRMATION',
      data: { orderId: order.id }
    });
    
    return order;
  } catch (error) {
    // Rollback transaction on error
    await transaction.rollback();
    
    // Log failed transaction
    await FailedOrder.create({
      userId,
      items: cartItems,
      error: error.message,
      timestamp: new Date()
    });
    
    throw error;
  }
};

// Transaction with lock
const updateWithLock = async (productId, updateFn) => {
  const transaction = await sequelize.transaction({
    isolationLevel: Transaction.ISOLATION_LEVELS.SERIALIZABLE
  });
  
  try {
    // Lock row for update
    const product = await Product.findOne({
      where: { id: productId },
      lock: Transaction.LOCK.UPDATE,
      transaction
    });
    
    if (!product) {
      throw new Error('Product not found');
    }
    
    // Perform update
    const updatedProduct = await updateFn(product, transaction);
    
    await transaction.commit();
    return updatedProduct;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

// Bulk operations in transaction
const bulkUpdateWithTransaction = async (updates) => {
  const transaction = await sequelize.transaction();
  
  try {
    const results = await Promise.all(
      updates.map(async (update) => {
        return User.update(update.data, {
          where: update.where,
          transaction,
          returning: true
        });
      })
    );
    
    await transaction.commit();
    return results;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

// Transaction with retry logic
const executeWithRetry = async (operation, maxRetries = 3) => {
  let lastError;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      // Check for deadlock or serialization failure
      if (
        (error.name === 'SequelizeDatabaseError' && 
         (error.parent?.code === '40001' || error.parent?.code === '40P01')) ||
        error.message.includes('deadlock') ||
        error.message.includes('serialization')
      ) {
        if (attempt < maxRetries - 1) {
          // Exponential backoff
          const delay = Math.pow(2, attempt) * 100;
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
      break;
    }
  }
  
  throw lastError;
};
```

### Nested Transactions

```typescript
// Prisma nested transactions (using savepoints)
const processOrderWithFallback = async (orderId: string) => {
  return prisma.$transaction(async (outerTx) => {
    // Start outer transaction
    
    // Update order status
    await outerTx.order.update({
      where: { id: orderId },
      data: { status: 'PROCESSING' }
    });
    
    try {
      // Create savepoint for inventory update
      await outerTx.$executeRaw`SAVEPOINT inventory_update`;
      
      // Try to update inventory
      await outerTx.$transaction(async (innerTx) => {
        const order = await innerTx.order.findUnique({
          where: { id: orderId },
          include: { items: true }
        });
        
        for (const item of order.items) {
          await innerTx.product.update({
            where: { id: item.productId },
            data: {
              stock: { decrement: item.quantity }
            }
          });
        }
        
        // Simulate potential failure
        if (Math.random() < 0.3) {
          throw new Error('Random inventory failure');
        }
      });
      
      // Release savepoint if successful
      await outerTx.$executeRaw`RELEASE SAVEPOINT inventory_update`;
      
    } catch (error) {
      // Rollback to savepoint (undo inventory updates)
      await outerTx.$executeRaw`ROLLBACK TO SAVEPOINT inventory_update`;
      console.log('Inventory update failed, using alternative strategy');
      
      // Alternative: mark for manual review
      await outerTx.order.update({
        where: { id: orderId },
        data: { 
          status: 'REQUIRES_MANUAL_REVIEW',
          notes: 'Inventory update failed, needs manual processing'
        }
      });
    }
    
    // Continue with other operations
    await outerTx.order.update({
      where: { id: orderId },
      data: { 
        processedAt: new Date(),
        processedBy: 'system'
      }
    });
    
    return outerTx.order.findUnique({
      where: { id: orderId }
    });
  });
};

// Sequelize nested transactions with savepoints
const complexWorkflow = async () => {
  const transaction = await sequelize.transaction();
  
  try {
    // Main workflow
    const user = await User.create({
      username: 'testuser',
      email: 'test@example.com'
    }, { transaction });
    
    // Create savepoint for profile creation
    const savepoint1 = await transaction.savepoint('profile_creation');
    
    try {
      await Profile.create({
        userId: user.id,
        bio: 'Test bio'
      }, { transaction: savepoint1 });
      
      await transaction.releaseSavepoint('profile_creation');
    } catch (error) {
      // Rollback profile creation but continue
      await transaction.rollbackSavepoint('profile_creation');
      console.log('Profile creation failed, continuing');
    }
    
    // Create another savepoint for posts
    const savepoint2 = await transaction.savepoint('post_creation');
    
    try {
      await Post.create({
        title: 'First Post',
        authorId: user.id,
        content: 'Hello World'
      }, { transaction: savepoint2 });
      
      // Nested savepoint within savepoint
      const savepoint3 = await transaction.savepoint('comments_creation');
      
      try {
        await Comment.create({
          postId: post.id,
          authorId: user.id,
          content: 'First comment'
        }, { transaction: savepoint3 });
        
        await transaction.releaseSavepoint('comments_creation');
      } catch (error) {
        await transaction.rollbackSavepoint('comments_creation');
        console.log('Comment creation failed');
      }
      
      await transaction.releaseSavepoint('post_creation');
    } catch (error) {
      await transaction.rollbackSavepoint('post_creation');
      console.log('Post creation failed');
    }
    
    // Finalize transaction
    await transaction.commit();
    return user;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};
```

---

## Raw SQL Queries

### Prisma Raw Queries

```typescript
// Parameterized queries (safe from SQL injection)
const users = await prisma.$queryRaw`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(p.id) as post_count,
    COALESCE(SUM(p.likes), 0) as total_likes
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id
  WHERE u.status = 'ACTIVE'
    AND u.created_at >= ${startDate}
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(p.id) > 0
  ORDER BY post_count DESC
  LIMIT ${limit}
  OFFSET ${offset}
`;

// Raw queries with Prisma.sql for dynamic SQL
const searchUsers = async (searchTerm: string, filters: any) => {
  let whereClause = Prisma.sql`WHERE u.deleted_at IS NULL`;
  const params: any[] = [];
  
  if (searchTerm) {
    whereClause = Prisma.sql`${whereClause} AND (
      u.name ILIKE ${'%' + searchTerm + '%'} OR
      u.email ILIKE ${'%' + searchTerm + '%'}
    )`;
  }
  
  if (filters.status) {
    whereClause = Prisma.sql`${whereClause} AND u.status = ${filters.status}`;
  }
  
  if (filters.minAge) {
    whereClause = Prisma.sql`${whereClause} AND u.age >= ${filters.minAge}`;
  }
  
  return prisma.$queryRaw`
    SELECT 
      u.*,
      (
        SELECT COUNT(*) 
        FROM posts p 
        WHERE p.author_id = u.id
          AND p.published = true
      ) as published_post_count
    FROM users u
    ${whereClause}
    ORDER BY u.created_at DESC
    LIMIT ${filters.limit || 50}
    OFFSET ${filters.offset || 0}
  `;
};

// Execute raw SQL for DDL operations
await prisma.$executeRaw`
  CREATE INDEX IF NOT EXISTS users_email_lower_idx 
  ON users (LOWER(email))
`;

await prisma.$executeRaw`
  CREATE OR REPLACE FUNCTION update_updated_at_column()
  RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
  END;
  $$ language 'plpgsql';
`;

await prisma.$executeRaw`
  CREATE TRIGGER update_users_updated_at 
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
`;

// Call stored procedures
const result = await prisma.$queryRaw`
  SELECT * FROM calculate_user_stats(${userId}, ${startDate}, ${endDate})
`;

// Raw queries with returning clause
const insertedUser = await prisma.$queryRaw`
  INSERT INTO users (email, name, created_at, updated_at)
  VALUES (${email}, ${name}, NOW(), NOW())
  RETURNING id, email, name, created_at
`;

// Bulk operations with raw SQL
const batchUpdate = async (updates: Array<{id: string, status: string}>) => {
  return prisma.$transaction(async (tx) => {
    // Create temporary table
    await tx.$executeRaw`
      CREATE TEMP TABLE user_updates (
        id VARCHAR(255) PRIMARY KEY,
        status VARCHAR(50)
      ) ON COMMIT DROP
    `;
    
    // Insert updates into temp table
    for (const update of updates) {
      await tx.$executeRaw`
        INSERT INTO user_updates (id, status)
        VALUES (${update.id}, ${update.status})
      `;
    }
    
    // Perform update join
    await tx.$executeRaw`
      UPDATE users u
      SET status = uu.status,
          updated_at = NOW()
      FROM user_updates uu
      WHERE u.id = uu.id
    `;
    
    return tx.$queryRaw`
      SELECT u.id, u.email, u.status
      FROM users u
      JOIN user_updates uu ON u.id = uu.id
    `;
  });
};

// Window functions with raw queries
const rankedUsers = await prisma.$queryRaw`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(p.id) as post_count,
    RANK() OVER (ORDER BY COUNT(p.id) DESC) as rank,
    PERCENT_RANK() OVER (ORDER BY COUNT(p.id) DESC) as percentile,
    LAG(email) OVER (ORDER BY COUNT(p.id) DESC) as prev_user_email
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
  WHERE u.deleted_at IS NULL
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(p.id) > 0
  ORDER BY post_count DESC
`;

// Recursive CTE queries
const categoryHierarchy = await prisma.$queryRaw`
  WITH RECURSIVE category_tree AS (
    SELECT 
      id,
      name,
      parent_id,
      1 as level,
      ARRAY[id] as path,
      name as path_names
    FROM categories
    WHERE parent_id IS NULL
    
    UNION ALL
    
    SELECT 
      c.id,
      c.name,
      c.parent_id,
      ct.level + 1,
      ct.path || c.id,
      ct.path_names || ' > ' || c.name
    FROM categories c
    INNER JOIN category_tree ct ON c.parent_id = ct.id
  )
  SELECT * FROM category_tree
  ORDER BY path
`;

// JSON operations
const usersWithPreferences = await prisma.$queryRaw`
  SELECT 
    u.id,
    u.name,
    u.email,
    u.metadata->>'theme' as theme,
    u.metadata->'notifications'->'email' as email_notifications,
    jsonb_array_length(u.metadata->'tags') as tag_count
  FROM users u
  WHERE u.metadata @> '{"preferences": {"newsletter": true}}'
    AND u.metadata->'preferences'->>'language' = 'en'
  ORDER BY u.created_at DESC
`;

// Full-text search
const searchResults = await prisma.$queryRaw`
  SELECT 
    p.id,
    p.title,
    p.content,
    ts_rank_cd(
      setweight(to_tsvector('english', p.title), 'A') ||
      setweight(to_tsvector('english', p.content), 'B'),
      plainto_tsquery('english', ${searchQuery})
    ) as relevance
  FROM posts p
  WHERE 
    setweight(to_tsvector('english', p.title), 'A') ||
    setweight(to_tsvector('english', p.content), 'B') @@ plainto_tsquery('english', ${searchQuery})
  ORDER BY relevance DESC
  LIMIT 20
`;
```

### Sequelize Raw Queries

```javascript
// Basic raw query
const users = await sequelize.query(
  'SELECT * FROM users WHERE status = :status AND deleted_at IS NULL',
  {
    replacements: { status: 'ACTIVE' },
    type: QueryTypes.SELECT,
    model: User,
    mapToModel: true // Map results to model instances
  }
);

// Raw query with joins
const userStats = await sequelize.query(`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(DISTINCT p.id) as post_count,
    COUNT(DISTINCT c.id) as comment_count,
    COALESCE(SUM(p.likes), 0) as total_likes
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
  LEFT JOIN comments c ON u.id = c.author_id
  WHERE u.status = :status
    AND u.created_at >= :startDate
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(DISTINCT p.id) > 0
  ORDER BY post_count DESC
  LIMIT :limit
  OFFSET :offset
`, {
  replacements: {
    status: 'ACTIVE',
    startDate: '2024-01-01',
    limit: 50,
    offset: 0
  },
  type: QueryTypes.SELECT
});

// Execute DDL operations
await sequelize.query(`
  CREATE INDEX IF NOT EXISTS users_email_lower_idx 
  ON users (LOWER(email))
`);

await sequelize.query(`
  CREATE OR REPLACE FUNCTION update_updated_at_column()
  RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
  END;
  $$ language 'plpgsql'
`);

// Call stored procedures
const result = await sequelize.query(
  'SELECT * FROM calculate_user_stats(:userId, :startDate, :endDate)',
  {
    replacements: {
      userId: '123',
      startDate: '2024-01-01',
      endDate: '2024-12-31'
    },
    type: QueryTypes.SELECT
  }
);

// Raw insert with returning
const [insertedUser] = await sequelize.query(
  `INSERT INTO users (email, name, created_at, updated_at)
   VALUES (:email, :name, NOW(), NOW())
   RETURNING id, email, name, created_at`,
  {
    replacements: { email, name },
    type: QueryTypes.SELECT
  }
);

// Bulk operations with raw SQL
const batchUpdate = async (updates) => {
  const transaction = await sequelize.transaction();
  
  try {
    // Create temporary table
    await sequelize.query(`
      CREATE TEMP TABLE user_updates (
        id VARCHAR(255) PRIMARY KEY,
        status VARCHAR(50)
      ) ON COMMIT DROP
    `, { transaction });
    
    // Insert updates into temp table
    for (const update of updates) {
      await sequelize.query(
        'INSERT INTO user_updates (id, status) VALUES (:id, :status)',
        {
          replacements: update,
          transaction
        }
      );
    }
    
    // Perform update join
    await sequelize.query(`
      UPDATE users u
      SET status = uu.status,
          updated_at = NOW()
      FROM user_updates uu
      WHERE u.id = uu.id
    `, { transaction });
    
    const results = await sequelize.query(`
      SELECT u.id, u.email, u.status
      FROM users u
      JOIN user_updates uu ON u.id = uu.id
    `, {
      type: QueryTypes.SELECT,
      transaction
    });
    
    await transaction.commit();
    return results;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

// Window functions
const rankedUsers = await sequelize.query(`
  SELECT 
    u.id,
    u.name,
    u.email,
    COUNT(p.id) as post_count,
    RANK() OVER (ORDER BY COUNT(p.id) DESC) as rank,
    PERCENT_RANK() OVER (ORDER BY COUNT(p.id) DESC) as percentile,
    LAG(email) OVER (ORDER BY COUNT(p.id) DESC) as prev_user_email
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
  WHERE u.deleted_at IS NULL
  GROUP BY u.id, u.name, u.email
  HAVING COUNT(p.id) > 0
  ORDER BY post_count DESC
`, {
  type: QueryTypes.SELECT
});

// Recursive CTE
const categoryTree = await sequelize.query(`
  WITH RECURSIVE category_tree AS (
    SELECT 
      id,
      name,
      parent_id,
      1 as level,
      ARRAY[id] as path,
      name as path_names
    FROM categories
    WHERE parent_id IS NULL
    
    UNION ALL
    
    SELECT 
      c.id,
      c.name,
      c.parent_id,
      ct.level + 1,
      ct.path || c.id,
      ct.path_names || ' > ' || c.name
    FROM categories c
    INNER JOIN category_tree ct ON c.parent_id = ct.id
  )
  SELECT * FROM category_tree
  ORDER BY path
`, {
  type: QueryTypes.SELECT
});

// JSON operations
const usersWithPreferences = await sequelize.query(`
  SELECT 
    u.id,
    u.name,
    u.email,
    u.metadata->>'theme' as theme,
    u.metadata->'notifications'->'email' as email_notifications,
    jsonb_array_length(u.metadata->'tags') as tag_count
  FROM users u
  WHERE u.metadata @> '{"preferences": {"newsletter": true}}'
    AND u.metadata->'preferences'->>'language' = 'en'
  ORDER BY u.created_at DESC
`, {
  type: QueryTypes.SELECT
});

// Full-text search
const searchResults = await sequelize.query(`
  SELECT 
    p.id,
    p.title,
    p.content,
    ts_rank_cd(
      setweight(to_tsvector('english', p.title), 'A') ||
      setweight(to_tsvector('english', p.content), 'B'),
      plainto_tsquery('english', :searchQuery)
    ) as relevance
  FROM posts p
  WHERE 
    setweight(to_tsvector('english', p.title), 'A') ||
    setweight(to_tsvector('english', p.content), 'B') @@ plainto_tsquery('english', :searchQuery)
  ORDER BY relevance DESC
  LIMIT 20
`, {
  replacements: { searchQuery },
  type: QueryTypes.SELECT
});

// Dynamic query building
const buildSearchQuery = (filters) => {
  let query = 'SELECT * FROM users WHERE deleted_at IS NULL';
  const replacements = {};
  const conditions = [];
  
  if (filters.name) {
    conditions.push('name ILIKE :name');
    replacements.name = `%${filters.name}%`;
  }
  
  if (filters.email) {
    conditions.push('email ILIKE :email');
    replacements.email = `%${filters.email}%`;
  }
  
  if (filters.status) {
    conditions.push('status = :status');
    replacements.status = filters.status;
  }
  
  if (filters.minAge) {
    conditions.push('age >= :minAge');
    replacements.minAge = filters.minAge;
  }
  
  if (filters.maxAge) {
    conditions.push('age <= :maxAge');
    replacements.maxAge = filters.maxAge;
  }
  
  if (conditions.length > 0) {
    query += ' AND ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY created_at DESC';
  
  if (filters.limit) {
    query += ' LIMIT :limit';
    replacements.limit = filters.limit;
  }
  
  if (filters.offset) {
    query += ' OFFSET :offset';
    replacements.offset = filters.offset;
  }
  
  return { query, replacements };
};

// Usage
const { query, replacements } = buildSearchQuery({
  name: 'john',
  status: 'ACTIVE',
  minAge: 18,
  limit: 50,
  offset: 0
});

const results = await sequelize.query(query, {
  replacements,
  type: QueryTypes.SELECT
});
```

### Query Building

```javascript
// Knex-style query building (can be used with Sequelize or standalone)
class QueryBuilder {
  constructor(table) {
    this.table = table;
    this.query = {
      select: [],
      where: [],
      joins: [],
      orderBy: [],
      groupBy: [],
      having: [],
      limit: null,
      offset: null
    };
  }
  
  select(...columns) {
    this.query.select.push(...columns);
    return this;
  }
  
  where(column, operator, value) {
    this.query.where.push({ column, operator, value });
    return this;
  }
  
  whereIn(column, values) {
    this.query.where.push({ column, operator: 'IN', value: values });
    return this;
  }
  
  join(table, first, operator, second) {
    this.query.joins.push({
      table,
      type: 'INNER',
      condition: { first, operator, second }
    });
    return this;
  }
  
  leftJoin(table, first, operator, second) {
    this.query.joins.push({
      table,
      type: 'LEFT',
      condition: { first, operator, second }
    });
    return this;
  }
  
  orderBy(column, direction = 'ASC') {
    this.query.orderBy.push({ column, direction });
    return this;
  }
  
  groupBy(...columns) {
    this.query.groupBy.push(...columns);
    return this;
  }
  
  having(column, operator, value) {
    this.query.having.push({ column, operator, value });
    return this;
  }
  
  limit(count) {
    this.query.limit = count;
    return this;
  }
  
  offset(count) {
    this.query.offset = count;
    return this;
  }
  
  toSQL() {
    let sql = 'SELECT ';
    
    // SELECT clause
    if (this.query.select.length === 0) {
      sql += '*';
    } else {
      sql += this.query.select.join(', ');
    }
    
    sql += ` FROM ${this.table}`;
    
    // JOIN clauses
    this.query.joins.forEach(join => {
      sql += ` ${join.type} JOIN ${join.table} ON ${join.condition.first} ${join.condition.operator} ${join.condition.second}`;
    });
    
    // WHERE clause
    if (this.query.where.length > 0) {
      sql += ' WHERE ' + this.query.where.map(condition => {
        if (condition.operator === 'IN') {
          const values = Array.isArray(condition.value) 
            ? condition.value.map(v => `'${v}'`).join(', ')
            : condition.value;
          return `${condition.column} IN (${values})`;
        }
        return `${condition.column} ${condition.operator} '${condition.value}'`;
      }).join(' AND ');
    }
    
    // GROUP BY clause
    if (this.query.groupBy.length > 0) {
      sql += ' GROUP BY ' + this.query.groupBy.join(', ');
    }
    
    // HAVING clause
    if (this.query.having.length > 0) {
      sql += ' HAVING ' + this.query.having.map(condition => {
        return `${condition.column} ${condition.operator} '${condition.value}'`;
      }).join(' AND ');
    }
    
    // ORDER BY clause
    if (this.query.orderBy.length > 0) {
      sql += ' ORDER BY ' + this.query.orderBy.map(order => {
        return `${order.column} ${order.direction}`;
      }).join(', ');
    }
    
    // LIMIT and OFFSET
    if (this.query.limit !== null) {
      sql += ` LIMIT ${this.query.limit}`;
    }
    
    if (this.query.offset !== null) {
      sql += ` OFFSET ${this.query.offset}`;
    }
    
    return sql;
  }
  
  async execute(sequelize) {
    const sql = this.toSQL();
    return sequelize.query(sql, {
      type: QueryTypes.SELECT
    });
  }
}

// Usage
const query = new QueryBuilder('users')
  .select('id', 'name', 'email', 'created_at')
  .where('status', '=', 'ACTIVE')
  .where('deleted_at', 'IS', 'NULL')
  .leftJoin('profiles', 'users.id', '=', 'profiles.user_id')
  .orderBy('created_at', 'DESC')
  .limit(50)
  .offset(0);

const users = await query.execute(sequelize);
console.log(query.toSQL());
```

---

## Connection Pooling

### Prisma Pooling

```typescript
// Prisma connection configuration
const prisma = new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'info' },
    { emit: 'event', level: 'warn' },
    { emit: 'event', level: 'error' }
  ],
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
      // Connection pool settings in URL
      // directUrl: process.env.DIRECT_URL // For connection pooling
    }
  },
  // Error formatting
  errorFormat: 'pretty'
});

// Configure connection pool via DATABASE_URL
// postgresql://user:password@localhost:5432/dbname?connection_limit=20&pool_timeout=10

// Monitor connection pool
prisma.$on('query', (e) => {
  console.log({
    query: e.query,
    params: e.params,
    duration: e.duration,
    timestamp: e.timestamp
  });
});

prisma.$on('info', (e) => {
  console.log('Info:', e.message);
});

prisma.$on('warn', (e) => {
  console.warn('Warning:', e.message);
});

prisma.$on('error', (e) => {
  console.error('Error:', e.message);
});

// Connection health check
async function checkConnectionHealth() {
  try {
    // Simple query to check connection
    await prisma.$queryRaw`SELECT 1`;
    
    // Get connection pool stats
    const poolStats = await prisma.$queryRaw`
      SELECT 
        datname as database,
        numbackends as connections,
        xact_commit as transactions_committed,
        xact_rollback as transactions_rolled_back
      FROM pg_stat_database 
      WHERE datname = current_database()
    `;
    
    return {
      status: 'healthy',
      poolStats: poolStats[0],
      timestamp: new Date()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date()
    };
  }
}

// Connection retry logic
async function connectWithRetry(maxRetries = 5, initialDelay = 1000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await prisma.$connect();
      console.log('Connected to database');
      return;
    } catch (error) {
      console.error(`Connection attempt ${i + 1} failed:`, error.message);
      
      if (i === maxRetries - 1) {
        throw error;
      }
      
      // Exponential backoff
      const delay = initialDelay * Math.pow(2, i);
      console.log(`Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Graceful shutdown
async function gracefulShutdown() {
  console.log('Shutting down gracefully...');
  
  try {
    // Close Prisma connection
    await prisma.$disconnect();
    console.log('Database connections closed');
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Connection pool management for multiple databases
class DatabaseManager {
  private connections: Map<string, PrismaClient> = new Map();
  
  getConnection(databaseName: string): PrismaClient {
    if (!this.connections.has(databaseName)) {
      const connection = new PrismaClient({
        datasources: {
          db: {
            url: this.getDatabaseUrl(databaseName)
          }
        }
      });
      
      this.connections.set(databaseName, connection);
    }
    
    return this.connections.get(databaseName)!;
  }
  
  async closeAllConnections() {
    const closePromises = Array.from(this.connections.values()).map(
      connection => connection.$disconnect()
    );
    
    await Promise.all(closePromises);
    this.connections.clear();
  }
  
  private getDatabaseUrl(databaseName: string): string {
    // Implement based on your configuration
    return `postgresql://user:password@localhost:5432/${databaseName}?connection_limit=10`;
  }
}
```

### Sequelize Pooling

```javascript
// Sequelize connection configuration with pooling
const sequelize = new Sequelize(database, username, password, {
  host: 'localhost',
  port: 5432,
  dialect: 'postgres',
  
  // Connection pooling configuration
  pool: {
    max: 20,                 // Maximum number of connections in pool
    min: 5,                  // Minimum number of connections in pool
    acquire: 30000,          // Maximum time (ms) to acquire connection
    idle: 10000,             // Maximum time (ms) a connection can be idle
    evict: 1000,             // Time interval (ms) to check for idle connections
    validate: (connection) => {
      // Custom validation function
      return connection.$isValid;
    }
  },
  
  // Connection retry configuration
  retry: {
    max: 3,                  // Maximum retries
    match: [
      /SequelizeConnectionError/,
      /SequelizeConnectionRefusedError/,
      /SequelizeHostNotFoundError/,
      /SequelizeHostNotReachableError/,
      /SequelizeInvalidConnectionError/,
      /SequelizeConnectionTimedOutError/
    ],
    backoffBase: 100,        // Initial backoff delay in ms
    backoffExponent: 1.5,    // Backoff exponent
    timeout: 60000           // Timeout per retry in ms
  },
  
  // Logging configuration
  logging: (sql, timing) => {
    if (timing && timing > 1000) { // Log slow queries
      console.warn(`Slow query (${timing}ms):`, sql);
    }
  },
  
  // Other options
  dialectOptions: {
    ssl: process.env.NODE_ENV === 'production' ? {
      require: true,
      rejectUnauthorized: false
    } : false,
    // Connection timeout
    connectTimeout: 30000,
    // Keep-alive settings
    keepAlive: true,
    keepAliveInitialDelay: 30000
  },
  
  // Set timezone
  timezone: '+00:00',
  
  // Define model options
  define: {
    timestamps: true,
    underscored: true,
    paranoid: true,
    freezeTableName: false
  },
  
  // Query optimizer hints
  benchmark: process.env.NODE_ENV === 'development',
  
  // Transaction isolation level
  isolationLevel: Transaction.ISOLATION_LEVELS.REPEATABLE_READ,
  
  // Connection hooks
  hooks: {
    beforeConnect: async (config) => {
      console.log('Establishing connection to:', config.host);
    },
    afterConnect: async (connection, config) => {
      console.log('Connection established');
      // Set session variables
      await connection.query("SET TIME ZONE 'UTC'");
      await connection.query("SET application_name = 'myapp'");
    },
    beforeDisconnect: async (connection) => {
      console.log('Disconnecting from database');
    }
  }
});

// Monitor connection pool
const monitorPool = () => {
  const pool = sequelize.connectionManager.pool;
  
  console.log('Connection pool stats:', {
    size: pool.size,
    available: pool.available,
    waiting: pool.waiting,
    max: pool.max,
    min: pool.min
  });
};

// Check connection health
async function checkConnectionHealth() {
  try {
    // Test connection
    await sequelize.authenticate();
    
    // Get pool statistics
    const pool = sequelize.connectionManager.pool;
    const poolStats = {
      size: pool.size,
      available: pool.available,
      pending: pool.waiting,
      max: pool.max,
      min: pool.min
    };
    
    // Get database statistics
    const [dbStats] = await sequelize.query(`
      SELECT 
        current_database() as database,
        count(*) as active_connections,
        (SELECT setting FROM pg_settings WHERE name = 'max_connections') as max_connections,
        pg_database_size(current_database()) as database_size
      FROM pg_stat_activity 
      WHERE datname = current_database()
    `);
    
    return {
      status: 'healthy',
      pool: poolStats,
      database: dbStats[0],
      timestamp: new Date()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date()
    };
  }
}

// Connection retry with exponential backoff
async function connectWithRetry(maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await sequelize.authenticate();
      console.log('Database connection established');
      return;
    } catch (error) {
      console.error(`Connection attempt ${i + 1} failed:`, error.message);
      
      if (i === maxRetries - 1) {
        throw error;
      }
      
      // Exponential backoff
      const delay = Math.pow(2, i) * 1000;
      console.log(`Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Graceful shutdown
async function gracefulShutdown() {
  console.log('Shutting down gracefully...');
  
  try {
    // Close all connections
    await sequelize.close();
    console.log('Database connections closed');
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Connection pool for multiple databases
class DatabasePoolManager {
  constructor() {
    this.pools = new Map();
  }
  
  getPool(databaseConfig) {
    const key = JSON.stringify(databaseConfig);
    
    if (!this.pools.has(key)) {
      const sequelize = new Sequelize(
        databaseConfig.database,
        databaseConfig.username,
        databaseConfig.password,
        {
          host: databaseConfig.host,
          port: databaseConfig.port,
          dialect: 'postgres',
          pool: {
            max: databaseConfig.poolMax || 10,
            min: databaseConfig.poolMin || 2,
            acquire: 30000,
            idle: 10000
          },
          logging: false
        }
      );
      
      this.pools.set(key, sequelize);
    }
    
    return this.pools.get(key);
  }
  
  async closeAllPools() {
    const closePromises = Array.from(this.pools.values()).map(
      sequelize => sequelize.close()
    );
    
    await Promise.all(closePromises);
    this.pools.clear();
  }
  
  async healthCheck() {
    const healthResults = [];
    
    for (const [key, sequelize] of this.pools.entries()) {
      try {
        await sequelize.authenticate();
        const [dbInfo] = await sequelize.query('SELECT current_database() as name');
        
        healthResults.push({
          database: dbInfo[0].name,
          status: 'healthy',
          poolSize: sequelize.connectionManager.pool.size
        });
      } catch (error) {
        healthResults.push({
          database: key,
          status: 'unhealthy',
          error: error.message
        });
      }
    }
    
    return healthResults;
  }
}

// Dynamic connection switching
class MultiTenantConnectionManager {
  constructor() {
    this.connections = new Map();
    this.configs = new Map();
  }
  
  addTenant(tenantId, config) {
    this.configs.set(tenantId, config);
  }
  
  async getConnection(tenantId) {
    if (!this.connections.has(tenantId)) {
      const config = this.configs.get(tenantId);
      
      if (!config) {
        throw new Error(`No configuration found for tenant ${tenantId}`);
      }
      
      const sequelize = new Sequelize(
        config.database,
        config.username,
        config.password,
        {
          host: config.host,
          port: config.port,
          dialect: 'postgres',
          pool: {
            max: 5,
            min: 1,
            acquire: 30000,
            idle: 10000
          },
          logging: false
        }
      );
      
      // Test connection
      await sequelize.authenticate();
      
      this.connections.set(tenantId, sequelize);
    }
    
    return this.connections.get(tenantId);
  }
  
  async closeTenantConnection(tenantId) {
    if (this.connections.has(tenantId)) {
      const sequelize = this.connections.get(tenantId);
      await sequelize.close();
      this.connections.delete(tenantId);
    }
  }
  
  async closeAllConnections() {
    const closePromises = Array.from(this.connections.values()).map(
      sequelize => sequelize.close()
    );
    
    await Promise.all(closePromises);
    this.connections.clear();
  }
}
```

### Connection Management Best Practices

```javascript
// Connection pool monitoring and alerting
class ConnectionMonitor {
  constructor(sequelize, options = {}) {
    this.sequelize = sequelize;
    this.options = {
      checkInterval: 30000, // Check every 30 seconds
      maxPoolSize: 20,
      warningThreshold: 0.8, // 80% of max pool size
      ...options
    };
    
    this.metrics = {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      waitingAcquires: 0,
      connectionErrors: 0,
      lastCheck: null
    };
    
    this.startMonitoring();
  }
  
  startMonitoring() {
    this.interval = setInterval(() => {
      this.checkPoolHealth();
    }, this.options.checkInterval);
    
    // Listen for connection events
    this.sequelize.connectionManager.initPools();
    
    const pool = this.sequelize.connectionManager.pool;
    
    // Monitor pool events
    pool.on('acquire', (connection) => {
      this.metrics.activeConnections++;
      console.log('Connection acquired:', connection.id);
    });
    
    pool.on('release', (connection) => {
      this.metrics.activeConnections = Math.max(0, this.metrics.activeConnections - 1);
      console.log('Connection released:', connection.id);
    });
    
    pool.on('create', (connection) => {
      this.metrics.totalConnections++;
      console.log('New connection created:', connection.id);
    });
    
    pool.on('destroy', (connection) => {
      this.metrics.totalConnections = Math.max(0, this.metrics.totalConnections - 1);
      console.log('Connection destroyed:', connection.id);
    });
  }
  
  async checkPoolHealth() {
    try {
      const pool = this.sequelize.connectionManager.pool;
      
      this.metrics = {
        totalConnections: pool.size,
        activeConnections: pool.size - pool.available,
        idleConnections: pool.available,
        waitingAcquires: pool.waiting,
        connectionErrors: 0,
        lastCheck: new Date()
      };
      
      // Check if pool is near capacity
      const utilization = this.metrics.activeConnections / this.options.maxPoolSize;
      
      if (utilization > this.options.warningThreshold) {
        console.warn(`Connection pool utilization high: ${(utilization * 100).toFixed(1)}%`);
        // Send alert
        this.sendAlert('High pool utilization', {
          utilization,
          activeConnections: this.metrics.activeConnections,
          maxPoolSize: this.options.maxPoolSize
        });
      }
      
      // Check for waiting acquires
      if (this.metrics.waitingAcquires > 0) {
        console.warn(`Connections waiting to be acquired: ${this.metrics.waitingAcquires}`);
      }
      
      // Log metrics
      console.log('Connection pool metrics:', this.metrics);
      
    } catch (error) {
      console.error('Error checking pool health:', error);
      this.metrics.connectionErrors++;
    }
  }
  
  sendAlert(subject, data) {
    // Implement alerting (email, Slack, etc.)
    console.log(`ALERT: ${subject}`, data);
  }
  
  stopMonitoring() {
    if (this.interval) {
      clearInterval(this.interval);
    }
  }
  
  getMetrics() {
    return this.metrics;
  }
}

// Connection pool optimization based on load
class AdaptiveConnectionPool {
  constructor(sequelize, options = {}) {
    this.sequelize = sequelize;
    this.options = {
      minConnections: 2,
      maxConnections: 50,
      targetUtilization: 0.7, // Target 70% utilization
      adjustmentInterval: 60000, // Adjust every minute
      ...options
    };
    
    this.metricsHistory = [];
    this.startAdaptation();
  }
  
  startAdaptation() {
    this.interval = setInterval(() => {
      this.adaptPoolSize();
    }, this.options.adjustmentInterval);
  }
  
  async adaptPoolSize() {
    try {
      const pool = this.sequelize.connectionManager.pool;
      const currentMetrics = await this.collectMetrics();
      
      this.metricsHistory.push({
        timestamp: new Date(),
        ...currentMetrics
      });
      
      // Keep only last hour of metrics
      const oneHourAgo = new Date(Date.now() - 3600000);
      this.metricsHistory = this.metricsHistory.filter(
        m => m.timestamp > oneHourAgo
      );
      
      // Calculate average utilization over last 5 minutes
      const fiveMinutesAgo = new Date(Date.now() - 300000);
      const recentMetrics = this.metricsHistory.filter(
        m => m.timestamp > fiveMinutesAgo
      );
      
      if (recentMetrics.length === 0) return;
      
      const avgUtilization = recentMetrics.reduce(
        (sum, m) => sum + m.utilization, 0
      ) / recentMetrics.length;
      
      // Adjust pool size based on utilization
      const currentSize = pool.max;
      let newSize = currentSize;
      
      if (avgUtilization > this.options.targetUtilization * 1.2) {
        // Utilization too high, increase pool size
        newSize = Math.min(
          this.options.maxConnections,
          Math.ceil(currentSize * 1.2)
        );
      } else if (avgUtilization < this.options.targetUtilization * 0.5) {
        // Utilization too low, decrease pool size
        newSize = Math.max(
          this.options.minConnections,
          Math.floor(currentSize * 0.8)
        );
      }
      
      // Only adjust if change is significant
      if (Math.abs(newSize - currentSize) >= 2) {
        console.log(`Adjusting pool size from ${currentSize} to ${newSize}`);
        pool.max = newSize;
        
        // If decreasing, destroy excess idle connections
        if (newSize < currentSize) {
          const excessConnections = pool.available - newSize;
          if (excessConnections > 0) {
            // Destroy oldest idle connections
            const connectionsToDestroy = Array.from(pool._allObjects.values())
              .filter(conn => conn.state === 'IDLE')
              .slice(0, excessConnections);
            
            connectionsToDestroy.forEach(conn => {
              pool.destroy(conn);
            });
          }
        }
      }
      
    } catch (error) {
      console.error('Error adapting pool size:', error);
    }
  }
  
  async collectMetrics() {
    const pool = this.sequelize.connectionManager.pool;
    
    // Get database metrics
    const [dbMetrics] = await this.sequelize.query(`
      SELECT 
        COUNT(*) as total_connections,
        SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) as active_connections,
        SUM(CASE WHEN state = 'idle' THEN 1 ELSE 0 END) as idle_connections
      FROM pg_stat_activity 
      WHERE datname = current_database()
        AND pid <> pg_backend_pid()
    `);
    
    const poolMetrics = {
      poolSize: pool.size,
      available: pool.available,
      waiting: pool.waiting,
      max: pool.max,
      min: pool.min
    };
    
    const utilization = poolMetrics.poolSize > 0 
      ? (poolMetrics.poolSize - poolMetrics.available) / poolMetrics.max
      : 0;
    
    return {
      ...poolMetrics,
      ...dbMetrics[0],
      utilization
    };
  }
  
  stopAdaptation() {
    if (this.interval) {
      clearInterval(this.interval);
    }
  }
}
```

---

## Performance Optimization

### Query Optimization

```sql
-- 1. Use EXPLAIN ANALYZE to understand query performance
EXPLAIN ANALYZE
SELECT u.*, COUNT(p.id) as post_count
FROM users u
LEFT JOIN posts p ON u.id = p.author_id
WHERE u.status = 'ACTIVE'
  AND u.created_at >= '2024-01-01'
GROUP BY u.id
HAVING COUNT(p.id) > 0
ORDER BY post_count DESC
LIMIT 100;

-- 2. Create appropriate indexes
-- Covering index for common queries
CREATE INDEX idx_users_status_created 
ON users(status, created_at DESC)
INCLUDE (name, email);

-- Partial index for active users
CREATE INDEX idx_users_active 
ON users(id) 
WHERE status = 'ACTIVE' AND deleted_at IS NULL;

-- Composite index for join queries
CREATE INDEX idx_posts_author_published 
ON posts(author_id, published, created_at DESC);

-- 3. Use materialized views for complex aggregations
CREATE MATERIALIZED VIEW user_statistics AS
SELECT 
  u.id,
  u.name,
  u.email,
  COUNT(DISTINCT p.id) as post_count,
  COUNT(DISTINCT c.id) as comment_count,
  COALESCE(SUM(p.likes), 0) as total_likes,
  MAX(p.created_at) as last_post_date
FROM users u
LEFT JOIN posts p ON u.id = p.author_id AND p.published = true
LEFT JOIN comments c ON u.id = c.author_id
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.name, u.email;

-- Refresh materialized view
REFRESH MATERIALIZED VIEW CONCURRENTLY user_statistics;

-- 4. Use CTEs for complex queries
WITH user_stats AS (
  SELECT 
    u.id,
    COUNT(p.id) as post_count,
    AVG(p.likes) as avg_likes
  FROM users u
  LEFT JOIN posts p ON u.id = p.author_id
  WHERE u.status = 'ACTIVE'
  GROUP BY u.id
),
comment_stats AS (
  SELECT 
    u.id,
    COUNT(c.id) as comment_count,
    AVG(LENGTH(c.content)) as avg_comment_length
  FROM users u
  LEFT JOIN comments c ON u.id = c.author_id
  WHERE u.status = 'ACTIVE'
  GROUP BY u.id
)
SELECT 
  u.*,
  us.post_count,
  us.avg_likes,
  cs.comment_count,
  cs.avg_comment_length
FROM users u
JOIN user_stats us ON u.id = us.id
JOIN comment_stats cs ON u.id = cs.id
WHERE u.status = 'ACTIVE'
ORDER BY us.post_count DESC;

-- 5. Partition large tables
-- Create partitioned table
CREATE TABLE orders_partitioned (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  total DECIMAL(10,2) NOT NULL,
  status VARCHAR(50) NOT NULL,
  created_at TIMESTAMP NOT NULL
) PARTITION BY RANGE (created_at);

-- Create partitions
CREATE TABLE orders_2024_q1 PARTITION OF orders_partitioned
FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');

CREATE TABLE orders_2024_q2 PARTITION OF orders_partitioned
FOR VALUES FROM ('2024-04-01') TO ('2024-07-01');

-- 6. Use query hints
SELECT /*+ INDEX(users idx_users_email) */ *
FROM users 
WHERE email = 'test@example.com';

-- 7. Optimize JOIN order
-- Put most restrictive tables first
SELECT *
FROM small_table s
JOIN large_table l ON s.id = l.small_id
WHERE s.category = 'specific';

-- 8. Use EXISTS instead of IN for large datasets
-- Good for checking existence
SELECT u.*
FROM users u
WHERE EXISTS (
  SELECT 1 FROM posts p 
  WHERE p.author_id = u.id 
    AND p.published = true
);

-- 9. Avoid SELECT * in production
SELECT id, name, email -- Only needed columns
FROM users
WHERE status = 'ACTIVE';

-- 10. Use pagination with keyset pagination (instead of OFFSET)
-- Faster for deep pagination
SELECT *
FROM posts
WHERE created_at < '2024-06-01'  -- Last seen timestamp
  AND id > 'last-seen-id'        -- Last seen ID
ORDER BY created_at DESC, id DESC
LIMIT 20;
```

### Indexing Strategies

```sql
-- 1. B-tree indexes (default)
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_name ON users(name);

-- 2. Composite indexes
-- Order matters: equality → range → sort
CREATE INDEX idx_users_status_created 
ON users(status, created_at DESC, name);

-- 3. Partial indexes
CREATE INDEX idx_active_users ON users(id) 
WHERE status = 'ACTIVE' AND deleted_at IS NULL;

-- 4. Expression indexes
CREATE INDEX idx_users_lower_email ON users(LOWER(email));
CREATE INDEX idx_users_created_date ON users(DATE(created_at));

-- 5. GIN indexes for JSONB
CREATE INDEX idx_users_metadata ON users USING GIN(metadata);

-- 6. GiST indexes for full-text search
CREATE INDEX idx_posts_search ON posts USING GIN(
  to_tsvector('english', title || ' ' || content)
);

-- 7. BRIN indexes for large, sorted tables
CREATE INDEX idx_orders_created_brin ON orders 
USING BRIN(created_at);

-- 8. Hash indexes (for equality only)
CREATE INDEX idx_users_id_hash ON users USING HASH(id);

-- 9. Covering indexes (INCLUDE clause)
CREATE INDEX idx_users_covering ON users(status, created_at)
INCLUDE (name, email, avatar);

-- 10. Unique indexes with conditions
CREATE UNIQUE INDEX idx_users_active_email 
ON users(email) 
WHERE status = 'ACTIVE';

-- 11. Concurrent index creation (non-blocking)
CREATE INDEX CONCURRENTLY idx_users_status ON users(status);

-- 12. Index maintenance
-- Reindex to fix bloat
REINDEX INDEX idx_users_email;

-- Analyze table to update statistics
ANALYZE users;

-- Get index usage statistics
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan as index_scans,
  idx_tup_read as tuples_read,
  idx_tup_fetch as tuples_fetched
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Find unused indexes
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0;

-- Get index size
SELECT 
  indexname,
  pg_size_pretty(pg_relation_size(indexname::regclass)) as size
FROM pg_indexes
WHERE tablename = 'users'
ORDER BY pg_relation_size(indexname::regclass) DESC;

-- Create index with specific fillfactor
CREATE INDEX idx_users_email ON users(email)
WITH (fillfactor = 90);

-- Create index with parallel workers
CREATE INDEX idx_users_name ON users(name)
WITH (parallel_workers = 4);
```

### Connection Pool Tuning

```javascript
// Dynamic pool configuration based on environment
const getPoolConfig = () => {
  const baseConfig = {
    max: 20,
    min: 5,
    acquire: 30000,
    idle: 10000,
    evict: 1000
  };
  
  switch (process.env.NODE_ENV) {
    case 'production':
      return {
        ...baseConfig,
        max: 100,
        min: 20,
        acquire: 60000,
        idle: 30000
      };
      
    case 'staging':
      return {
        ...baseConfig,
        max: 50,
        min: 10,
        acquire: 45000,
        idle: 20000
      };
      
    case 'development':
      return {
        ...baseConfig,
        max: 10,
        min: 2,
        acquire: 30000,
        idle: 10000
      };
      
    default:
      return baseConfig;
  }
};

// Database connection factory with health checks
class DatabaseConnectionFactory {
  constructor() {
    this.connections = new Map();
    this.healthChecks = new Map();
  }
  
  async createConnection(name, config) {
    const sequelize = new Sequelize(
      config.database,
      config.username,
      config.password,
      {
        host: config.host,
        port: config.port,
        dialect: 'postgres',
        pool: getPoolConfig(),
        retry: {
          max: 3,
          match: [
            /SequelizeConnectionError/,
            /SequelizeConnectionRefusedError/
          ],
          backoffBase: 100,
          backoffExponent: 1.5,
          timeout: 30000
        },
        logging: config.logging || false,
        dialectOptions: {
          statement_timeout: 30000,
          idle_in_transaction_session_timeout: 30000,
          connectionTimeoutMillis: 10000,
          keepAlive: true,
          keepAliveInitialDelayMillis: 10000
        }
      }
    );
    
    // Test connection
    try {
      await sequelize.authenticate();
      console.log(`Connection ${name} established`);
    } catch (error) {
      console.error(`Failed to connect to ${name}:`, error);
      throw error;
    }
    
    // Set up connection health check
    this.setupHealthCheck(name, sequelize);
    
    this.connections.set(name, sequelize);
    return sequelize;
  }
  
  setupHealthCheck(name, sequelize) {
    const healthCheck = async () => {
      try {
        // Simple query to check connection
        await sequelize.query('SELECT 1');
        
        // Check pool status
        const pool = sequelize.connectionManager.pool;
        const poolStats = {
          size: pool.size,
          available: pool.available,
          waiting: pool.waiting,
          max: pool.max,
          min: pool.min
        };
        
        // Check for issues
        if (pool.waiting > 10) {
          console.warn(`Connection pool ${name} has ${pool.waiting} waiting requests`);
        }
        
        if (pool.available === 0 && pool.size >= pool.max) {
          console.error(`Connection pool ${name} exhausted`);
        }
        
        return {
          status: 'healthy',
          pool: poolStats,
          timestamp: new Date()
        };
      } catch (error) {
        console.error(`Health check failed for ${name}:`, error);
        return {
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date()
        };
      }
    };
    
    this.healthChecks.set(name, healthCheck);
    
    // Run health check periodically
    const interval = setInterval(async () => {
      const result = await healthCheck();
      if (result.status === 'unhealthy') {
        // Attempt to reconnect
        this.reconnect(name, sequelize);
      }
    }, 30000); // Every 30 seconds
    
    // Store interval for cleanup
    this.healthChecks.set(`${name}_interval`, interval);
  }
  
  async reconnect(name, sequelize) {
    console.log(`Attempting to reconnect ${name}...`);
    
    try {
      await sequelize.close();
      
      // Wait before reconnecting
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      await sequelize.authenticate();
      console.log(`Reconnected ${name} successfully`);
    } catch (error) {
      console.error(`Failed to reconnect ${name}:`, error);
    }
  }
  
  async getConnection(name) {
    if (!this.connections.has(name)) {
      throw new Error(`Connection ${name} not found`);
    }
    
    const sequelize = this.connections.get(name);
    
    // Verify connection is healthy
    const healthCheck = this.healthChecks.get(name);
    if (healthCheck) {
      const health = await healthCheck();
      if (health.status === 'unhealthy') {
        throw new Error(`Connection ${name} is unhealthy`);
      }
    }
    
    return sequelize;
  }
  
  async closeAll() {
    // Clear health check intervals
    for (const [key, value] of this.healthChecks.entries()) {
      if (key.endsWith('_interval')) {
        clearInterval(value);
      }
    }
    
    // Close all connections
    const closePromises = Array.from(this.connections.values()).map(
      sequelize => sequelize.close()
    );
    
    await Promise.all(closePromises);
    this.connections.clear();
    this.healthChecks.clear();
  }
  
  async getHealthStatus() {
    const status = {};
    
    for (const [name, healthCheck] of this.healthChecks.entries()) {
      if (!name.endsWith('_interval')) {
        status[name] = await healthCheck();
      }
    }
    
    return status;
  }
}

// Connection pool for read replicas
class ReadReplicaPool {
  constructor() {
    this.replicas = [];
    this.currentIndex = 0;
  }
  
  addReplica(config) {
    const sequelize = new Sequelize(
      config.database,
      config.username,
      config.password,
      {
        host: config.host,
        port: config.port,
        dialect: 'postgres',
        pool: {
          max: 10,
          min: 2,
          acquire: 30000,
          idle: 10000
        },
        logging: false,
        replication: false // Single connection
      }
    );
    
    this.replicas.push({
      sequelize,
      config,
      weight: config.weight || 1,
      healthy: true,
      lastUsed: null
    });
  }
  
  async getConnection(strategy = 'round-robin') {
    if (this.replicas.length === 0) {
      throw new Error('No replicas available');
    }
    
    let selectedReplica;
    
    switch (strategy) {
      case 'round-robin':
        selectedReplica = this.replicas[this.currentIndex];
        this.currentIndex = (this.currentIndex + 1) % this.replicas.length;
        break;
        
      case 'random':
        const randomIndex = Math.floor(Math.random() * this.replicas.length);
        selectedReplica = this.replicas[randomIndex];
        break;
        
      case 'weighted':
        const totalWeight = this.replicas.reduce((sum, r) => sum + r.weight, 0);
        let random = Math.random() * totalWeight;
        
        for (const replica of this.replicas) {
          random -= replica.weight;
          if (random <= 0) {
            selectedReplica = replica;
            break;
          }
        }
        break;
        
      case 'least-used':
        selectedReplica = this.replicas.reduce((least, current) => {
          if (!least.lastUsed) return current;
          if (!current.lastUsed) return least;
          return current.lastUsed < least.lastUsed ? current : least;
        });
        break;
        
      default:
        selectedReplica = this.replicas[0];
    }
    
    // Update last used timestamp
    selectedReplica.lastUsed = new Date();
    
    return selectedReplica.sequelize;
  }
  
  async healthCheck() {
    const checks = await Promise.all(
      this.replicas.map(async (replica) => {
        try {
          await replica.sequelize.authenticate();
          replica.healthy = true;
          return { host: replica.config.host, healthy: true };
        } catch (error) {
          replica.healthy = false;
          return { host: replica.config.host, healthy: false, error: error.message };
        }
      })
    );
    
    // Filter out unhealthy replicas for next selection
    this.replicas = this.replicas.filter(r => r.healthy);
    
    return checks;
  }
  
  async closeAll() {
    const closePromises = this.replicas.map(replica => 
      replica.sequelize.close()
    );
    
    await Promise.all(closePromises);
    this.replicas = [];
  }
}

// Usage example
const replicaPool = new ReadReplicaPool();

// Add replicas with weights
replicaPool.addReplica({
  host: 'replica1.example.com',
  database: 'mydb',
  username: 'user',
  password: 'pass',
  weight: 3 // Higher weight = more traffic
});

replicaPool.addReplica({
  host: 'replica2.example.com',
  database: 'mydb',
  username: 'user',
  password: 'pass',
  weight: 1
});

// Get connection for read query
const readConnection = await replicaPool.getConnection('weighted');
const results = await readConnection.query('SELECT * FROM users LIMIT 10');

// Run health check
await replicaPool.healthCheck();
```

---

## Interview Questions

### Junior to Mid-Level

**Prisma:**
1. What is Prisma and how does it differ from traditional ORMs?
2. How do you define a one-to-many relationship in Prisma schema?
3. What are Prisma Client extensions and when would you use them?
4. How do you handle database migrations with Prisma?
5. What is the purpose of the `@relation` directive in Prisma schema?

**Sequelize:**
1. What are Sequelize models and how do you define them?
2. How do you create associations between models in Sequelize?
3. What are hooks in Sequelize and give examples of when to use them?
4. How do you handle database migrations with Sequelize?
5. What is the difference between `findOne` and `findByPk`?

**General Database:**
1. What is the difference between INNER JOIN and LEFT JOIN?
2. How do transactions ensure data consistency?
3. What is connection pooling and why is it important?
4. When would you use raw SQL queries instead of ORM methods?
5. What are database indexes and why are they important?

### Senior Level

**Architecture & Design:**
1. How would you design a database schema for a multi-tenant SaaS application?
2. What strategies would you use for database sharding and partitioning?
3. How would you implement soft deletes at the database level?
4. What are the trade-offs between database normalization and denormalization?
5. How would you design a schema for an audit logging system?

**Performance:**
1. How would you identify and fix N+1 query problems?
2. What indexing strategies would you use for a high-traffic e-commerce site?
3. How do you optimize complex JOIN queries with multiple tables?
4. What are materialized views and when would you use them?
5. How would you handle database connection pool exhaustion?

**Advanced Features:**
1. How do you implement optimistic concurrency control?
2. What are database triggers and when should they be used?
3. How would you implement full-text search in PostgreSQL?
4. What are window functions and give examples of their use cases?
5. How do you handle database failover and replication?

**Security:**
1. How would you prevent SQL injection attacks in raw queries?
2. What strategies would you use for database encryption?
3. How do you implement row-level security in PostgreSQL?
4. What are prepared statements and why are they important for security?
5. How would you handle database credentials in a microservices architecture?

### Real-World Scenarios

**Scenario 1: E-commerce Platform**
You're building an e-commerce platform that needs to handle:
- 1M+ products with real-time inventory
- 10K+ daily orders
- Complex product search with filters
- Shopping cart and checkout process
- Order tracking and notifications

**Questions:**
1. How would you design the database schema for this platform?
2. What indexing strategy would you use for product search?
3. How would you handle inventory updates during flash sales?
4. How would you implement the shopping cart functionality?
5. What transaction isolation level would you use for checkout process?

**Scenario 2: Social Media Application**
You're building a social media app that needs:
- User profiles and relationships (followers/following)
- Posts, comments, and likes
- Real-time feed updates
- Notifications system
- Analytics on user engagement

**Questions:**
1. How would you design the database schema for relationships?
2. What strategy would you use for implementing the news feed?
3. How would you handle real-time notifications at scale?
4. How would you optimize queries for user timelines?
5. What database features would you use for full-text search?

**Scenario 3: Financial Application**
You're building a banking application that needs:
- ACID compliance for all transactions
- Audit trail for every operation
- Real-time balance updates
- Support for batch processing
- Regulatory compliance requirements

**Questions:**
1. How would you ensure data consistency for money transfers?
2. What transaction isolation level would you use and why?
3. How would you implement an audit trail?
4. How would you handle concurrent balance updates?
5. What backup and recovery strategy would you implement?

**Scenario 4: Analytics Platform**
You're building an analytics platform that needs to:
- Process billions of events per day
- Provide real-time dashboards
- Support complex aggregations
- Handle data retention policies
- Scale horizontally

**Questions:**
1. How would you structure your database for time-series data?
2. What partitioning strategy would you use?
3. How would you implement real-time aggregation?
4. What indexing strategy would you use for analytics queries?
5. How would you handle data archiving and retention?

**Scenario 5: Multi-tenant SaaS Application**
You're building a SaaS platform that needs to:
- Support thousands of tenants
- Provide data isolation between tenants
- Allow tenant-specific customizations
- Scale database operations
- Provide cross-tenant analytics

**Questions:**
1. How would you implement data isolation between tenants?
2. What database design pattern would you use?
3. How would you handle database migrations across all tenants?
4. How would you optimize queries for multi-tenant data?
5. What sharding strategy would you use for horizontal scaling?

**Scenario 6: Real-time Gaming Platform**
You're building a gaming platform that needs:
- Real-time player state updates
- Leaderboards with millions of players
- Matchmaking system
- Player inventory and transactions
- Anti-cheat mechanisms

**Questions:**
1. How would you design the database for real-time updates?
2. What strategy would you use for leaderboard implementation?
3. How would you handle matchmaking database operations?
4. What transaction patterns would you use for in-game purchases?
5. How would you detect and prevent cheating at the database level?

**Scenario 7: Healthcare Application**
You're building a healthcare application that needs:
- HIPAA compliance
- Patient record management
- Appointment scheduling
- Prescription tracking
- Audit trails for all access

**Questions:**
1. How would you ensure HIPAA compliance at the database level?
2. What encryption strategy would you use for sensitive data?
3. How would you implement access control for patient records?
4. What backup strategy would you use for critical health data?
5. How would you handle database audits for compliance?

These scenarios and questions cover the depth and breadth of knowledge expected from senior developers working with PostgreSQL, Prisma, and Sequelize in production environments.