# 🧪 Comprehensive Node.js Testing Guide

## 📑 Table of Contents
1. [Jest Fundamentals](#jest-fundamentals)
2. [Supertest (API Testing)](#supertest-api-testing)
3. [Unit Testing Services](#unit-testing-services)
4. [Integration Testing](#integration-testing)
5. [Mocking DB & APIs](#mocking-db-apis)
6. [End-to-End Testing](#end-to-end-testing)
7. [Testing Best Practices](#testing-best-practices)
8. [Testing Infrastructure](#testing-infrastructure)

---

## 1. Jest Fundamentals <a name="jest-fundamentals"></a>

### Overview
Jest is a comprehensive JavaScript testing framework with built-in mocking, code coverage, and snapshot testing capabilities.

### Comprehensive Setup and Configuration

```javascript
// jest.config.js
module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Directories
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.[jt]s?(x)',
    '**/?(*.)+(spec|test).[jt]s?(x)'
  ],
  
  // Coverage
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
    '!src/**/*.d.ts',
    '!src/**/index.{js,ts}',
    '!src/**/types/**',
    '!src/**/__tests__/**'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  
  // Transform
  transform: {
    '^.+\\.(js|ts)$': 'babel-jest'
  },
  
  // Module handling
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@test/(.*)$': '<rootDir>/tests/$1'
  },
  
  // Setup and teardown
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  globalSetup: '<rootDir>/tests/global-setup.js',
  globalTeardown: '<rootDir>/tests/global-teardown.js',
  
  // Test runner
  testRunner: 'jest-circus/runner',
  
  // Performance
  maxWorkers: '50%',
  testTimeout: 30000,
  
  // Watch mode
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname'
  ]
};

// tests/setup.js
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Custom matchers
expect.extend({
  toBeWithinRange(received, floor, ceiling) {
    const pass = received >= floor && received <= ceiling;
    if (pass) {
      return {
        message: () =>
          `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },
});

// Global test helpers
global.createTestUser = (overrides = {}) => ({
  id: 'user_123',
  email: 'test@example.com',
  name: 'Test User',
  role: 'user',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides
});

// tests/global-setup.js
module.exports = async () => {
  console.log('Global setup starting...');
  
  // Start test databases, servers, etc.
  await require('./test-db').start();
  await require('./test-redis').start();
  
  console.log('Global setup complete');
};

// tests/global-teardown.js
module.exports = async () => {
  console.log('Global teardown starting...');
  
  // Clean up test resources
  await require('./test-db').stop();
  await require('./test-redis').stop();
  
  console.log('Global teardown complete');
};
```

### Core Jest Features Deep Dive

```javascript
// tests/jest-fundamentals.test.js
describe('Jest Fundamentals', () => {
  // 1. Basic Testing
  describe('Basic Assertions', () => {
    test('equality matchers', () => {
      expect(2 + 2).toBe(4);
      expect({ a: 1 }).toEqual({ a: 1 });
      expect({ a: 1 }).not.toBe({ a: 1 }); // Different references
    });
    
    test('truthiness matchers', () => {
      expect(null).toBeNull();
      expect(undefined).toBeUndefined();
      expect('value').toBeDefined();
      expect(true).toBeTruthy();
      expect(false).toBeFalsy();
      expect(0).toBeFalsy();
      expect('').toBeFalsy();
    });
    
    test('numeric matchers', () => {
      expect(10).toBeGreaterThan(5);
      expect(10).toBeGreaterThanOrEqual(10);
      expect(5).toBeLessThan(10);
      expect(5).toBeLessThanOrEqual(5);
      expect(0.1 + 0.2).toBeCloseTo(0.3); // For floating point
    });
    
    test('string matchers', () => {
      expect('hello world').toMatch(/hello/);
      expect('hello world').toContain('hello');
      expect('HELLO').toEqual(expect.stringContaining('HELL'));
    });
    
    test('array matchers', () => {
      expect([1, 2, 3]).toContain(2);
      expect([1, 2, 3]).toEqual(expect.arrayContaining([1, 2]));
      expect([{ id: 1 }, { id: 2 }]).toEqual(
        expect.arrayContaining([{ id: 1 }])
      );
    });
    
    test('object matchers', () => {
      const user = { id: 1, name: 'John', email: 'john@example.com' };
      
      expect(user).toHaveProperty('name');
      expect(user).toHaveProperty('name', 'John');
      expect(user).toEqual(
        expect.objectContaining({
          id: 1,
          name: expect.any(String)
        })
      );
    });
    
    test('error matchers', () => {
      const throwError = () => {
        throw new Error('Something went wrong');
      };
      
      expect(throwError).toThrow();
      expect(throwError).toThrow('Something went wrong');
      expect(throwError).toThrow(/went wrong/);
      expect(throwError).toThrow(Error);
    });
  });
  
  // 2. Async Testing
  describe('Async Testing', () => {
    test('resolves/rejects', async () => {
      const promise = Promise.resolve('success');
      await expect(promise).resolves.toBe('success');
      
      const failedPromise = Promise.reject(new Error('failure'));
      await expect(failedPromise).rejects.toThrow('failure');
    });
    
    test('async/await', async () => {
      const fetchData = () => Promise.resolve({ data: 'test' });
      const data = await fetchData();
      expect(data).toEqual({ data: 'test' });
    });
    
    test('callback based', (done) => {
      setTimeout(() => {
        expect(true).toBe(true);
        done();
      }, 100);
    });
  });
  
  // 3. Test Lifecycle
  describe('Test Lifecycle', () => {
    let database;
    let counter = 0;
    
    // Runs once before all tests in this describe block
    beforeAll(async () => {
      database = await setupDatabase();
      console.log('Database setup complete');
    });
    
    // Runs once after all tests in this describe block
    afterAll(async () => {
      await database.disconnect();
      console.log('Database disconnected');
    });
    
    // Runs before each test
    beforeEach(() => {
      counter = 0;
      console.log(`Test ${++counter} starting...`);
    });
    
    // Runs after each test
    afterEach(() => {
      console.log(`Test ${counter} completed`);
    });
    
    test('test 1', () => {
      expect(database).toBeDefined();
    });
    
    test('test 2', () => {
      expect(counter).toBe(1);
    });
  });
  
  // 4. Parameterized Tests
  describe.each([
    [1, 1, 2],
    [1, 2, 3],
    [2, 2, 4],
  ])('Parameterized addition: %i + %i', (a, b, expected) => {
    test(`returns ${expected}`, () => {
      expect(a + b).toBe(expected);
    });
  });
  
  describe.each`
    a    | b    | expected
    ${1} | ${1} | ${2}
    ${1} | ${2} | ${3}
    ${2} | ${2} | ${4}
  `('Template literal parameterized: $a + $b', ({ a, b, expected }) => {
    test(`returns ${expected}`, () => {
      expect(a + b).toBe(expected);
    });
  });
  
  // 5. Snapshots
  describe('Snapshot Testing', () => {
    test('object snapshot', () => {
      const user = {
        id: 1,
        name: 'John Doe',
        email: 'john@example.com',
        roles: ['admin', 'user'],
        metadata: {
          created: '2024-01-01',
          updated: '2024-01-02'
        }
      };
      
      expect(user).toMatchSnapshot();
    });
    
    test('inline snapshot', () => {
      const config = {
        apiUrl: 'https://api.example.com',
        timeout: 5000,
        retries: 3
      };
      
      expect(config).toMatchInlineSnapshot(`
        Object {
          "apiUrl": "https://api.example.com",
          "retries": 3,
          "timeout": 5000,
        }
      `);
    });
    
    test('property matchers in snapshots', () => {
      const result = {
        id: expect.any(String),
        timestamp: expect.any(Date),
        data: { name: 'Test' }
      };
      
      expect(result).toMatchSnapshot({
        id: expect.any(String),
        timestamp: expect.any(Date)
      });
    });
  });
  
  // 6. Custom Matchers
  describe('Custom Matchers', () => {
    test('custom range matcher', () => {
      expect(5).toBeWithinRange(1, 10);
      expect(15).not.toBeWithinRange(1, 10);
    });
    
    // Custom async matcher
    expect.extend({
      async toBeRejectedWith(received, expectedError) {
        try {
          await received;
          return {
            message: () => 'Expected promise to reject, but it resolved',
            pass: false
          };
        } catch (error) {
          if (error.message === expectedError) {
            return {
              message: () => `Expected promise not to reject with "${expectedError}"`,
              pass: true
            };
          }
          return {
            message: () => 
              `Expected promise to reject with "${expectedError}", but got "${error.message}"`,
            pass: false
          };
        }
      }
    });
  });
  
  // 7. Performance Testing
  describe('Performance Testing', () => {
    test('execution time', () => {
      const start = performance.now();
      
      // Code to test
      let sum = 0;
      for (let i = 0; i < 1000000; i++) {
        sum += i;
      }
      
      const end = performance.now();
      const executionTime = end - start;
      
      // Should complete in less than 100ms
      expect(executionTime).toBeLessThan(100);
    });
  });
  
  // 8. Test.each with different scenarios
  describe.each([
    {
      name: 'valid user',
      input: { email: 'test@example.com', password: 'Password123!' },
      expected: { success: true }
    },
    {
      name: 'invalid email',
      input: { email: 'invalid', password: 'Password123!' },
      expected: { success: false, error: 'Invalid email' }
    },
    {
      name: 'weak password',
      input: { email: 'test@example.com', password: '123' },
      expected: { success: false, error: 'Password too weak' }
    }
  ])('User validation: $name', ({ input, expected }) => {
    test(`returns ${expected.success ? 'success' : 'error'}`, () => {
      const result = validateUser(input);
      expect(result).toEqual(expected);
    });
  });
});

// Helper functions
async function setupDatabase() {
  return {
    connect: () => Promise.resolve(),
    disconnect: () => Promise.resolve(),
    query: () => Promise.resolve([])
  };
}

function validateUser({ email, password }) {
  if (!email.includes('@')) {
    return { success: false, error: 'Invalid email' };
  }
  
  if (password.length < 8) {
    return { success: false, error: 'Password too weak' };
  }
  
  return { success: true };
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the difference between `toBe`, `toEqual`, and `toStrictEqual`. When would you use each?"
2. "How does Jest's mocking system work under the hood? Explain `jest.mock()` vs `jest.spyOn()`."
3. "What are Jest's lifecycle methods and in what order do they execute for nested describe blocks?"

**Scenario-Based Questions:**
1. "You have a flaky test that occasionally fails due to timing issues. How would you investigate and fix it?"
2. "Your test suite takes 30 minutes to run. What strategies would you implement to reduce this time?"
3. "A developer complains that snapshot tests are causing too many false positives. How would you improve snapshot testing in your team?"

**Real-World Challenge:**
> "Design a testing strategy for a real-time chat application that: 1) Handles WebSocket connections, 2) Processes messages with different priorities, 3) Stores chat history, 4) Implements typing indicators, 5) Supports file uploads. Include: Unit tests for business logic, integration tests for WebSocket handling, and E2E tests for user interactions."

---

## 2. Supertest (API Testing) <a name="supertest-api-testing"></a>

### Overview
Supertest is a HTTP assertion library that allows you to test Node.js HTTP servers with a fluent API.

### Comprehensive Implementation

```javascript
// tests/setup-api.js
const mongoose = require('mongoose');
const Redis = require('ioredis');
const { createServer } = require('../src/server');

// Test database connections
let mongoConnection;
let redisClient;
let server;

beforeAll(async () => {
  // Connect to test MongoDB
  mongoConnection = await mongoose.createConnection('mongodb://localhost:27017/test_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  // Connect to test Redis
  redisClient = new Redis({
    host: 'localhost',
    port: 6379,
    db: 1, // Use separate DB for tests
  });
  
  // Create test server
  server = await createServer({
    mongoConnection,
    redisClient,
    environment: 'test'
  });
});

afterAll(async () => {
  // Cleanup
  await mongoConnection.dropDatabase();
  await mongoConnection.close();
  await redisClient.flushdb();
  await redisClient.quit();
  await server.close();
});

beforeEach(async () => {
  // Clear collections before each test
  const collections = await mongoConnection.db.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }
  
  // Clear Redis
  await redisClient.flushdb();
});

// Global test helper for authenticated requests
global.createAuthenticatedRequest = (app, user = {}) => {
  const jwt = require('jsonwebtoken');
  const token = jwt.sign(
    { 
      id: user.id || 'test_user_id',
      email: user.email || 'test@example.com',
      role: user.role || 'user' 
    },
    process.env.JWT_SECRET
  );
  
  return request(app)
    .set('Authorization', `Bearer ${token}`);
};

// Export test utilities
module.exports = {
  server,
  mongoConnection,
  redisClient,
  request: require('supertest')
};

// tests/api/users.test.js
const { request, server, createAuthenticatedRequest } = require('../setup-api');
const User = require('../../src/models/User');

describe('User API', () => {
  describe('POST /api/users', () => {
    const validUserData = {
      email: 'test@example.com',
      password: 'Password123!',
      name: 'Test User',
      age: 25
    };

    test('creates a new user with valid data', async () => {
      const response = await request(server)
        .post('/api/users')
        .send(validUserData)
        .expect('Content-Type', /json/)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        data: {
          email: validUserData.email,
          name: validUserData.name,
          age: validUserData.age
        }
      });

      // Verify user was created in database
      const user = await User.findOne({ email: validUserData.email });
      expect(user).toBeTruthy();
      expect(user.name).toBe(validUserData.name);
      expect(user.age).toBe(validUserData.age);
    });

    test('returns 400 for invalid email', async () => {
      const response = await request(server)
        .post('/api/users')
        .send({
          ...validUserData,
          email: 'invalid-email'
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Validation failed',
        details: expect.arrayContaining([
          expect.objectContaining({
            field: 'email',
            message: expect.stringContaining('email')
          })
        ])
      });
    });

    test('returns 400 for weak password', async () => {
      const response = await request(server)
        .post('/api/users')
        .send({
          ...validUserData,
          password: '123'
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Validation failed',
        details: expect.arrayContaining([
          expect.objectContaining({
            field: 'password',
            message: expect.stringContaining('password')
          })
        ])
      });
    });

    test('returns 409 for duplicate email', async () => {
      // Create user first
      await User.create(validUserData);

      const response = await request(server)
        .post('/api/users')
        .send(validUserData)
        .expect(409);

      expect(response.body).toEqual({
        success: false,
        error: 'User already exists'
      });
    });

    test('hashes password before saving', async () => {
      const response = await request(server)
        .post('/api/users')
        .send(validUserData)
        .expect(201);

      const user = await User.findOne({ email: validUserData.email });
      expect(user.password).not.toBe(validUserData.password);
      expect(user.password).toMatch(/^\$2[aby]\$/); // bcrypt hash format
    });
  });

  describe('GET /api/users/:id', () => {
    let testUser;
    let authRequest;

    beforeEach(async () => {
      testUser = await User.create({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User',
        age: 25
      });

      authRequest = createAuthenticatedRequest(server, {
        id: testUser._id.toString(),
        email: testUser.email
      });
    });

    test('returns user data for authorized request', async () => {
      const response = await authRequest
        .get(`/api/users/${testUser._id}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: {
          id: testUser._id.toString(),
          email: testUser.email,
          name: testUser.name,
          age: testUser.age,
          createdAt: testUser.createdAt.toISOString(),
          updatedAt: testUser.updatedAt.toISOString()
        }
      });
    });

    test('returns 401 for unauthorized request', async () => {
      await request(server)
        .get(`/api/users/${testUser._id}`)
        .expect(401);
    });

    test('returns 403 for accessing other user data', async () => {
      const otherUser = await User.create({
        email: 'other@example.com',
        password: 'Password123!',
        name: 'Other User'
      });

      await authRequest
        .get(`/api/users/${otherUser._id}`)
        .expect(403);
    });

    test('returns 404 for non-existent user', async () => {
      const nonExistentId = new mongoose.Types.ObjectId();
      
      const response = await authRequest
        .get(`/api/users/${nonExistentId}`)
        .expect(404);

      expect(response.body).toEqual({
        success: false,
        error: 'User not found'
      });
    });

    test('handles invalid ObjectId format', async () => {
      const response = await authRequest
        .get('/api/users/invalid-id')
        .expect(400);

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid user ID'
      });
    });
  });

  describe('PUT /api/users/:id', () => {
    let testUser;
    let authRequest;

    beforeEach(async () => {
      testUser = await User.create({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User',
        age: 25,
        bio: 'Original bio'
      });

      authRequest = createAuthenticatedRequest(server, {
        id: testUser._id.toString(),
        email: testUser.email
      });
    });

    test('updates user with valid data', async () => {
      const updates = {
        name: 'Updated Name',
        age: 30,
        bio: 'Updated bio'
      };

      const response = await authRequest
        .put(`/api/users/${testUser._id}`)
        .send(updates)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        data: {
          name: updates.name,
          age: updates.age,
          bio: updates.bio
        }
      });

      // Verify database update
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.name).toBe(updates.name);
      expect(updatedUser.age).toBe(updates.age);
      expect(updatedUser.bio).toBe(updates.bio);
      expect(updatedUser.updatedAt.getTime()).toBeGreaterThan(
        testUser.updatedAt.getTime()
      );
    });

    test('does not allow email update', async () => {
      const response = await authRequest
        .put(`/api/users/${testUser._id}`)
        .send({ email: 'new@example.com' })
        .expect(200);

      // Email should remain unchanged
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.email).toBe(testUser.email);
    });

    test('validates update data', async () => {
      const response = await authRequest
        .put(`/api/users/${testUser._id}`)
        .send({ age: -5 }) // Invalid age
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Validation failed'
      });
    });
  });

  describe('DELETE /api/users/:id', () => {
    let testUser;
    let authRequest;

    beforeEach(async () => {
      testUser = await User.create({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User'
      });

      authRequest = createAuthenticatedRequest(server, {
        id: testUser._id.toString(),
        email: testUser.email,
        role: 'admin' // Admin can delete users
      });
    });

    test('soft deletes user', async () => {
      const response = await authRequest
        .delete(`/api/users/${testUser._id}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'User deleted successfully'
      });

      // User should be marked as deleted
      const deletedUser = await User.findById(testUser._id);
      expect(deletedUser.deleted).toBe(true);
      expect(deletedUser.deletedAt).toBeInstanceOf(Date);
    });

    test('prevents hard deletion', async () => {
      await authRequest
        .delete(`/api/users/${testUser._id}`)
        .expect(200);

      // User should still exist in database
      const user = await User.findById(testUser._id);
      expect(user).toBeTruthy();
    });

    test('returns 403 for non-admin users', async () => {
      const regularUserRequest = createAuthenticatedRequest(server, {
        id: testUser._id.toString(),
        email: testUser.email,
        role: 'user' // Regular user cannot delete
      });

      await regularUserRequest
        .delete(`/api/users/${testUser._id}`)
        .expect(403);
    });
  });

  describe('GET /api/users', () => {
    beforeEach(async () => {
      // Create test users
      await User.create([
        {
          email: 'user1@example.com',
          password: 'Password123!',
          name: 'User One',
          age: 25,
          role: 'user'
        },
        {
          email: 'user2@example.com',
          password: 'Password123!',
          name: 'User Two',
          age: 30,
          role: 'user'
        },
        {
          email: 'admin@example.com',
          password: 'Password123!',
          name: 'Admin User',
          age: 35,
          role: 'admin'
        }
      ]);
    });

    test('returns paginated users', async () => {
      const authRequest = createAuthenticatedRequest(server, { role: 'admin' });
      
      const response = await authRequest
        .get('/api/users')
        .query({ page: 1, limit: 2 })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        data: expect.any(Array),
        pagination: {
          page: 1,
          limit: 2,
          total: 3,
          pages: 2
        }
      });

      expect(response.body.data).toHaveLength(2);
    });

    test('filters users by role', async () => {
      const authRequest = createAuthenticatedRequest(server, { role: 'admin' });
      
      const response = await authRequest
        .get('/api/users')
        .query({ role: 'admin' })
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].role).toBe('admin');
    });

    test('sorts users by age', async () => {
      const authRequest = createAuthenticatedRequest(server, { role: 'admin' });
      
      const response = await authRequest
        .get('/api/users')
        .query({ sort: 'age', order: 'desc' })
        .expect(200);

      const ages = response.body.data.map(user => user.age);
      expect(ages).toEqual([35, 30, 25]);
    });

    test('searches users by name', async () => {
      const authRequest = createAuthenticatedRequest(server, { role: 'admin' });
      
      const response = await authRequest
        .get('/api/users')
        .query({ search: 'Admin' })
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].name).toBe('Admin User');
    });
  });

  describe('Authentication Tests', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await User.create({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User'
      });
    });

    describe('POST /api/auth/login', () => {
      test('returns token with valid credentials', async () => {
        const response = await request(server)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'Password123!'
          })
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            token: expect.any(String),
            user: {
              id: testUser._id.toString(),
              email: testUser.email,
              name: testUser.name
            }
          }
        });

        // Verify token is valid
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(response.body.data.token, process.env.JWT_SECRET);
        expect(decoded.id).toBe(testUser._id.toString());
      });

      test('returns 401 with invalid password', async () => {
        const response = await request(server)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'WrongPassword!'
          })
          .expect(401);

        expect(response.body).toEqual({
          success: false,
          error: 'Invalid credentials'
        });
      });

      test('returns 401 with non-existent email', async () => {
        const response = await request(server)
          .post('/api/auth/login')
          .send({
            email: 'nonexistent@example.com',
            password: 'Password123!'
          })
          .expect(401);

        expect(response.body).toEqual({
          success: false,
          error: 'Invalid credentials'
        });
      });

      test('rate limits login attempts', async () => {
        const requests = Array(10).fill().map(() =>
          request(server)
            .post('/api/auth/login')
            .send({
              email: 'test@example.com',
              password: 'WrongPassword!'
            })
        );

        // First 5 requests should fail with 401
        for (let i = 0; i < 5; i++) {
          await requests[i].expect(401);
        }

        // Next requests should be rate limited
        for (let i = 5; i < 10; i++) {
          await requests[i].expect(429);
        }
      });
    });

    describe('POST /api/auth/refresh', () => {
      test('refreshes valid token', async () => {
        const jwt = require('jsonwebtoken');
        const refreshToken = jwt.sign(
          { id: testUser._id.toString(), type: 'refresh' },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: '7d' }
        );

        // Store refresh token
        await redisClient.set(`refresh_token:${testUser._id}`, refreshToken);

        const response = await request(server)
          .post('/api/auth/refresh')
          .set('Authorization', `Bearer ${refreshToken}`)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            token: expect.any(String)
          }
        });
      });

      test('returns 401 with invalid refresh token', async () => {
        await request(server)
          .post('/api/auth/refresh')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401);
      });

      test('returns 401 with expired refresh token', async () => {
        const jwt = require('jsonwebtoken');
        const expiredToken = jwt.sign(
          { id: testUser._id.toString(), type: 'refresh' },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: '-1s' } // Already expired
        );

        await request(server)
          .post('/api/auth/refresh')
          .set('Authorization', `Bearer ${expiredToken}`)
          .expect(401);
      });
    });
  });

  describe('File Upload Tests', () => {
    let authRequest;

    beforeEach(async () => {
      const testUser = await User.create({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User'
      });

      authRequest = createAuthenticatedRequest(server, {
        id: testUser._id.toString(),
        email: testUser.email
      });
    });

    test('uploads profile picture', async () => {
      const fs = require('fs');
      const path = require('path');

      const imagePath = path.join(__dirname, 'fixtures', 'test-image.jpg');
      
      const response = await authRequest
        .post('/api/users/profile/picture')
        .attach('picture', imagePath)
        .field('description', 'Test profile picture')
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        data: {
          url: expect.stringMatching(/^https?:\/\//),
          size: expect.any(Number),
          mimetype: 'image/jpeg'
        }
      });

      // Verify file was saved
      const filePath = path.join(
        process.cwd(),
        'uploads',
        'profiles',
        path.basename(response.body.data.url)
      );
      expect(fs.existsSync(filePath)).toBe(true);
    });

    test('validates file type', async () => {
      const fs = require('fs');
      const path = require('path');

      const textPath = path.join(__dirname, 'fixtures', 'test.txt');
      fs.writeFileSync(textPath, 'Not an image');

      const response = await authRequest
        .post('/api/users/profile/picture')
        .attach('picture', textPath)
        .expect(400);

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid file type. Only images are allowed'
      });

      fs.unlinkSync(textPath);
    });

    test('validates file size', async () => {
      const fs = require('fs');
      const path = require('path');

      // Create a large file (5MB)
      const largeFilePath = path.join(__dirname, 'fixtures', 'large.jpg');
      const buffer = Buffer.alloc(5 * 1024 * 1024); // 5MB
      fs.writeFileSync(largeFilePath, buffer);

      const response = await authRequest
        .post('/api/users/profile/picture')
        .attach('picture', largeFilePath)
        .expect(400);

      expect(response.body).toEqual({
        success: false,
        error: 'File too large. Maximum size is 2MB'
      });

      fs.unlinkSync(largeFilePath);
    });
  });

  describe('Webhook Tests', () => {
    test('processes valid webhook', async () => {
      const webhookPayload = {
        event: 'payment.completed',
        data: {
          paymentId: 'pay_123',
          amount: 1000,
          currency: 'USD'
        }
      };

      const signature = createWebhookSignature(webhookPayload);

      const response = await request(server)
        .post('/api/webhooks/payments')
        .set('X-Webhook-Signature', signature)
        .send(webhookPayload)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'Webhook processed'
      });
    });

    test('rejects invalid signature', async () => {
      const response = await request(server)
        .post('/api/webhooks/payments')
        .set('X-Webhook-Signature', 'invalid-signature')
        .send({ event: 'test' })
        .expect(401);

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid webhook signature'
      });
    });

    test('handles webhook retries', async () => {
      const webhookPayload = {
        event: 'payment.completed',
        data: { paymentId: 'pay_123' }
      };

      const signature = createWebhookSignature(webhookPayload);

      // First attempt fails
      let attempt = 1;
      const originalHandler = require('../../src/webhooks/paymentWebhook').default;
      jest.spyOn(require('../../src/webhooks/paymentWebhook'), 'default')
        .mockImplementation(() => {
          if (attempt++ < 3) {
            throw new Error('Temporary failure');
          }
          return originalHandler();
        });

      const response = await request(server)
        .post('/api/webhooks/payments')
        .set('X-Webhook-Signature', signature)
        .send(webhookPayload)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'Webhook processed'
      });
      expect(attempt).toBe(4); // 3 retries + 1 success
    });
  });
});

// Helper function for webhook signatures
function createWebhookSignature(payload) {
  const crypto = require('crypto');
  const secret = process.env.WEBHOOK_SECRET;
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(payload));
  return hmac.digest('hex');
}
```

### Advanced API Testing Patterns

```javascript
// tests/api/advanced-patterns.test.js
const { request, server } = require('../setup-api');

describe('Advanced API Testing Patterns', () => {
  describe('Concurrent Request Testing', () => {
    test('handles concurrent user creation', async () => {
      const userCount = 10;
      const requests = Array(userCount).fill().map((_, i) =>
        request(server)
          .post('/api/users')
          .send({
            email: `user${i}@example.com`,
            password: 'Password123!',
            name: `User ${i}`
          })
      );

      const responses = await Promise.allSettled(requests);
      
      // All requests should succeed
      const successful = responses.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      expect(successful).toHaveLength(userCount);
    });

    test('prevents race conditions in inventory', async () => {
      // Simulate concurrent purchases of limited inventory
      const productId = 'prod_123';
      const initialStock = 5;
      const concurrentPurchases = 10;

      // Setup product with limited stock
      await request(server)
        .post('/api/products')
        .send({
          id: productId,
          name: 'Test Product',
          stock: initialStock
        });

      const purchaseRequests = Array(concurrentPurchases).fill().map(() =>
        request(server)
          .post('/api/purchases')
          .send({
            productId,
            quantity: 1
          })
      );

      const responses = await Promise.allSettled(purchaseRequests);
      
      // Count successful purchases
      const successful = responses.filter(
        r => r.status === 'fulfilled' && r.value.status === 201
      );
      
      // Should not exceed initial stock
      expect(successful.length).toBeLessThanOrEqual(initialStock);
      
      // Check for proper error responses for failed purchases
      const failed = responses.filter(
        r => r.status === 'fulfilled' && r.value.status === 409
      );
      expect(failed.length).toBeGreaterThanOrEqual(concurrentPurchases - initialStock);
    });
  });

  describe('Performance Testing', () => {
    test('response time under load', async () => {
      const iterations = 100;
      const maxResponseTime = 100; // ms
      
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const response = await request(server)
          .get('/api/health')
          .expect(200);
        
        expect(response.body.status).toBe('healthy');
      }
      
      const totalTime = Date.now() - startTime;
      const averageTime = totalTime / iterations;
      
      expect(averageTime).toBeLessThan(maxResponseTime);
    });

    test('memory usage during batch processing', async () => {
      const batchSize = 1000;
      
      const initialMemory = process.memoryUsage().heapUsed;
      
      const response = await request(server)
        .post('/api/batch/process')
        .send({
          items: Array(batchSize).fill().map((_, i) => ({
            id: i,
            data: `item-${i}`
          }))
        })
        .expect(200);
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB
    });
  });

  describe('Security Testing', () => {
    test('SQL injection prevention', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      const response = await request(server)
        .get('/api/users')
        .query({ search: maliciousInput })
        .expect(400); // Should reject or sanitize
      
      expect(response.body.error).not.toContain('syntax error');
    });

    test('XSS prevention in responses', async () => {
      const xssPayload = '<script>alert("xss")</script>';
      
      const response = await request(server)
        .post('/api/comments')
        .send({ content: xssPayload })
        .expect(201);
      
      // Response should be sanitized
      expect(response.body.data.content).not.toContain('<script>');
      expect(response.body.data.content).toContain('&lt;script&gt;');
    });

    test('CSRF protection', async () => {
      const response = await request(server)
        .post('/api/sensitive-action')
        .set('Origin', 'https://malicious-site.com')
        .send({ action: 'transfer' })
        .expect(403);
      
      expect(response.body.error).toContain('CSRF');
    });

    test('mass assignment prevention', async () => {
      const response = await request(server)
        .post('/api/users')
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          name: 'Test User',
          role: 'admin', // Should not be assignable
          balance: 1000000 // Should not be assignable
        })
        .expect(201);
      
      // Check that protected fields were not set
      expect(response.body.data.role).not.toBe('admin');
      expect(response.body.data.balance).not.toBe(1000000);
    });
  });

  describe('Error Handling Tests', () => {
    test('graceful shutdown during request', async () => {
      const requestPromise = request(server)
        .get('/api/long-running')
        .timeout(5000);
      
      // Simulate server shutdown after 100ms
      setTimeout(() => {
        server.close();
      }, 100);
      
      // Request should either complete or fail gracefully
      await expect(requestPromise).resolves
        .toBeTruthy();
    });

    test('circuit breaker pattern', async () => {
      // Mock dependency to fail
      jest.spyOn(require('../../src/services/externalService'), 'call')
        .mockRejectedValue(new Error('Service unavailable'));
      
      // First few requests should fail
      for (let i = 0; i < 5; i++) {
        await request(server)
          .get('/api/dependent')
          .expect(500);
      }
      
      // Circuit should open - subsequent requests should fail fast
      const response = await request(server)
        .get('/api/dependent')
        .expect(503);
      
      expect(response.body.error).toContain('circuit open');
    });

    test('retry logic', async () => {
      let callCount = 0;
      jest.spyOn(require('../../src/services/flakyService'), 'call')
        .mockImplementation(() => {
          callCount++;
          if (callCount < 3) {
            throw new Error('Temporary failure');
          }
          return Promise.resolve('success');
        });
      
      const response = await request(server)
        .get('/api/with-retry')
        .expect(200);
      
      expect(response.body.data).toBe('success');
      expect(callCount).toBe(3);
    });
  });

  describe('Stateful Testing', () => {
    test('maintains session across requests', async () => {
      // Login
      const loginResponse = await request(server)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'Password123!'
        })
        .expect(200);
      
      const sessionCookie = loginResponse.headers['set-cookie'][0];
      
      // Use session in subsequent request
      const profileResponse = await request(server)
        .get('/api/profile')
        .set('Cookie', sessionCookie)
        .expect(200);
      
      expect(profileResponse.body.data.email).toBe('test@example.com');
    });

    test('handles session expiration', async () => {
      // Create short-lived session
      const jwt = require('jsonwebtoken');
      const expiredToken = jwt.sign(
        { id: 'user_123' },
        process.env.JWT_SECRET,
        { expiresIn: '-1s' }
      );
      
      const response = await request(server)
        .get('/api/profile')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
      
      expect(response.body.error).toContain('expired');
    });
  });

  describe('Contract Testing', () => {
    test('API response matches OpenAPI schema', async () => {
      const OpenAPISchemaValidator = require('openapi-schema-validator').default;
      const validator = new OpenAPISchemaValidator({ version: 3 });
      
      const response = await request(server)
        .get('/api/users')
        .expect(200);
      
      // Load OpenAPI schema
      const schema = require('../../openapi/schemas/UserList.yaml');
      
      // Validate response against schema
      const result = validator.validate(response.body, schema);
      
      expect(result.errors).toHaveLength(0);
    });

    test('deprecated API returns proper headers', async () => {
      const response = await request(server)
        .get('/api/v1/old-endpoint')
        .expect(200);
      
      expect(response.headers['deprecation']).toBe('true');
      expect(response.headers['sunset']).toMatch(/\d{4}-\d{2}-\d{2}/);
      expect(response.headers['link']).toContain('/api/v2/new-endpoint');
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does Supertest differ from directly testing Express apps with Jest? What are the advantages?"
2. "Explain how to test WebSocket endpoints with Supertest. What challenges might you face?"
3. "How would you test rate limiting in your API endpoints?"

**Scenario-Based Questions:**
1. "You need to test an endpoint that makes calls to third-party APIs. How would you mock these external dependencies?"
2. "Your API has a complex authentication flow with multiple token types. How would you structure these tests?"
3. "Users report that your API returns inconsistent error formats. How would you write tests to ensure consistency?"

**Real-World Challenge:**
> "Design a testing strategy for a payment processing API that: 1) Handles multiple payment methods (credit card, PayPal, crypto), 2) Implements idempotency keys, 3) Has webhook endpoints for payment status updates, 4) Integrates with fraud detection services, 5) Must be PCI-DSS compliant. Include tests for: Happy paths, error conditions, edge cases, security vulnerabilities, and performance under load."

---

## 3. Unit Testing Services <a name="unit-testing-services"></a>

### Overview
Unit testing services focuses on testing individual business logic components in isolation, ensuring they work correctly without external dependencies.

### Comprehensive Service Testing

```javascript
// tests/unit/services/UserService.test.js
const UserService = require('../../../src/services/UserService');
const EmailService = require('../../../src/services/EmailService');
const NotificationService = require('../../../src/services/NotificationService');
const { ValidationError, NotFoundError, ConflictError } = require('../../../src/utils/errors');

// Mock external dependencies
jest.mock('../../../src/services/EmailService');
jest.mock('../../../src/services/NotificationService');
jest.mock('../../../src/repositories/UserRepository');
const UserRepository = require('../../../src/repositories/UserRepository');

describe('UserService', () => {
  let userService;
  let mockUser;
  let mockUserData;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create service instance
    userService = new UserService();
    
    // Mock data
    mockUser = {
      id: 'user_123',
      email: 'test@example.com',
      name: 'Test User',
      password: 'hashed_password',
      role: 'user',
      status: 'active',
      emailVerified: false,
      createdAt: new Date('2024-01-01'),
      updatedAt: new Date('2024-01-01')
    };
    
    mockUserData = {
      email: 'test@example.com',
      password: 'Password123!',
      name: 'Test User',
      age: 25
    };
  });

  describe('createUser', () => {
    test('creates a user with valid data', async () => {
      // Mock repository
      UserRepository.findByEmail.mockResolvedValue(null);
      UserRepository.create.mockResolvedValue(mockUser);
      
      // Mock email service
      EmailService.sendWelcomeEmail.mockResolvedValue(true);
      
      // Execute
      const result = await userService.createUser(mockUserData);
      
      // Assertions
      expect(UserRepository.findByEmail).toHaveBeenCalledWith(mockUserData.email);
      expect(UserRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          email: mockUserData.email,
          name: mockUserData.name,
          age: mockUserData.age,
          password: expect.not.stringMatching(mockUserData.password) // Should be hashed
        })
      );
      
      expect(EmailService.sendWelcomeEmail).toHaveBeenCalledWith(
        mockUserData.email,
        expect.objectContaining({ name: mockUserData.name })
      );
      
      expect(result).toEqual(expect.objectContaining({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name
      }));
    });

    test('throws ValidationError for invalid email', async () => {
      const invalidData = { ...mockUserData, email: 'invalid-email' };
      
      await expect(userService.createUser(invalidData))
        .rejects
        .toThrow(ValidationError);
      
      expect(UserRepository.findByEmail).not.toHaveBeenCalled();
      expect(UserRepository.create).not.toHaveBeenCalled();
    });

    test('throws ConflictError for duplicate email', async () => {
      UserRepository.findByEmail.mockResolvedValue(mockUser);
      
      await expect(userService.createUser(mockUserData))
        .rejects
        .toThrow(ConflictError);
      
      expect(UserRepository.create).not.toHaveBeenCalled();
    });

    test('handles email service failure gracefully', async () => {
      UserRepository.findByEmail.mockResolvedValue(null);
      UserRepository.create.mockResolvedValue(mockUser);
      EmailService.sendWelcomeEmail.mockRejectedValue(new Error('SMTP error'));
      
      // Should still create user even if email fails
      const result = await userService.createUser(mockUserData);
      
      expect(result).toBeDefined();
      expect(UserRepository.create).toHaveBeenCalled();
    });

    test('generates unique username from email', async () => {
      const userWithNoName = { ...mockUserData, name: undefined };
      UserRepository.findByEmail.mockResolvedValue(null);
      UserRepository.create.mockImplementation((data) => ({
        ...mockUser,
        ...data
      }));
      
      const result = await userService.createUser(userWithNoName);
      
      expect(result.username).toBeDefined();
      expect(result.username).toMatch(/^test\d*$/); // From test@example.com
    });
  });

  describe('authenticateUser', () => {
    const credentials = {
      email: 'test@example.com',
      password: 'Password123!'
    };

    test('authenticates user with valid credentials', async () => {
      // Mock password verification
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      
      UserRepository.findByEmail.mockResolvedValue({
        ...mockUser,
        password: 'hashed_password'
      });
      
      const result = await userService.authenticateUser(credentials);
      
      expect(bcrypt.compare).toHaveBeenCalledWith(
        credentials.password,
        'hashed_password'
      );
      expect(result).toMatchObject({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name
      });
    });

    test('throws ValidationError for invalid credentials format', async () => {
      const invalidCredentials = { email: 'invalid', password: '123' };
      
      await expect(userService.authenticateUser(invalidCredentials))
        .rejects
        .toThrow(ValidationError);
    });

    test('throws NotFoundError for non-existent user', async () => {
      UserRepository.findByEmail.mockResolvedValue(null);
      
      await expect(userService.authenticateUser(credentials))
        .rejects
        .toThrow(NotFoundError);
    });

    test('throws ValidationError for incorrect password', async () => {
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
      
      UserRepository.findByEmail.mockResolvedValue(mockUser);
      
      await expect(userService.authenticateUser(credentials))
        .rejects
        .toThrow(ValidationError);
    });

    test('tracks failed login attempts', async () => {
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
      
      UserRepository.findByEmail.mockResolvedValue(mockUser);
      UserRepository.incrementFailedAttempts = jest.fn();
      UserRepository.lockAccount = jest.fn();
      
      try {
        await userService.authenticateUser(credentials);
      } catch (error) {
        // Expected
      }
      
      expect(UserRepository.incrementFailedAttempts).toHaveBeenCalledWith(mockUser.id);
      
      // Simulate multiple failed attempts
      UserRepository.findByEmail.mockResolvedValue({
        ...mockUser,
        failedAttempts: 5
      });
      
      await expect(userService.authenticateUser(credentials))
        .rejects
        .toThrow('Account locked');
      
      expect(UserRepository.lockAccount).toHaveBeenCalledWith(mockUser.id);
    });
  });

  describe('updateUserProfile', () => {
    const userId = 'user_123';
    const updates = {
      name: 'Updated Name',
      age: 30,
      bio: 'New bio'
    };

    test('updates user profile successfully', async () => {
      UserRepository.findById.mockResolvedValue(mockUser);
      UserRepository.update.mockResolvedValue({
        ...mockUser,
        ...updates,
        updatedAt: new Date()
      });
      
      const result = await userService.updateUserProfile(userId, updates);
      
      expect(UserRepository.findById).toHaveBeenCalledWith(userId);
      expect(UserRepository.update).toHaveBeenCalledWith(
        userId,
        expect.objectContaining(updates)
      );
      expect(result).toMatchObject(updates);
    });

    test('validates update data', async () => {
      const invalidUpdates = { age: -5 };
      
      await expect(userService.updateUserProfile(userId, invalidUpdates))
        .rejects
        .toThrow(ValidationError);
    });

    test('throws NotFoundError for non-existent user', async () => {
      UserRepository.findById.mockResolvedValue(null);
      
      await expect(userService.updateUserProfile(userId, updates))
        .rejects
        .toThrow(NotFoundError);
    });

    test('sanitizes HTML in bio field', async () => {
      const maliciousBio = '<script>alert("xss")</script>Safe text';
      
      UserRepository.findById.mockResolvedValue(mockUser);
      UserRepository.update.mockImplementation((id, data) => ({
        ...mockUser,
        ...data
      }));
      
      const result = await userService.updateUserProfile(userId, {
        bio: maliciousBio
      });
      
      expect(result.bio).not.toContain('<script>');
      expect(result.bio).toContain('Safe text');
    });

    test('handles concurrent updates with optimistic locking', async () => {
      UserRepository.findById.mockResolvedValue({
        ...mockUser,
        version: 1
      });
      
      UserRepository.update.mockImplementation((id, data) => {
        if (data.version !== 1) {
          throw new Error('Version mismatch');
        }
        return {
          ...mockUser,
          ...data,
          version: 2
        };
      });
      
      const result = await userService.updateUserProfile(userId, {
        ...updates,
        version: 1
      });
      
      expect(result.version).toBe(2);
    });
  });

  describe('deleteUser', () => {
    const userId = 'user_123';
    const adminId = 'admin_123';

    test('soft deletes user for admin', async () => {
      UserRepository.findById.mockResolvedValue(mockUser);
      UserRepository.softDelete.mockResolvedValue(true);
      NotificationService.notifyUserDeletion = jest.fn();
      
      const result = await userService.deleteUser(userId, adminId);
      
      expect(UserRepository.softDelete).toHaveBeenCalledWith(userId);
      expect(NotificationService.notifyUserDeletion).toHaveBeenCalledWith(
        mockUser,
        adminId
      );
      expect(result).toBe(true);
    });

    test('throws NotFoundError for non-existent user', async () => {
      UserRepository.findById.mockResolvedValue(null);
      
      await expect(userService.deleteUser(userId, adminId))
        .rejects
        .toThrow(NotFoundError);
    });

    test('prevents self-deletion', async () => {
      await expect(userService.deleteUser(userId, userId))
        .rejects
        .toThrow(ValidationError);
    });

    test('performs cascading deletion', async () => {
      UserRepository.findById.mockResolvedValue(mockUser);
      UserRepository.softDelete.mockResolvedValue(true);
      
      // Mock related services
      const PostService = require('../../../src/services/PostService');
      const CommentService = require('../../../src/services/CommentService');
      
      jest.spyOn(PostService.prototype, 'deleteUserPosts').mockResolvedValue();
      jest.spyOn(CommentService.prototype, 'deleteUserComments').mockResolvedValue();
      
      await userService.deleteUser(userId, adminId);
      
      expect(PostService.prototype.deleteUserPosts).toHaveBeenCalledWith(userId);
      expect(CommentService.prototype.deleteUserComments).toHaveBeenCalledWith(userId);
    });
  });

  describe('searchUsers', () => {
    const filters = {
      role: 'user',
      status: 'active',
      ageMin: 20,
      ageMax: 40
    };
    const pagination = {
      page: 1,
      limit: 20,
      sort: 'createdAt',
      order: 'desc'
    };

    test('searches users with filters', async () => {
      const mockUsers = [mockUser];
      const mockTotal = 1;
      
      UserRepository.search.mockResolvedValue({
        users: mockUsers,
        total: mockTotal
      });
      
      const result = await userService.searchUsers(filters, pagination);
      
      expect(UserRepository.search).toHaveBeenCalledWith(
        expect.objectContaining(filters),
        expect.objectContaining(pagination)
      );
      
      expect(result).toEqual({
        data: expect.arrayContaining([
          expect.objectContaining({
            id: mockUser.id,
            email: mockUser.email
          })
        ]),
        pagination: {
          page: pagination.page,
          limit: pagination.limit,
          total: mockTotal,
          pages: Math.ceil(mockTotal / pagination.limit)
        }
      });
    });

    test('sanitizes search filters', async () => {
      const maliciousFilters = {
        role: { $ne: null }, // NoSQL injection attempt
        status: 'active'
      };
      
      UserRepository.search.mockResolvedValue({ users: [], total: 0 });
      
      await userService.searchUsers(maliciousFilters, pagination);
      
      // Repository should receive sanitized filters
      expect(UserRepository.search).toHaveBeenCalledWith(
        expect.not.objectContaining({
          role: { $ne: null }
        }),
        expect.any(Object)
      );
    });

    test('applies default pagination', async () => {
      UserRepository.search.mockResolvedValue({ users: [], total: 0 });
      
      await userService.searchUsers({}, {});
      
      expect(UserRepository.search).toHaveBeenCalledWith(
        {},
        expect.objectContaining({
          page: 1,
          limit: 20,
          sort: 'createdAt',
          order: 'desc'
        })
      );
    });

    test('caches search results', async () => {
      const cacheService = require('../../../src/services/CacheService');
      const cacheKey = `users:search:${JSON.stringify(filters)}:${JSON.stringify(pagination)}`;
      
      UserRepository.search.mockResolvedValue({
        users: [mockUser],
        total: 1
      });
      
      // First call - cache miss
      await userService.searchUsers(filters, pagination);
      expect(UserRepository.search).toHaveBeenCalledTimes(1);
      expect(cacheService.set).toHaveBeenCalledWith(
        cacheKey,
        expect.any(Object),
        300 // 5 minutes TTL
      );
      
      // Second call - cache hit
      cacheService.get.mockResolvedValue({
        data: [mockUser],
        pagination: { page: 1, limit: 20, total: 1, pages: 1 }
      });
      
      await userService.searchUsers(filters, pagination);
      expect(UserRepository.search).toHaveBeenCalledTimes(1); // Still 1
    });
  });

  describe('User Statistics', () => {
    test('calculates user statistics', async () => {
      const mockStats = {
        total: 100,
        active: 80,
        verified: 75,
        byRole: { user: 70, admin: 10, moderator: 20 },
        growth: [10, 15, 20, 25, 30]
      };
      
      UserRepository.getStatistics.mockResolvedValue(mockStats);
      
      const result = await userService.getStatistics();
      
      expect(result).toEqual({
        ...mockStats,
        verificationRate: 75, // 75/100 * 100
        activityRate: 80 // 80/100 * 100
      });
    });

    test('handles empty statistics', async () => {
      UserRepository.getStatistics.mockResolvedValue({
        total: 0,
        active: 0,
        verified: 0,
        byRole: {},
        growth: []
      });
      
      const result = await userService.getStatistics();
      
      expect(result.verificationRate).toBe(0);
      expect(result.activityRate).toBe(0);
    });
  });

  describe('Batch Operations', () => {
    test('processes batch user updates', async () => {
      const updates = [
        { id: 'user_1', status: 'active' },
        { id: 'user_2', status: 'inactive' },
        { id: 'user_3', status: 'suspended' }
      ];
      
      UserRepository.batchUpdate.mockResolvedValue({
        success: 3,
        failed: 0,
        errors: []
      });
      
      const result = await userService.batchUpdateUsers(updates);
      
      expect(UserRepository.batchUpdate).toHaveBeenCalledWith(updates);
      expect(result.success).toBe(3);
      expect(result.failed).toBe(0);
    });

    test('handles partial failures in batch operations', async () => {
      const updates = [
        { id: 'user_1', status: 'active' },
        { id: 'invalid_user', status: 'active' },
        { id: 'user_3', status: 'active' }
      ];
      
      UserRepository.batchUpdate.mockResolvedValue({
        success: 2,
        failed: 1,
        errors: [{ id: 'invalid_user', error: 'User not found' }]
      });
      
      const result = await userService.batchUpdateUsers(updates);
      
      expect(result.success).toBe(2);
      expect(result.failed).toBe(1);
      expect(result.errors).toHaveLength(1);
    });

    test('validates batch operation size', async () => {
      const largeBatch = Array(1001).fill().map((_, i) => ({
        id: `user_${i}`,
        status: 'active'
      }));
      
      await expect(userService.batchUpdateUsers(largeBatch))
        .rejects
        .toThrow(ValidationError);
    });
  });

  describe('Event-Driven Operations', () => {
    test('emits events on user actions', async () => {
      const eventBus = require('../../../src/events/EventBus');
      const emitSpy = jest.spyOn(eventBus, 'emit');
      
      UserRepository.findByEmail.mockResolvedValue(null);
      UserRepository.create.mockResolvedValue(mockUser);
      
      await userService.createUser(mockUserData);
      
      expect(emitSpy).toHaveBeenCalledWith(
        'user.created',
        expect.objectContaining({
          userId: mockUser.id,
          email: mockUser.email
        })
      );
    });

    test('handles event listeners', async () => {
      // Mock event listener
      const mockListener = jest.fn();
      const eventBus = require('../../../src/events/EventBus');
      
      eventBus.on('user.updated', mockListener);
      
      UserRepository.findById.mockResolvedValue(mockUser);
      UserRepository.update.mockResolvedValue({
        ...mockUser,
        name: 'Updated Name'
      });
      
      await userService.updateUserProfile(mockUser.id, { name: 'Updated Name' });
      
      expect(mockListener).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          oldName: 'Test User',
          newName: 'Updated Name'
        })
      );
    });
  });

  describe('Performance Optimization', () => {
    test('uses connection pooling efficiently', async () => {
      const pool = require('../../../src/database/pool');
      const acquireSpy = jest.spyOn(pool, 'acquire');
      const releaseSpy = jest.spyOn(pool, 'release');
      
      UserRepository.search.mockResolvedValue({ users: [], total: 0 });
      
      await userService.searchUsers({}, {});
      
      expect(acquireSpy).toHaveBeenCalled();
      expect(releaseSpy).toHaveBeenCalled();
    });

    test('implements query optimization', async () => {
      const complexFilters = {
        role: 'user',
        status: 'active',
        lastLoginAfter: new Date('2024-01-01'),
        hasProfilePicture: true
      };
      
      UserRepository.search.mockResolvedValue({ users: [], total: 0 });
      
      await userService.searchUsers(complexFilters, {});
      
      // Should use indexed fields first
      expect(UserRepository.search).toHaveBeenCalledWith(
        expect.objectContaining({
          role: 'user',
          status: 'active'
        }),
        expect.any(Object)
      );
    });
  });
});

// tests/unit/services/PaymentService.test.js
const PaymentService = require('../../../src/services/PaymentService');
const StripeService = require('../../../src/services/StripeService');
const PayPalService = require('../../../src/services/PayPalService');
const CryptoPaymentService = require('../../../src/services/CryptoPaymentService');

jest.mock('../../../src/services/StripeService');
jest.mock('../../../src/services/PayPalService');
jest.mock('../../../src/services/CryptoPaymentService');

describe('PaymentService', () => {
  let paymentService;
  let mockPayment;
  let mockPaymentData;

  beforeEach(() => {
    jest.clearAllMocks();
    paymentService = new PaymentService();
    
    mockPayment = {
      id: 'pay_123',
      amount: 1000,
      currency: 'USD',
      status: 'pending',
      method: 'credit_card',
      userId: 'user_123',
      createdAt: new Date()
    };
    
    mockPaymentData = {
      amount: 1000,
      currency: 'USD',
      method: 'credit_card',
      source: 'tok_visa',
      userId: 'user_123',
      metadata: {
        orderId: 'order_456',
        description: 'Test payment'
      }
    };
  });

  describe('processPayment', () => {
    test('processes credit card payment successfully', async () => {
      StripeService.createCharge.mockResolvedValue({
        id: 'ch_123',
        status: 'succeeded',
        amount: mockPaymentData.amount
      });
      
      const result = await paymentService.processPayment(mockPaymentData);
      
      expect(StripeService.createCharge).toHaveBeenCalledWith(
        expect.objectContaining({
          amount: mockPaymentData.amount,
          source: mockPaymentData.source,
          metadata: mockPaymentData.metadata
        })
      );
      
      expect(result).toMatchObject({
        id: expect.any(String),
        status: 'completed',
        amount: mockPaymentData.amount
      });
    });

    test('processes PayPal payment', async () => {
      const paypalData = {
        ...mockPaymentData,
        method: 'paypal',
        paypalOrderId: 'PAYPAL_123'
      };
      
      PayPalService.captureOrder.mockResolvedValue({
        id: 'CAPTURE_123',
        status: 'COMPLETED'
      });
      
      const result = await paymentService.processPayment(paypalData);
      
      expect(PayPalService.captureOrder).toHaveBeenCalledWith(
        paypalData.paypalOrderId
      );
      expect(result.method).toBe('paypal');
    });

    test('processes cryptocurrency payment', async () => {
      const cryptoData = {
        ...mockPaymentData,
        method: 'crypto',
        cryptocurrency: 'BTC',
        walletAddress: '1ABC...'
      };
      
      CryptoPaymentService.createInvoice.mockResolvedValue({
        id: 'CRYPTO_123',
        address: '1ABC...',
        amount: '0.001'
      });
      
      const result = await paymentService.processPayment(cryptoData);
      
      expect(CryptoPaymentService.createInvoice).toHaveBeenCalledWith(
        expect.objectContaining({
          amount: cryptoData.amount,
          currency: cryptoData.currency,
          cryptocurrency: cryptoData.cryptocurrency
        })
      );
      expect(result.status).toBe('pending');
    });

    test('implements idempotency', async () => {
      const idempotencyKey = 'idemp_123';
      
      StripeService.createCharge.mockResolvedValue({
        id: 'ch_123',
        status: 'succeeded'
      });
      
      // First request
      await paymentService.processPayment({
        ...mockPaymentData,
        idempotencyKey
      });
      
      // Second identical request should return cached result
      const result = await paymentService.processPayment({
        ...mockPaymentData,
        idempotencyKey
      });
      
      expect(StripeService.createCharge).toHaveBeenCalledTimes(1);
      expect(result).toHaveProperty('idempotent', true);
    });

    test('handles payment failures gracefully', async () => {
      StripeService.createCharge.mockRejectedValue(
        new Error('Card declined')
      );
      
      const result = await paymentService.processPayment(mockPaymentData);
      
      expect(result.status).toBe('failed');
      expect(result.error).toBe('Card declined');
    });

    test('validates payment amount limits', async () => {
      const largePayment = {
        ...mockPaymentData,
        amount: 10000000 // $100,000
      };
      
      await expect(paymentService.processPayment(largePayment))
        .rejects
        .toThrow('Payment amount exceeds limit');
    });

    test('applies currency conversion', async () => {
      const foreignPayment = {
        ...mockPaymentData,
        amount: 1000,
        currency: 'EUR'
      };
      
      const exchangeService = require('../../../src/services/ExchangeService');
      exchangeService.convert.mockResolvedValue(1100); // EUR to USD
      
      StripeService.createCharge.mockResolvedValue({
        id: 'ch_123',
        status: 'succeeded',
        amount: 1100
      });
      
      await paymentService.processPayment(foreignPayment);
      
      expect(exchangeService.convert).toHaveBeenCalledWith(
        1000,
        'EUR',
        'USD'
      );
      expect(StripeService.createCharge).toHaveBeenCalledWith(
        expect.objectContaining({
          amount: 1100,
          currency: 'USD'
        })
      );
    });
  });

  describe('refundPayment', () => {
    test('refunds successful payment', async () => {
      const paymentId = 'pay_123';
      const refundAmount = 500;
      
      StripeService.createRefund.mockResolvedValue({
        id: 're_123',
        status: 'succeeded',
        amount: refundAmount
      });
      
      const result = await paymentService.refundPayment(paymentId, refundAmount);
      
      expect(StripeService.createRefund).toHaveBeenCalledWith(
        paymentId,
        refundAmount
      );
      expect(result.status).toBe('refunded');
    });

    test('prevents double refund', async () => {
      const paymentId = 'pay_123';
      
      // Mock payment as already refunded
      jest.spyOn(paymentService, 'getPayment').mockResolvedValue({
        status: 'refunded'
      });
      
      await expect(paymentService.refundPayment(paymentId, 500))
        .rejects
        .toThrow('Payment already refunded');
    });

    test('partial refund with limits', async () => {
      const paymentId = 'pay_123';
      const refundAmount = 1500; // More than payment amount
      
      jest.spyOn(paymentService, 'getPayment').mockResolvedValue({
        amount: 1000,
        status: 'completed'
      });
      
      await expect(paymentService.refundPayment(paymentId, refundAmount))
        .rejects
        .toThrow('Refund amount exceeds payment amount');
    });
  });

  describe('fraudDetection', () => {
    test('detects suspicious payment patterns', async () => {
      const fraudService = require('../../../src/services/FraudDetectionService');
      fraudService.analyzePayment.mockResolvedValue({
        riskScore: 85,
        reasons: ['High amount', 'New device', 'Unusual location']
      });
      
      const result = await paymentService.processPayment({
        ...mockPaymentData,
        amount: 5000,
        ip: '185.86.151.11', // Suspicious IP
        userAgent: 'Mozilla/5.0 (compatible; suspicious-bot/1.0)'
      });
      
      expect(fraudService.analyzePayment).toHaveBeenCalled();
      expect(result.riskScore).toBe(85);
      expect(result.status).toBe('review');
    });

    test('implements velocity checking', async () => {
      const paymentHistory = Array(10).fill().map((_, i) => ({
        id: `pay_${i}`,
        amount: 100,
        createdAt: new Date(Date.now() - i * 60000) // Last 10 minutes
      }));
      
      jest.spyOn(paymentService, 'getUserPaymentHistory').mockResolvedValue(paymentHistory);
      
      await expect(paymentService.processPayment(mockPaymentData))
        .rejects
        .toThrow('Too many payments in short period');
    });
  });
});

// tests/unit/services/NotificationService.test.js
const NotificationService = require('../../../src/services/NotificationService');

describe('NotificationService', () => {
  let notificationService;
  let mockUser;
  let mockNotification;

  beforeEach(() => {
    notificationService = new NotificationService();
    
    mockUser = {
      id: 'user_123',
      email: 'test@example.com',
      phone: '+1234567890',
      preferences: {
        email: true,
        sms: false,
        push: true,
        inApp: true
      }
    };
    
    mockNotification = {
      type: 'welcome',
      title: 'Welcome!',
      message: 'Welcome to our service',
      data: { userId: 'user_123' }
    };
  });

  describe('sendNotification', () => {
    test('sends email notification when enabled', async () => {
      const emailService = require('../../../src/services/EmailService');
      emailService.send.mockResolvedValue(true);
      
      await notificationService.sendNotification(mockUser, mockNotification);
      
      expect(emailService.send).toHaveBeenCalledWith(
        mockUser.email,
        expect.objectContaining({
          subject: mockNotification.title,
          body: mockNotification.message
        })
      );
    });

    test('sends SMS notification when enabled', async () => {
      const userWithSMS = {
        ...mockUser,
        preferences: { ...mockUser.preferences, sms: true }
      };
      
      const smsService = require('../../../src/services/SmsService');
      smsService.send.mockResolvedValue(true);
      
      await notificationService.sendNotification(userWithSMS, mockNotification);
      
      expect(smsService.send).toHaveBeenCalledWith(
        userWithSMS.phone,
        mockNotification.message
      );
    });

    test('sends push notification when enabled', async () => {
      const pushService = require('../../../src/services/PushNotificationService');
      pushService.send.mockResolvedValue(true);
      
      await notificationService.sendNotification(mockUser, mockNotification);
      
      expect(pushService.send).toHaveBeenCalledWith(
        mockUser.id,
        expect.objectContaining({
          title: mockNotification.title,
          body: mockNotification.message
        })
      );
    });

    test('stores in-app notification', async () => {
      const notificationRepo = require('../../../src/repositories/NotificationRepository');
      notificationRepo.create.mockResolvedValue({
        id: 'notif_123',
        ...mockNotification
      });
      
      await notificationService.sendNotification(mockUser, mockNotification);
      
      expect(notificationRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          type: mockNotification.type,
          title: mockNotification.title,
          message: mockNotification.message,
          read: false
        })
      );
    });

    test('respects user preferences', async () => {
      const userWithNoNotifications = {
        ...mockUser,
        preferences: {
          email: false,
          sms: false,
          push: false,
          inApp: false
        }
      };
      
      const emailService = require('../../../src/services/EmailService');
      const smsService = require('../../../src/services/SmsService');
      const pushService = require('../../../src/services/PushNotificationService');
      
      await notificationService.sendNotification(
        userWithNoNotifications,
        mockNotification
      );
      
      expect(emailService.send).not.toHaveBeenCalled();
      expect(smsService.send).not.toHaveBeenCalled();
      expect(pushService.send).not.toHaveBeenCalled();
    });

    test('handles notification failures gracefully', async () => {
      const emailService = require('../../../src/services/EmailService');
      emailService.send.mockRejectedValue(new Error('SMTP error'));
      
      // Should not throw, other channels should still work
      await expect(
        notificationService.sendNotification(mockUser, mockNotification)
      ).resolves.not.toThrow();
    });

    test('implements notification deduplication', async () => {
      const duplicateNotification = { ...mockNotification };
      
      // First notification
      await notificationService.sendNotification(mockUser, mockNotification);
      
      // Second identical notification within short period
      await notificationService.sendNotification(mockUser, duplicateNotification);
      
      // Should be deduplicated
      const notificationRepo = require('../../../src/repositories/NotificationRepository');
      expect(notificationRepo.create).toHaveBeenCalledTimes(1);
    });

    test('localizes notifications', async () => {
      const userWithLocale = {
        ...mockUser,
        locale: 'es-ES'
      };
      
      const localizedNotification = {
        ...mockNotification,
        title: '¡Bienvenido!',
        message: 'Bienvenido a nuestro servicio'
      };
      
      const localizationService = require('../../../src/services/LocalizationService');
      localizationService.translateNotification.mockResolvedValue(
        localizedNotification
      );
      
      await notificationService.sendNotification(
        userWithLocale,
        mockNotification
      );
      
      expect(localizationService.translateNotification).toHaveBeenCalledWith(
        mockNotification,
        'es-ES'
      );
    });
  });

  describe('batchNotifications', () => {
    test('sends batch notifications efficiently', async () => {
      const users = Array(100).fill().map((_, i) => ({
        id: `user_${i}`,
        email: `user${i}@example.com`,
        preferences: { email: true }
      }));
      
      const notification = {
        type: 'announcement',
        title: 'Important Announcement',
        message: 'Service maintenance scheduled'
      };
      
      await notificationService.sendBatchNotification(users, notification);
      
      // Should use batch email sending
      const emailService = require('../../../src/services/EmailService');
      expect(emailService.sendBatch).toHaveBeenCalledWith(
        expect.arrayContaining(
          users.map(user => expect.objectContaining({
            to: user.email,
            subject: notification.title
          }))
        )
      );
    });

    test('chunks large batches', async () => {
      const users = Array(10000).fill().map((_, i) => ({
        id: `user_${i}`,
        email: `user${i}@example.com`,
        preferences: { email: true }
      }));
      
      await notificationService.sendBatchNotification(users, mockNotification);
      
      // Should chunk into smaller batches
      const emailService = require('../../../src/services/EmailService');
      expect(emailService.sendBatch).toHaveBeenCalledTimes(
        Math.ceil(users.length / 1000) // Default chunk size
      );
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How do you decide what to mock in unit tests vs what to test with real dependencies?"
2. "Explain the difference between stubs, spies, and mocks. When would you use each?"
3. "How do you test private methods in a class? Should you test them at all?"

**Scenario-Based Questions:**
1. "You have a service that calls multiple external APIs. How would you test it to ensure resilience?"
2. "Your service has a complex state machine. How would you test all possible state transitions?"
3. "A service method has multiple side effects. How would you ensure all side effects are properly tested?"

**Real-World Challenge:**
> "Design a comprehensive testing strategy for an e-commerce order processing service that: 1) Validates inventory, 2) Calculates taxes and shipping, 3) Processes payments, 4) Updates inventory, 5) Sends notifications, 6) Handles cancellations and refunds, 7) Integrates with fulfillment services. Include tests for: Normal flow, edge cases, error conditions, race conditions, and performance."

---

## 4. Integration Testing <a name="integration-testing"></a>

### Overview
Integration testing verifies that different modules or services work together correctly, testing the interactions between components.

### Comprehensive Integration Testing

```javascript
// tests/integration/database.test.js
const mongoose = require('mongoose');
const Redis = require('ioredis');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../../src/models/User');
const Order = require('../../src/models/Order');
const Product = require('../../src/models/Product');
const CacheService = require('../../src/services/CacheService');

describe('Database Integration Tests', () => {
  let mongoServer;
  let mongoConnection;
  let redisClient;
  let cacheService;

  beforeAll(async () => {
    // Start MongoDB memory server
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    // Connect to test database
    mongoConnection = await mongoose.createConnection(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    // Initialize models with test connection
    User.init(mongoConnection);
    Order.init(mongoConnection);
    Product.init(mongoConnection);
    
    // Connect to Redis
    redisClient = new Redis({
      host: 'localhost',
      port: 6379,
      db: 2, // Separate DB for integration tests
    });
    
    // Create cache service
    cacheService = new CacheService(redisClient);
  });

  afterAll(async () => {
    // Cleanup
    await mongoConnection.close();
    await mongoServer.stop();
    await redisClient.quit();
  });

  beforeEach(async () => {
    // Clear all collections
    await User.deleteMany({});
    await Order.deleteMany({});
    await Product.deleteMany({});
    
    // Clear Redis
    await redisClient.flushdb();
  });

  describe('MongoDB Transactions', () => {
    test('maintains data consistency with transactions', async () => {
      const session = await mongoConnection.startSession();
      
      try {
        session.startTransaction();
        
        // Create user
        const user = await User.create([{
          email: 'test@example.com',
          password: 'hashed_password',
          name: 'Test User'
        }], { session });
        
        // Create product
        const product = await Product.create([{
          name: 'Test Product',
          price: 100,
          stock: 10
        }], { session });
        
        // Create order
        await Order.create([{
          userId: user[0]._id,
          products: [{
            productId: product[0]._id,
            quantity: 2,
            price: product[0].price
          }],
          total: 200,
          status: 'pending'
        }], { session });
        
        // Update product stock
        await Product.findByIdAndUpdate(
          product[0]._id,
          { $inc: { stock: -2 } },
          { session }
        );
        
        await session.commitTransaction();
        
        // Verify data consistency
        const updatedProduct = await Product.findById(product[0]._id);
        const createdOrder = await Order.findOne({ userId: user[0]._id });
        
        expect(updatedProduct.stock).toBe(8);
        expect(createdOrder.total).toBe(200);
        expect(createdOrder.products).toHaveLength(1);
        
      } catch (error) {
        await session.abortTransaction();
        throw error;
      } finally {
        await session.endSession();
      }
    });

    test('rolls back transaction on error', async () => {
      const session = await mongoConnection.startSession();
      
      try {
        session.startTransaction();
        
        // Create user
        await User.create([{
          email: 'test@example.com',
          password: 'hashed_password',
          name: 'Test User'
        }], { session });
        
        // This should fail due to validation
        await Product.create([{
          name: 'Test Product',
          price: -100, // Invalid price
          stock: 10
        }], { session });
        
        await session.commitTransaction();
        
      } catch (error) {
        await session.abortTransaction();
        // Expected error
      } finally {
        await session.endSession();
      }
      
      // Verify no data was persisted
      const userCount = await User.countDocuments();
      const productCount = await Product.countDocuments();
      
      expect(userCount).toBe(0);
      expect(productCount).toBe(0);
    });
  });

  describe('Database Indexes', () => {
    test('uses indexes for efficient queries', async () => {
      // Create test users
      const users = Array(1000).fill().map((_, i) => ({
        email: `user${i}@example.com`,
        password: 'hashed_password',
        name: `User ${i}`,
        age: 20 + (i % 50),
        createdAt: new Date(Date.now() - i * 1000)
      }));
      
      await User.insertMany(users);
      
      // Query with indexed field
      const startTime = Date.now();
      const result = await User.find({ email: 'user500@example.com' });
      const queryTime = Date.now() - startTime;
      
      expect(result).toHaveLength(1);
      expect(queryTime).toBeLessThan(100); // Should be fast with index
    });

    test('composite indexes work correctly', async () => {
      // Create orders with different statuses and dates
      const orders = Array(500).fill().map((_, i) => ({
        userId: new mongoose.Types.ObjectId(),
        status: i % 2 === 0 ? 'completed' : 'pending',
        total: 100 + (i % 10),
        createdAt: new Date(Date.now() - i * 10000)
      }));
      
      await Order.insertMany(orders);
      
      // Query using composite index (status + createdAt)
      const explain = await Order.find({
        status: 'completed',
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }).explain('executionStats');
      
      // Verify index was used
      expect(explain.executionStats.executionStages.inputStage.stage).toBe('IXSCAN');
    });
  });

  describe('Database Constraints', () => {
    test('enforces unique constraints', async () => {
      // Create first user
      await User.create({
        email: 'unique@example.com',
        password: 'hashed_password',
        name: 'User One'
      });
      
      // Attempt to create duplicate
      await expect(
        User.create({
          email: 'unique@example.com', // Same email
          password: 'hashed_password',
          name: 'User Two'
        })
      ).rejects.toThrow(/duplicate key error/);
    });

    test('enforces referential integrity', async () => {
      const userId = new mongoose.Types.ObjectId();
      
      // Attempt to create order with non-existent user
      await expect(
        Order.create({
          userId,
          products: [],
          total: 100,
          status: 'pending'
        })
      ).rejects.toThrow(); // Should fail due to foreign key constraint
    });

    test('validates data types', async () => {
      await expect(
        User.create({
          email: 'test@example.com',
          password: 'hashed_password',
          name: 'Test User',
          age: 'not-a-number' // Invalid type
        })
      ).rejects.toThrow(/validation failed/);
    });
  });

  describe('Redis Integration', () => {
    test('caches database queries', async () => {
      // Create test user
      const user = await User.create({
        email: 'cache@example.com',
        password: 'hashed_password',
        name: 'Cached User'
      });
      
      // First query - cache miss
      const startTime1 = Date.now();
      const result1 = await cacheService.cacheQuery(
        `user:${user._id}`,
        () => User.findById(user._id),
        60 // 60 seconds TTL
      );
      const time1 = Date.now() - startTime1;
      
      expect(result1.email).toBe('cache@example.com');
      
      // Second query - cache hit
      const startTime2 = Date.now();
      const result2 = await cacheService.cacheQuery(
        `user:${user._id}`,
        () => User.findById(user._id),
        60
      );
      const time2 = Date.now() - startTime2;
      
      expect(result2.email).toBe('cache@example.com');
      expect(time2).toBeLessThan(time1); // Should be faster
      
      // Verify cache was used
      const cacheKey = `user:${user._id}`;
      const cachedData = await redisClient.get(cacheKey);
      expect(cachedData).toBeTruthy();
    });

    test('invalidates cache on update', async () => {
      const user = await User.create({
        email: 'cache@example.com',
        password: 'hashed_password',
        name: 'Original Name'
      });
      
      // Cache the user
      await cacheService.cacheQuery(
        `user:${user._id}`,
        () => User.findById(user._id),
        60
      );
      
      // Update user
      await User.findByIdAndUpdate(user._id, {
        name: 'Updated Name'
      });
      
      // Invalidate cache
      await cacheService.invalidate(`user:${user._id}`);
      
      // Query should get fresh data
      const updatedUser = await cacheService.cacheQuery(
        `user:${user._id}`,
        () => User.findById(user._id),
        60
      );
      
      expect(updatedUser.name).toBe('Updated Name');
    });

    test('handles cache stampede', async () => {
      const user = await User.create({
        email: 'stampede@example.com',
        password: 'hashed_password',
        name: 'Stampede User'
      });
      
      // Simulate concurrent cache misses
      const concurrentQueries = Array(10).fill().map(() =>
        cacheService.cacheQuery(
          `user:${user._id}`,
          () => User.findById(user._id),
          60
        )
      );
      
      const results = await Promise.all(concurrentQueries);
      
      // All should return same data
      results.forEach(result => {
        expect(result.email).toBe('stampede@example.com');
      });
      
      // Database query should only be called once
      const querySpy = jest.spyOn(User, 'findById');
      expect(querySpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Database Performance', () => {
    test('handles bulk operations efficiently', async () => {
      const batchSize = 10000;
      const users = Array(batchSize).fill().map((_, i) => ({
        email: `bulk${i}@example.com`,
        password: 'hashed_password',
        name: `Bulk User ${i}`,
        age: 20 + (i % 50)
      }));
      
      const startTime = Date.now();
      await User.insertMany(users);
      const insertTime = Date.now() - startTime;
      
      // Should complete in reasonable time
      expect(insertTime).toBeLessThan(5000); // 5 seconds
      
      // Verify all inserted
      const count = await User.countDocuments();
      expect(count).toBe(batchSize);
    });

    test('efficiently paginates large datasets', async () => {
      // Create large dataset
      const users = Array(10000).fill().map((_, i) => ({
        email: `page${i}@example.com`,
        password: 'hashed_password',
        name: `Page User ${i}`,
        createdAt: new Date(Date.now() - i * 1000)
      }));
      
      await User.insertMany(users);
      
      // Test pagination performance
      const pageSize = 100;
      const pages = 10;
      
      for (let page = 1; page <= pages; page++) {
        const startTime = Date.now();
        const result = await User.find()
          .sort({ createdAt: -1 })
          .skip((page - 1) * pageSize)
          .limit(pageSize);
        
        const queryTime = Date.now() - startTime;
        
        expect(result).toHaveLength(pageSize);
        expect(queryTime).toBeLessThan(100); // Each page should be fast
      }
    });
  });

  describe('Database Migration Tests', () => {
    test('handles schema changes', async () => {
      // Old schema data
      await mongoConnection.collection('users').insertOne({
        email: 'old@example.com',
        password: 'hashed_password',
        // Missing new required field: name
      });
      
      // Migration script
      await mongoConnection.collection('users').updateMany(
        { name: { $exists: false } },
        { $set: { name: 'Migrated User' } }
      );
      
      // Verify migration
      const migratedUser = await User.findOne({ email: 'old@example.com' });
      expect(migratedUser.name).toBe('Migrated User');
    });

    test('maintains data integrity during migration', async () => {
      // Create data with old schema
      const oldData = Array(100).fill().map((_, i) => ({
        email: `migrate${i}@example.com`,
        password: 'hashed_password',
        profile: {
          firstName: `User${i}`,
          lastName: `Last${i}`
        }
      }));
      
      await mongoConnection.collection('users').insertMany(oldData);
      
      // Complex migration: flatten profile fields
      const cursor = mongoConnection.collection('users').find();
      while (await cursor.hasNext()) {
        const doc = await cursor.next();
        await mongoConnection.collection('users').updateOne(
          { _id: doc._id },
          {
            $set: {
              firstName: doc.profile.firstName,
              lastName: doc.profile.lastName
            },
            $unset: { profile: 1 }
          }
        );
      }
      
      // Verify all data migrated
      const migratedCount = await mongoConnection.collection('users').countDocuments({
        firstName: { $exists: true },
        lastName: { $exists: true },
        profile: { $exists: false }
      });
      
      expect(migratedCount).toBe(100);
    });
  });
});

// tests/integration/service-integration.test.js
const UserService = require('../../src/services/UserService');
const EmailService = require('../../src/services/EmailService');
const NotificationService = require('../../src/services/NotificationService');
const AuthService = require('../../src/services/AuthService');
const User = require('../../src/models/User');
const Session = require('../../src/models/Session');

describe('Service Integration Tests', () => {
  let userService;
  let authService;
  let testUser;

  beforeAll(async () => {
    // Initialize services with real dependencies
    userService = new UserService();
    authService = new AuthService();
  });

  beforeEach(async () => {
    // Clear database
    await User.deleteMany({});
    await Session.deleteMany({});
    
    // Create test user
    testUser = await User.create({
      email: 'integration@example.com',
      password: 'Password123!',
      name: 'Integration User',
      emailVerified: true
    });
  });

  describe('User Registration Flow', () => {
    test('complete user registration flow', async () => {
      // 1. Create user
      const newUser = await userService.createUser({
        email: 'new@example.com',
        password: 'Password123!',
        name: 'New User'
      });
      
      expect(newUser.email).toBe('new@example.com');
      expect(newUser.emailVerified).toBe(false);
      
      // 2. Send verification email
      const emailResult = await EmailService.sendVerificationEmail(
        newUser.email,
        newUser.verificationToken
      );
      
      expect(emailResult.success).toBe(true);
      
      // 3. Verify email
      const verifiedUser = await userService.verifyEmail(
        newUser.verificationToken
      );
      
      expect(verifiedUser.emailVerified).toBe(true);
      
      // 4. Login
      const authResult = await authService.login({
        email: 'new@example.com',
        password: 'Password123!'
      });
      
      expect(authResult.token).toBeTruthy();
      expect(authResult.user.email).toBe('new@example.com');
      
      // 5. Create session
      const session = await Session.findOne({ userId: newUser._id });
      expect(session).toBeTruthy();
      expect(session.active).toBe(true);
    });

    test('registration with notification preferences', async () => {
      const user = await userService.createUser({
        email: 'notify@example.com',
        password: 'Password123!',
        name: 'Notification User',
        preferences: {
          email: true,
          sms: false,
          marketing: true
        }
      });
      
      // Should send welcome email
      expect(EmailService.sendWelcomeEmail).toHaveBeenCalledWith(
        'notify@example.com',
        expect.any(Object)
      );
      
      // Should NOT send SMS (preference is false)
      const smsService = require('../../src/services/SmsService');
      expect(smsService.send).not.toHaveBeenCalled();
    });
  });

  describe('Authentication Flow', () => {
    test('complete authentication flow with refresh tokens', async () => {
      // 1. Login
      const loginResult = await authService.login({
        email: 'integration@example.com',
        password: 'Password123!'
      });
      
      expect(loginResult.token).toBeTruthy();
      expect(loginResult.refreshToken).toBeTruthy();
      
      // 2. Use access token
      const protectedData = await authService.getProtectedData(
        loginResult.token
      );
      
      expect(protectedData.userId).toBe(testUser._id.toString());
      
      // 3. Refresh token
      const refreshResult = await authService.refreshToken(
        loginResult.refreshToken
      );
      
      expect(refreshResult.token).toBeTruthy();
      expect(refreshResult.refreshToken).toBeTruthy();
      expect(refreshResult.token).not.toBe(loginResult.token);
      
      // 4. Logout
      await authService.logout(loginResult.refreshToken);
      
      // 5. Verify old refresh token no longer works
      await expect(
        authService.refreshToken(loginResult.refreshToken)
      ).rejects.toThrow('Invalid refresh token');
    });

    test('handles concurrent sessions', async () => {
      // Create multiple sessions for same user
      const session1 = await authService.createSession(testUser._id, 'device1');
      const session2 = await authService.createSession(testUser._id, 'device2');
      const session3 = await authService.createSession(testUser._id, 'device3');
      
      // All sessions should be active
      const sessions = await Session.find({ userId: testUser._id });
      expect(sessions).toHaveLength(3);
      expect(sessions.every(s => s.active)).toBe(true);
      
      // Revoke one session
      await authService.revokeSession(session1.token);
      
      const updatedSessions = await Session.find({ userId: testUser._id });
      const activeSessions = updatedSessions.filter(s => s.active);
      
      expect(activeSessions).toHaveLength(2);
    });

    test('implements session timeout', async () => {
      const session = await authService.createSession(testUser._id, 'test-device');
      
      // Simulate time passing
      jest.useFakeTimers();
      jest.advanceTimersByTime(25 * 60 * 1000); // 25 minutes
      
      // Session should still be valid
      const isValid = await authService.validateSession(session.token);
      expect(isValid).toBe(true);
      
      // Advance beyond timeout
      jest.advanceTimersByTime(10 * 60 * 1000); // Additional 10 minutes
      
      // Session should be expired
      await expect(
        authService.validateSession(session.token)
      ).rejects.toThrow('Session expired');
      
      jest.useRealTimers();
    });
  });

  describe('Password Reset Flow', () => {
    test('complete password reset flow', async () => {
      // 1. Request password reset
      const resetRequest = await authService.requestPasswordReset(
        'integration@example.com'
      );
      
      expect(resetRequest.success).toBe(true);
      expect(resetRequest.resetToken).toBeTruthy();
      
      // 2. Verify reset token
      const isValid = await authService.validateResetToken(
        resetRequest.resetToken
      );
      expect(isValid).toBe(true);
      
      // 3. Reset password
      const resetResult = await authService.resetPassword(
        resetRequest.resetToken,
        'NewPassword456!'
      );
      
      expect(resetResult.success).toBe(true);
      
      // 4. Verify old password no longer works
      await expect(
        authService.login({
          email: 'integration@example.com',
          password: 'Password123!' // Old password
        })
      ).rejects.toThrow('Invalid credentials');
      
      // 5. Verify new password works
      const loginResult = await authService.login({
        email: 'integration@example.com',
        password: 'NewPassword456!' // New password
      });
      
      expect(loginResult.token).toBeTruthy();
    });

    test('prevents password reset token reuse', async () => {
      const resetRequest = await authService.requestPasswordReset(
        'integration@example.com'
      );
      
      // Use token once
      await authService.resetPassword(
        resetRequest.resetToken,
        'NewPassword456!'
      );
      
      // Attempt to reuse token
      await expect(
        authService.resetPassword(
          resetRequest.resetToken,
          'AnotherPassword789!'
        )
      ).rejects.toThrow('Invalid or expired reset token');
    });
  });

  describe('Notification Integration', () => {
    test('sends notifications on user actions', async () => {
      // Mock event bus
      const eventBus = require('../../src/events/EventBus');
      const eventSpy = jest.spyOn(eventBus, 'emit');
      
      // Update user profile
      await userService.updateUserProfile(testUser._id, {
        name: 'Updated Name'
      });
      
      // Should emit event
      expect(eventSpy).toHaveBeenCalledWith(
        'user.updated',
        expect.objectContaining({
          userId: testUser._id.toString(),
          oldName: 'Integration User',
          newName: 'Updated Name'
        })
      );
      
      // Notification service should be triggered
      expect(NotificationService.sendNotification).toHaveBeenCalled();
    });

    test('batches notifications efficiently', async () => {
      // Create multiple users
      const users = await User.create(
        Array(100).fill().map((_, i) => ({
          email: `batch${i}@example.com`,
          password: 'Password123!',
          name: `Batch User ${i}`,
          preferences: { email: true }
        }))
      );
      
      // Send batch notification
      await NotificationService.sendBatchNotification(
        users,
        {
          type: 'announcement',
          title: 'Important Update',
          message: 'Service maintenance scheduled'
        }
      );
      
      // Should use batch email sending
      expect(EmailService.sendBatch).toHaveBeenCalled();
      expect(EmailService.sendBatch.mock.calls[0][0]).toHaveLength(100);
    });
  });

  describe('Error Recovery', () => {
    test('recovers from partial service failures', async () => {
      // Mock email service to fail
      EmailService.sendWelcomeEmail.mockRejectedValue(
        new Error('SMTP server down')
      );
      
      // User creation should still succeed
      const user = await userService.createUser({
        email: 'resilient@example.com',
        password: 'Password123!',
        name: 'Resilient User'
      });
      
      expect(user).toBeTruthy();
      expect(user.email).toBe('resilient@example.com');
      
      // Notification should be queued for retry
      const queueService = require('../../src/services/QueueService');
      expect(queueService.add).toHaveBeenCalledWith(
        'retry-notification',
        expect.objectContaining({
          type: 'welcome_email',
          userId: user._id
        })
      );
    });

    test('maintains consistency during service outages', async () => {
      // Simulate database connection loss during operation
      const originalFind = User.findById;
      User.findById = jest.fn()
        .mockResolvedValueOnce(testUser) // First call works
        .mockRejectedValueOnce(new Error('Database connection lost')) // Second fails
        .mockResolvedValueOnce(testUser); // Third works after retry
      
      // Service should retry and eventually succeed
      const result = await userService.getUserProfile(testUser._id);
      
      expect(result).toBeTruthy();
      expect(User.findById).toHaveBeenCalledTimes(3); // Initial + 2 retries
      
      // Restore original method
      User.findById = originalFind;
    });
  });
});

// tests/integration/third-party-integration.test.js
const axios = require('axios');
const MockAdapter = require('axios-mock-adapter');
const PaymentService = require('../../src/services/PaymentService');
const EmailService = require('../../src/services/EmailService');
const GeoLocationService = require('../../src/services/GeoLocationService');

describe('Third-Party Integration Tests', () => {
  let axiosMock;
  let paymentService;
  
  beforeAll(() => {
    axiosMock = new MockAdapter(axios);
    paymentService = new PaymentService();
  });
  
  afterEach(() => {
    axiosMock.reset();
  });
  
  afterAll(() => {
    axiosMock.restore();
  });
  
  describe('Payment Gateway Integration', () => {
    test('integrates with Stripe API', async () => {
      // Mock Stripe API response
      axiosMock.onPost('https://api.stripe.com/v1/charges').reply(200, {
        id: 'ch_123',
        object: 'charge',
        amount: 1000,
        currency: 'usd',
        status: 'succeeded',
        source: {
          id: 'card_123',
          brand: 'visa',
          last4: '4242'
        }
      });
      
      const paymentData = {
        amount: 1000,
        currency: 'USD',
        source: 'tok_visa',
        description: 'Test payment'
      };
      
      const result = await paymentService.processStripePayment(paymentData);
      
      expect(result).toMatchObject({
        id: 'ch_123',
        status: 'succeeded',
        amount: 1000,
        paymentMethod: 'visa'
      });
      
      // Verify API call
      expect(axiosMock.history.post).toHaveLength(1);
      const request = axiosMock.history.post[0];
      expect(request.url).toBe('https://api.stripe.com/v1/charges');
      expect(request.headers['Authorization']).toContain('Bearer sk_test_');
    });
    
    test('handles Stripe API errors', async () => {
      axiosMock.onPost('https://api.stripe.com/v1/charges').reply(402, {
        error: {
          type: 'card_error',
          code: 'card_declined',
          message: 'Your card was declined.'
        }
      });
      
      await expect(
        paymentService.processStripePayment({
          amount: 1000,
          source: 'tok_declined'
        })
      ).rejects.toThrow('Card declined');
    });
    
    test('implements retry logic for transient failures', async () => {
      let callCount = 0;
      axiosMock.onPost('https://api.stripe.com/v1/charges').reply(() => {
        callCount++;
        if (callCount < 3) {
          return [500, { error: 'Internal Server Error' }];
        }
        return [200, { id: 'ch_123', status: 'succeeded' }];
      });
      
      const result = await paymentService.processStripePayment({
        amount: 1000,
        source: 'tok_visa'
      });
      
      expect(callCount).toBe(3);
      expect(result.status).toBe('succeeded');
    });
  });
  
  describe('Email Service Integration', () => {
    test('integrates with SendGrid API', async () => {
      axiosMock.onPost('https://api.sendgrid.com/v3/mail/send').reply(202, {});
      
      const emailResult = await EmailService.send({
        to: 'recipient@example.com',
        subject: 'Test Email',
        html: '<p>Test content</p>'
      });
      
      expect(emailResult.success).toBe(true);
      expect(axiosMock.history.post).toHaveLength(1);
    });
    
    test('handles email service rate limiting', async () => {
      // Mock rate limit response
      axiosMock.onPost('https://api.sendgrid.com/v3/mail/send').reply(429, {
        errors: [{ message: 'Too many requests' }]
      }, {
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + 60
      });
      
      // Should queue email for later
      const result = await EmailService.send({
        to: 'recipient@example.com',
        subject: 'Test Email'
      });
      
      expect(result.queued).toBe(true);
      expect(result.retryAt).toBeInstanceOf(Date);
    });
  });
  
  describe('Geolocation Integration', () => {
    test('integrates with IP geolocation service', async () => {
      axiosMock.onGet('https://ipapi.co/8.8.8.8/json/').reply(200, {
        ip: '8.8.8.8',
        city: 'Mountain View',
        region: 'California',
        country: 'US',
        country_name: 'United States',
        latitude: 37.386,
        longitude: -122.0838,
        timezone: 'America/Los_Angeles'
      });
      
      const location = await GeoLocationService.getLocation('8.8.8.8');
      
      expect(location).toMatchObject({
        country: 'US',
        city: 'Mountain View',
        coordinates: {
          lat: 37.386,
          lng: -122.0838
        }
      });
    });
    
    test('caches geolocation results', async () => {
      axiosMock.onGet('https://ipapi.co/8.8.8.8/json/').reply(200, {
        country: 'US',
        city: 'Mountain View'
      });
      
      // First call - API call
      await GeoLocationService.getLocation('8.8.8.8');
      
      // Second call - should use cache
      await GeoLocationService.getLocation('8.8.8.8');
      
      expect(axiosMock.history.get).toHaveLength(1); // Only one API call
    });
  });
  
  describe('Webhook Integration', () => {
    test('receives and processes webhooks', async () => {
      const webhookPayload = {
        event: 'payment.succeeded',
        data: {
          payment_id: 'pay_123',
          amount: 1000,
          currency: 'usd'
        }
      };
      
      const signature = 'valid_signature';
      
      // Mock webhook handler
      const webhookService = require('../../src/services/WebhookService');
      const processSpy = jest.spyOn(webhookService, 'processWebhook');
      
      // Send webhook
      const response = await axios.post('http://localhost:3000/api/webhooks/stripe', webhookPayload, {
        headers: {
          'Stripe-Signature': signature
        }
      });
      
      expect(response.status).toBe(200);
      expect(processSpy).toHaveBeenCalledWith(
        'stripe',
        webhookPayload,
        signature
      );
    });
    
    test('validates webhook signatures', async () => {
      const response = await axios.post(
        'http://localhost:3000/api/webhooks/stripe',
        { event: 'test' },
        {
          headers: {
            'Stripe-Signature': 'invalid_signature'
          }
        }
      ).catch(error => error.response);
      
      expect(response.status).toBe(401);
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between integration testing and end-to-end testing? When would you use each?"
2. "How do you handle test data isolation in integration tests that share a database?"
3. "What strategies do you use to test integrations with external APIs?"

**Scenario-Based Questions:**
1. "You have a microservices architecture. How would you design integration tests that span multiple services?"
2. "Your integration tests are flaky due to timing issues with external dependencies. How would you fix this?"
3. "You need to test a database migration that takes hours to run. How would you approach testing this?"

**Real-World Challenge:**
> "Design an integration testing strategy for a ride-sharing application that: 1) Matches riders with drivers, 2) Calculates fares dynamically, 3) Processes payments, 4) Tracks real-time locations, 5) Sends notifications to both parties, 6) Handles cancellations and disputes. Include tests for: API integrations, database transactions, message queue processing, and third-party service integrations."

---

## 5. Mocking DB & APIs <a name="mocking-db-apis"></a>

### Overview
Mocking allows you to simulate database and API behavior, enabling isolated testing without external dependencies.

### Comprehensive Mocking Strategies

```javascript
// tests/mocking/advanced-mocking.test.js
const UserService = require('../../src/services/UserService');
const PaymentService = require('../../src/services/PaymentService');
const { EventEmitter } = require('events');

describe('Advanced Mocking Techniques', () => {
  describe('Database Mocking', () => {
    test('mocks MongoDB with in-memory database', async () => {
      // Using MongoDB Memory Server
      const { MongoMemoryServer } = require('mongodb-memory-server');
      const mongoose = require('mongoose');
      
      const mongoServer = await MongoMemoryServer.create();
      const mongoUri = mongoServer.getUri();
      
      await mongoose.connect(mongoUri);
      
      // Real mongoose models
      const User = mongoose.model('User', new mongoose.Schema({
        email: String,
        name: String,
        age: Number
      }));
      
      // Test with real database
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        age: 25
      });
      
      const foundUser = await User.findById(user._id);
      expect(foundUser.email).toBe('test@example.com');
      
      await mongoose.disconnect();
      await mongoServer.stop();
    });
    
    test('mocks Mongoose models with jest.mock', () => {
      // Mock entire mongoose module
      jest.mock('mongoose', () => {
        const mockModel = {
          find: jest.fn(),
          findById: jest.fn(),
          findOne: jest.fn(),
          create: jest.fn(),
          updateOne: jest.fn(),
          deleteOne: jest.fn(),
          countDocuments: jest.fn()
        };
        
        return {
          connect: jest.fn(),
          disconnect: jest.fn(),
          model: jest.fn(() => mockModel),
          Schema: class MockSchema {},
          Types: {
            ObjectId: jest.fn(() => 'mock_object_id')
          }
        };
      });
      
      const mongoose = require('mongoose');
      const User = mongoose.model('User');
      
      // Configure mock behavior
      User.findById.mockResolvedValue({
        _id: 'user_123',
        email: 'test@example.com',
        name: 'Test User'
      });
      
      // Test service that uses mongoose
      const userService = new UserService();
      const result = userService.getUser('user_123');
      
      expect(User.findById).toHaveBeenCalledWith('user_123');
      expect(result).resolves.toMatchObject({
        email: 'test@example.com'
      });
    });
    
    test('mocks database transactions', async () => {
      const mockSession = {
        startTransaction: jest.fn(),
        commitTransaction: jest.fn(),
        abortTransaction: jest.fn(),
        endSession: jest.fn()
      };
      
      const mockConnection = {
        startSession: jest.fn(() => mockSession)
      };
      
      const User = {
        create: jest.fn()
      };
      
      // Simulate transaction flow
      const session = await mockConnection.startSession();
      session.startTransaction();
      
      try {
        await User.create([{ name: 'Test User' }], { session });
        await session.commitTransaction();
      } catch (error) {
        await session.abortTransaction();
        throw error;
      } finally {
        await session.endSession();
      }
      
      expect(mockSession.startTransaction).toHaveBeenCalled();
      expect(mockSession.commitTransaction).toHaveBeenCalled();
      expect(mockSession.endSession).toHaveBeenCalled();
    });
    
    test('mocks database indexes and query plans', () => {
      const mockExplain = {
        executionStats: {
          executionStages: {
            stage: 'IXSCAN',
            indexName: 'email_1'
          },
          totalDocsExamined: 1,
          executionTimeMillis: 5
        }
      };
      
      const User = {
        find: jest.fn().mockReturnThis(),
        explain: jest.fn().mockResolvedValue(mockExplain)
      };
      
      // Test query optimization
      const query = User.find({ email: 'test@example.com' });
      const explain = query.explain('executionStats');
      
      expect(explain).resolves.toMatchObject({
        executionStats: {
          executionStages: {
            stage: 'IXSCAN'
          }
        }
      });
    });
  });
  
  describe('API Mocking', () => {
    let axiosMock;
    
    beforeEach(() => {
      // Create axios mock adapter
      const axios = require('axios');
      const MockAdapter = require('axios-mock-adapter');
      axiosMock = new MockAdapter(axios);
    });
    
    afterEach(() => {
      axiosMock.reset();
    });
    
    test('mocks REST API endpoints', async () => {
      // Mock specific endpoint
      axiosMock.onGet('https://api.example.com/users/123').reply(200, {
        id: 123,
        name: 'John Doe',
        email: 'john@example.com'
      });
      
      // Mock POST with request validation
      axiosMock.onPost('https://api.example.com/users').reply((config) => {
        const data = JSON.parse(config.data);
        if (!data.email || !data.name) {
          return [400, { error: 'Missing required fields' }];
        }
        return [201, { id: 456, ...data }];
      });
      
      // Mock with dynamic response based on request
      axiosMock.onPut(/\/users\/\d+/).reply((config) => {
        const userId = config.url.split('/').pop();
        const data = JSON.parse(config.data);
        return [200, { id: userId, ...data, updated: true }];
      });
      
      // Test the mocks
      const axios = require('axios');
      
      const getResponse = await axios.get('https://api.example.com/users/123');
      expect(getResponse.data.name).toBe('John Doe');
      
      const postResponse = await axios.post('https://api.example.com/users', {
        name: 'Jane Doe',
        email: 'jane@example.com'
      });
      expect(postResponse.status).toBe(201);
      expect(postResponse.data.id).toBe(456);
      
      const putResponse = await axios.put('https://api.example.com/users/789', {
        name: 'Updated Name'
      });
      expect(putResponse.data.id).toBe('789');
      expect(putResponse.data.updated).toBe(true);
    });
    
    test('mocks API with authentication', async () => {
      // Mock OAuth2 token endpoint
      axiosMock.onPost('https://auth.example.com/oauth/token').reply(200, {
        access_token: 'mock_access_token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'mock_refresh_token'
      });
      
      // Mock authenticated endpoints
      axiosMock.onGet('https://api.example.com/protected')
        .reply((config) => {
          if (config.headers.Authorization !== 'Bearer mock_access_token') {
            return [401, { error: 'Unauthorized' }];
          }
          return [200, { data: 'protected data' }];
        });
      
      // Mock token refresh
      axiosMock.onPost('https://auth.example.com/oauth/refresh').reply(200, {
        access_token: 'new_access_token',
        expires_in: 3600
      });
      
      const axios = require('axios');
      
      // Get access token
      const tokenResponse = await axios.post('https://auth.example.com/oauth/token', {
        grant_type: 'client_credentials',
        client_id: 'client_id',
        client_secret: 'client_secret'
      });
      
      // Use token to access protected endpoint
      const protectedResponse = await axios.get('https://api.example.com/protected', {
        headers: {
          Authorization: `Bearer ${tokenResponse.data.access_token}`
        }
      });
      
      expect(protectedResponse.data.data).toBe('protected data');
    });
    
    test('mocks API rate limiting', async () => {
      let callCount = 0;
      
      axiosMock.onGet('https://api.example.com/limited').reply(() => {
        callCount++;
        if (callCount > 3) {
          return [429, { error: 'Rate limit exceeded' }, {
            'X-RateLimit-Limit': '3',
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + 60
          }];
        }
        return [200, { data: `Call ${callCount}` }];
      });
      
      const axios = require('axios');
      
      // First 3 calls should succeed
      for (let i = 1; i <= 3; i++) {
        const response = await axios.get('https://api.example.com/limited');
        expect(response.status).toBe(200);
        expect(response.data.data).toBe(`Call ${i}`);
      }
      
      // Fourth call should be rate limited
      const response = await axios.get('https://api.example.com/limited')
        .catch(error => error.response);
      
      expect(response.status).toBe(429);
      expect(response.data.error).toBe('Rate limit exceeded');
    });
    
    test('mocks WebSocket connections', () => {
      const WebSocket = require('ws');
      
      // Create mock WebSocket server
      const WebSocketServer = require('ws').Server;
      const wss = new WebSocketServer({ port: 8080 });
      
      const messages = [];
      
      wss.on('connection', (ws) => {
        ws.on('message', (message) => {
          messages.push(message);
          
          // Echo message back
          ws.send(`Echo: ${message}`);
          
          // Send automated response for specific messages
          if (message === 'getUsers') {
            ws.send(JSON.stringify({ type: 'users', data: ['user1', 'user2'] }));
          }
        });
        
        // Send welcome message
        ws.send(JSON.stringify({ type: 'connected', timestamp: Date.now() }));
      });
      
      // Test WebSocket client
      const client = new WebSocket('ws://localhost:8080');
      
      return new Promise((resolve) => {
        client.on('open', () => {
          client.send('getUsers');
        });
        
        const receivedMessages = [];
        client.on('message', (data) => {
          receivedMessages.push(data.toString());
          
          if (receivedMessages.length === 2) { // Welcome + response
            expect(receivedMessages[0]).toContain('connected');
            expect(receivedMessages[1]).toContain('users');
            wss.close();
            resolve();
          }
        });
      });
    });
    
    test('mocks GraphQL API', async () => {
      const { graphql, buildSchema } = require('graphql');
      
      // Mock GraphQL schema
      const schema = buildSchema(`
        type User {
          id: ID!
          name: String!
          email: String!
        }
        
        type Query {
          getUser(id: ID!): User
          listUsers: [User!]!
        }
        
        type Mutation {
          createUser(name: String!, email: String!): User!
        }
      `);
      
      // Mock resolvers
      const root = {
        getUser: ({ id }) => ({
          id,
          name: 'Mock User',
          email: 'mock@example.com'
        }),
        listUsers: () => [
          { id: '1', name: 'User One', email: 'one@example.com' },
          { id: '2', name: 'User Two', email: 'two@example.com' }
        ],
        createUser: ({ name, email }) => ({
          id: 'new_id',
          name,
          email
        })
      };
      
      // Test GraphQL queries
      const query = `
        query GetUser($id: ID!) {
          getUser(id: $id) {
            id
            name
            email
          }
        }
      `;
      
      const result = await graphql({
        schema,
        source: query,
        rootValue: root,
        variableValues: { id: '123' }
      });
      
      expect(result.data.getUser.name).toBe('Mock User');
    });
  });
  
  describe('Event System Mocking', () => {
    test('mocks event emitters', () => {
      const eventEmitter = new EventEmitter();
      
      // Create mock event handler
      const mockHandler = jest.fn();
      eventEmitter.on('testEvent', mockHandler);
      
      // Emit event
      eventEmitter.emit('testEvent', { data: 'test' });
      
      expect(mockHandler).toHaveBeenCalledWith({ data: 'test' });
    });
    
    test('mocks event-driven architecture', async () => {
      // Mock event bus
      const eventBus = {
        events: new Map(),
        on: jest.fn((event, handler) => {
          if (!eventBus.events.has(event)) {
            eventBus.events.set(event, []);
          }
          eventBus.events.get(event).push(handler);
        }),
        emit: jest.fn((event, data) => {
          const handlers = eventBus.events.get(event) || [];
          handlers.forEach(handler => handler(data));
        }),
        removeListener: jest.fn()
      };
      
      // Test event-driven service
      const orderService = {
        createOrder: jest.fn((orderData) => {
          const order = { id: 'order_123', ...orderData };
          eventBus.emit('order.created', order);
          return order;
        })
      };
      
      // Register event handlers
      const inventoryHandler = jest.fn();
      const notificationHandler = jest.fn();
      const analyticsHandler = jest.fn();
      
      eventBus.on('order.created', inventoryHandler);
      eventBus.on('order.created', notificationHandler);
      eventBus.on('order.created', analyticsHandler);
      
      // Create order
      const order = orderService.createOrder({
        productId: 'prod_123',
        quantity: 2
      });
      
      expect(order.id).toBe('order_123');
      expect(eventBus.emit).toHaveBeenCalledWith(
        'order.created',
        expect.objectContaining({ productId: 'prod_123' })
      );
      
      // All handlers should have been called
      expect(inventoryHandler).toHaveBeenCalled();
      expect(notificationHandler).toHaveBeenCalled();
      expect(analyticsHandler).toHaveBeenCalled();
    });
    
    test('mocks message queues', async () => {
      // Mock message queue
      const mockQueue = {
        messages: [],
        publish: jest.fn((message) => {
          mockQueue.messages.push(message);
          return Promise.resolve();
        }),
        subscribe: jest.fn((handler) => {
          mockQueue.handler = handler;
        }),
        process: jest.fn(() => {
          mockQueue.messages.forEach(message => {
            mockQueue.handler(message);
          });
          mockQueue.messages = [];
        })
      };
      
      // Test queue producer
      const producer = {
        sendMessage: async (type, data) => {
          await mockQueue.publish({ type, data, timestamp: Date.now() });
        }
      };
      
      // Test queue consumer
      const processedMessages = [];
      mockQueue.subscribe((message) => {
        processedMessages.push(message);
      });
      
      // Send messages
      await producer.sendMessage('user.created', { userId: '123' });
      await producer.sendMessage('order.placed', { orderId: '456' });
      
      // Process messages
      mockQueue.process();
      
      expect(processedMessages).toHaveLength(2);
      expect(processedMessages[0].type).toBe('user.created');
      expect(processedMessages[1].type).toBe('order.placed');
    });
  });
  
  describe('File System Mocking', () => {
    test('mocks file system operations', () => {
      // Mock fs module
      jest.mock('fs', () => {
        const mockFiles = new Map();
        
        return {
          promises: {
            readFile: jest.fn((path) => {
              if (!mockFiles.has(path)) {
                throw new Error('File not found');
              }
              return Promise.resolve(mockFiles.get(path));
            }),
            writeFile: jest.fn((path, data) => {
              mockFiles.set(path, data);
              return Promise.resolve();
            }),
            unlink: jest.fn((path) => {
              mockFiles.delete(path);
              return Promise.resolve();
            }),
            readdir: jest.fn((dir) => {
              const files = Array.from(mockFiles.keys())
                .filter(path => path.startsWith(dir))
                .map(path => path.split('/').pop());
              return Promise.resolve(files);
            })
          }
        };
      });
      
      const fs = require('fs').promises;
      
      // Test file operations
      const fileService = {
        async saveConfig(path, config) {
          await fs.writeFile(path, JSON.stringify(config));
        },
        
        async loadConfig(path) {
          const data = await fs.readFile(path, 'utf8');
          return JSON.parse(data);
        }
      };
      
      // Save config
      const config = { apiUrl: 'https://api.example.com', timeout: 5000 };
      await fileService.saveConfig('/app/config.json', config);
      
      // Load config
      const loadedConfig = await fileService.loadConfig('/app/config.json');
      
      expect(loadedConfig).toEqual(config);
      expect(fs.writeFile).toHaveBeenCalledWith(
        '/app/config.json',
        JSON.stringify(config)
      );
    });
    
    test('mocks file uploads', async () => {
      const mockStorage = {
        files: new Map(),
        
        upload: jest.fn((stream, filename) => {
          return new Promise((resolve) => {
            const chunks = [];
            stream.on('data', (chunk) => chunks.push(chunk));
            stream.on('end', () => {
              const buffer = Buffer.concat(chunks);
              const fileId = `file_${Date.now()}`;
              mockStorage.files.set(fileId, { buffer, filename });
              resolve({ id: fileId, filename, size: buffer.length });
            });
          });
        }),
        
        download: jest.fn((fileId) => {
          const file = mockStorage.files.get(fileId);
          if (!file) {
            throw new Error('File not found');
          }
          return Promise.resolve(file.buffer);
        })
      };
      
      // Test file upload
      const { Readable } = require('stream');
      const fileContent = Buffer.from('Test file content');
      const fileStream = Readable.from([fileContent]);
      
      const uploadResult = await mockStorage.upload(fileStream, 'test.txt');
      
      expect(uploadResult.filename).toBe('test.txt');
      expect(uploadResult.size).toBe(fileContent.length);
      
      // Test file download
      const downloaded = await mockStorage.download(uploadResult.id);
      expect(downloaded.toString()).toBe('Test file content');
    });
  });
  
  describe('Date and Time Mocking', () => {
    test('mocks current date and time', () => {
      const fixedDate = new Date('2024-01-01T12:00:00Z');
      
      // Mock Date constructor
      const RealDate = Date;
      global.Date = class extends RealDate {
        constructor(...args) {
          if (args.length === 0) {
            return fixedDate;
          }
          return new RealDate(...args);
        }
        
        static now() {
          return fixedDate.getTime();
        }
      };
      
      // Test date-dependent code
      const timeService = {
        getCurrentTime: () => new Date(),
        isWeekend: () => {
          const day = new Date().getDay();
          return day === 0 || day === 6;
        }
      };
      
      expect(timeService.getCurrentTime()).toEqual(fixedDate);
      expect(timeService.isWeekend()).toBe(false); // Monday
      
      // Restore original Date
      global.Date = RealDate;
    });
    
    test('mocks setTimeout and setInterval', () => {
      jest.useFakeTimers();
      
      const callback = jest.fn();
      
      // Schedule callback
      setTimeout(callback, 5000);
      
      // Fast-forward time
      jest.advanceTimersByTime(5000);
      
      expect(callback).toHaveBeenCalled();
      
      jest.useRealTimers();
    });
    
    test('mocks time-dependent operations', () => {
      jest.useFakeTimers();
      
      const cache = new Map();
      const cacheService = {
        set: (key, value, ttl) => {
          cache.set(key, value);
          setTimeout(() => {
            cache.delete(key);
          }, ttl);
        },
        get: (key) => cache.get(key)
      };
      
      // Set value with 10-second TTL
      cacheService.set('test', 'value', 10000);
      expect(cacheService.get('test')).toBe('value');
      
      // Advance 9 seconds - should still exist
      jest.advanceTimersByTime(9000);
      expect(cacheService.get('test')).toBe('value');
      
      // Advance 2 more seconds - should be expired
      jest.advanceTimersByTime(2000);
      expect(cacheService.get('test')).toBeUndefined();
      
      jest.useRealTimers();
    });
  });
  
  describe('Complex Mocking Scenarios', () => {
    test('mocks circular dependencies', () => {
      // Service A depends on Service B, which depends on Service A
      const mockServiceB = {
        doSomething: jest.fn()
      };
      
      const ServiceA = jest.fn().mockImplementation(() => ({
        doWork: jest.fn(() => {
          return mockServiceB.doSomething();
        })
      }));
      
      const ServiceB = jest.fn().mockImplementation(() => ({
        doSomething: jest.fn(() => {
          const serviceA = new ServiceA();
          return serviceA.doWork();
        })
      }));
      
      // Update mock to use actual ServiceB
      mockServiceB.doSomething.mockImplementation(() => {
        const serviceB = new ServiceB();
        return serviceB.doSomething();
      });
      
      const serviceA = new ServiceA();
      serviceA.doWork();
      
      expect(mockServiceB.doSomething).toHaveBeenCalled();
    });
    
    test('mocks dynamic imports', async () => {
      // Mock dynamic import
      jest.mock('../../src/services/DynamicService', () => ({
        __esModule: true,
        default: jest.fn(() => ({
          getData: jest.fn().mockResolvedValue('mock data')
        }))
      }));
      
      // Test dynamic import
      const { default: DynamicService } = await import('../../src/services/DynamicService');
      const service = new DynamicService();
      const result = await service.getData();
      
      expect(result).toBe('mock data');
    });
    
    test('mocks environment variables', () => {
      const originalEnv = process.env;
      
      // Set test environment variables
      process.env = {
        ...originalEnv,
        NODE_ENV: 'test',
        API_KEY: 'test_key',
        DATABASE_URL: 'mongodb://localhost:27017/test'
      };
      
      // Test environment-dependent code
      const config = {
        env: process.env.NODE_ENV,
        apiKey: process.env.API_KEY,
        isProduction: process.env.NODE_ENV === 'production'
      };
      
      expect(config.env).toBe('test');
      expect(config.apiKey).toBe('test_key');
      expect(config.isProduction).toBe(false);
      
      // Restore original environment
      process.env = originalEnv;
    });
    
    test('mocks random number generation', () => {
      // Mock Math.random
      const mockRandom = jest.spyOn(Math, 'random');
      mockRandom.mockReturnValue(0.5);
      
      // Test random-dependent code
      const randomService = {
        generateId: () => `id_${Math.random().toString(36).substr(2, 9)}`,
        getRandomElement: (array) => array[Math.floor(Math.random() * array.length)]
      };
      
      const id = randomService.generateId();
      const element = randomService.getRandomElement(['a', 'b', 'c']);
      
      expect(id).toBe('id_k9h4h5p6h'); // Based on 0.5
      expect(element).toBe('b'); // 0.5 * 3 = 1.5, floor = 1
      
      mockRandom.mockRestore();
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between mocking, stubbing, and spying? When would you use each?"
2. "How do you mock ES6 modules vs CommonJS modules in Jest?"
3. "What are the pros and cons of using an in-memory database vs mocking the database layer?"

**Scenario-Based Questions:**
1. "You need to test a service that makes calls to three different external APIs. How would you mock them to test various failure scenarios?"
2. "Your tests are failing randomly because of timing issues with setTimeout. How would you mock time to make tests deterministic?"
3. "You have a class with circular dependencies. How would you mock this for testing?"

**Real-World Challenge:**
> "Design a mocking strategy for a stock trading application that: 1) Fetches real-time stock prices from multiple sources, 2) Processes trades through different brokers, 3) Sends notifications via email/SMS/push, 4) Generates PDF reports, 5) Integrates with accounting software. Include mocks for: Real-time data streams, third-party APIs, file system operations, and email/SMS services."

---

## 6. End-to-End Testing <a name="end-to-end-testing"></a>

### Overview
End-to-end testing verifies that the entire application works correctly from the user's perspective, testing all integrated components.

### Comprehensive E2E Testing Strategy

```javascript
// tests/e2e/setup-e2e.js
const { chromium, firefox, webkit } = require('playwright');
const { MongoMemoryServer } = require('mongodb-memory-server');
const Redis = require('ioredis');
const { createServer } = require('../../src/server');

// Global test state
let server;
let mongoServer;
let redisClient;
let browser;
let context;
let page;

// Test configuration
const config = {
  baseURL: 'http://localhost:3000',
  browser: process.env.E2E_BROWSER || 'chromium',
  headless: process.env.HEADLESS !== 'false',
  slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,
  viewport: { width: 1280, height: 720 },
  timeout: 30000
};

// Setup before all tests
beforeAll(async () => {
  console.log('=== Starting E2E Test Environment ===');
  
  // Start test database
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Start Redis
  redisClient = new Redis({
    host: 'localhost',
    port: 6379,
    db: 3 // Separate DB for E2E tests
  });
  
  // Start application server
  server = await createServer({
    mongoUri,
    redisClient,
    environment: 'test',
    port: 3000
  });
  
  // Launch browser
  const browserType = {
    chromium,
    firefox,
    webkit
  }[config.browser];
  
  browser = await browserType.launch({
    headless: config.headless,
    slowMo: config.slowMo,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  console.log(`E2E environment ready. Browser: ${config.browser}`);
});

// Setup before each test
beforeEach(async () => {
  // Create new browser context
  context = await browser.newContext({
    viewport: config.viewport,
    ignoreHTTPSErrors: true,
    recordVideo: process.env.RECORD_VIDEO ? { dir: 'videos/' } : undefined
  });
  
  // Enable request/response logging
  await context.route('**/*', (route, request) => {
    console.log(`→ ${request.method()} ${request.url()}`);
    route.continue();
  });
  
  // Create new page
  page = await context.newPage();
  
  // Clear database and cache
  await clearTestData();
  
  // Navigate to base URL
  await page.goto(config.baseURL);
  
  console.log(`Test started: ${expect.getState().currentTestName}`);
});

// Teardown after each test
afterEach(async () => {
  // Capture screenshot on failure
  if (expect.getState().currentTestName && expect.getState().testPath) {
    const testName = expect.getState().currentTestName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    
    if (process.env.CAPTURE_SCREENSHOTS === 'always' || 
        (process.env.CAPTURE_SCREENSHOTS === 'fail' && expect.getState().testPath[0].status === 'failed')) {
      await page.screenshot({
        path: `screenshots/${testName}.png`,
        fullPage: true
      });
    }
  }
  
  // Close context
  await context.close();
  
  console.log(`Test completed: ${expect.getState().currentTestName}`);
});

// Teardown after all tests
afterAll(async () => {
  console.log('=== Cleaning up E2E Test Environment ===');
  
  // Close browser
  await browser.close();
  
  // Stop server
  await server.close();
  
  // Cleanup database
  await mongoServer.stop();
  await redisClient.quit();
  
  console.log('E2E environment cleaned up');
});

// Helper functions
async function clearTestData() {
  // Clear MongoDB collections
  const mongoose = require('mongoose');
  const conn = mongoose.createConnection(mongoServer.getUri());
  
  const collections = await conn.db.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }
  
  await conn.close();
  
  // Clear Redis
  await redisClient.flushdb();
}

// Global test utilities
global.e2e = {
  config,
  
  // Navigation helpers
  async navigateTo(path) {
    await page.goto(`${config.baseURL}${path}`);
  },
  
  // Authentication helpers
  async login(email = 'test@example.com', password = 'Password123!') {
    await page.goto(`${config.baseURL}/login`);
    
    await page.fill('input[name="email"]', email);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');
    
    await page.waitForURL(`${config.baseURL}/dashboard`);
  },
  
  async logout() {
    await page.click('[data-testid="user-menu"]');
    await page.click('text=Logout');
    await page.waitForURL(`${config.baseURL}/login`);
  },
  
  // Form helpers
  async fillForm(selector, data) {
    const form = page.locator(selector);
    
    for (const [name, value] of Object.entries(data)) {
      await form.locator(`[name="${name}"]`).fill(value);
    }
  },
  
  async submitForm(selector) {
    await page.locator(selector).locator('button[type="submit"]').click();
  },
  
  // Assertion helpers
  async shouldSeeText(text, options = {}) {
    const locator = page.locator(`text=${text}`);
    if (options.exact) {
      await expect(locator).toHaveText(text, { exact: true });
    } else {
      await expect(locator).toBeVisible();
    }
  },
  
  async shouldNotSeeText(text) {
    await expect(page.locator(`text=${text}`)).not.toBeVisible();
  },
  
  async shouldBeOnPage(path) {
    await page.waitForURL(`${config.baseURL}${path}`);
  },
  
  // Network helpers
  async interceptRequest(url, response) {
    await page.route(url, (route) => {
      route.fulfill(response);
    });
  },
  
  async waitForRequest(url) {
    return page.waitForRequest(url);
  },
  
  async waitForResponse(url) {
    return page.waitForResponse(url);
  },
  
  // Performance helpers
  async measurePageLoad() {
    const navigationStart = await page.evaluate(() => window.performance.timing.navigationStart);
    const loadEventEnd = await page.evaluate(() => window.performance.timing.loadEventEnd);
    return loadEventEnd - navigationStart;
  },
  
  // Accessibility helpers
  async checkAccessibility() {
    const axe = require('@axe-core/playwright');
    const results = await axe.default(page).analyze();
    return results.violations;
  },
  
  // Visual testing helpers
  async takeScreenshot(name) {
    return page.screenshot({
      path: `screenshots/${name}.png`,
      fullPage: true
    });
  },
  
  // Database helpers
  async createUser(userData) {
    const User = require('../../src/models/User');
    const mongoose = require('mongoose');
    const conn = mongoose.createConnection(mongoServer.getUri());
    User.init(conn);
    
    const user = await User.create(userData);
    await conn.close();
    return user;
  },
  
  async getUser(email) {
    const User = require('../../src/models/User');
    const mongoose = require('mongoose');
    const conn = mongoose.createConnection(mongoServer.getUri());
    User.init(conn);
    
    const user = await User.findOne({ email });
    await conn.close();
    return user;
  }
};

// Export for use in tests
module.exports = { page, context, browser, server };
```

### Comprehensive E2E Test Suites

```javascript
// tests/e2e/authentication.test.js
const { page } = require('./setup-e2e');

describe('Authentication E2E Tests', () => {
  describe('User Registration', () => {
    test('successfully registers new user', async () => {
      // Navigate to registration page
      await page.goto('/register');
      
      // Fill registration form
      await page.fill('input[name="email"]', 'newuser@example.com');
      await page.fill('input[name="password"]', 'SecurePassword123!');
      await page.fill('input[name="confirmPassword"]', 'SecurePassword123!');
      await page.fill('input[name="fullName"]', 'New User');
      
      // Submit form
      await page.click('button[type="submit"]');
      
      // Verify successful registration
      await page.waitForURL('/registration-success');
      await expect(page.locator('text=Registration successful')).toBeVisible();
      
      // Check confirmation email was sent
      const emailService = require('../../src/services/EmailService');
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        'newuser@example.com',
        expect.any(String)
      );
      
      // Verify user was created in database
      const user = await global.e2e.getUser('newuser@example.com');
      expect(user).toBeTruthy();
      expect(user.emailVerified).toBe(false);
    });
    
    test('shows validation errors for invalid input', async () => {
      await page.goto('/register');
      
      // Submit empty form
      await page.click('button[type="submit"]');
      
      // Check validation messages
      await expect(page.locator('text=Email is required')).toBeVisible();
      await expect(page.locator('text=Password is required')).toBeVisible();
      
      // Test invalid email
      await page.fill('input[name="email"]', 'invalid-email');
      await page.click('button[type="submit"]');
      await expect(page.locator('text=Invalid email format')).toBeVisible();
      
      // Test weak password
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', '123');
      await page.click('button[type="submit"]');
      await expect(page.locator('text=Password must be at least 8 characters')).toBeVisible();
      
      // Test password mismatch
      await page.fill('input[name="password"]', 'Password123!');
      await page.fill('input[name="confirmPassword"]', 'DifferentPassword123!');
      await page.click('button[type="submit"]');
      await expect(page.locator('text=Passwords do not match')).toBeVisible();
    });
    
    test('prevents duplicate email registration', async () => {
      // Create existing user
      await global.e2e.createUser({
        email: 'existing@example.com',
        password: 'hashed_password',
        name: 'Existing User'
      });
      
      await page.goto('/register');
      
      // Try to register with existing email
      await page.fill('input[name="email"]', 'existing@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.fill('input[name="confirmPassword"]', 'Password123!');
      await page.fill('input[name="fullName"]', 'New User');
      
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Email already registered')).toBeVisible();
    });
    
    test('registration with optional fields', async () => {
      await page.goto('/register');
      
      // Fill only required fields
      await page.fill('input[name="email"]', 'minimal@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.fill('input[name="confirmPassword"]', 'Password123!');
      
      await page.click('button[type="submit"]');
      
      await page.waitForURL('/registration-success');
      
      // User should be created with default values
      const user = await global.e2e.getUser('minimal@example.com');
      expect(user.name).toBe('User'); // Default name
    });
  });
  
  describe('User Login', () => {
    beforeEach(async () => {
      // Create test user
      await global.e2e.createUser({
        email: 'test@example.com',
        password: '$2b$10$TestHashForPassword123', // Hashed version of 'Password123!'
        name: 'Test User',
        emailVerified: true
      });
    });
    
    test('successfully logs in with valid credentials', async () => {
      await page.goto('/login');
      
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      // Should redirect to dashboard
      await page.waitForURL('/dashboard');
      
      // Should show user name in header
      await expect(page.locator('[data-testid="user-greeting"]')).toContainText('Test User');
      
      // Should set authentication cookie
      const cookies = await page.context().cookies();
      const authCookie = cookies.find(c => c.name === 'auth_token');
      expect(authCookie).toBeTruthy();
      expect(authCookie.httpOnly).toBe(true);
    });
    
    test('shows error for invalid credentials', async () => {
      await page.goto('/login');
      
      // Wrong password
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', 'WrongPassword!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Invalid email or password')).toBeVisible();
      
      // Non-existent email
      await page.fill('input[name="email"]', 'nonexistent@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Invalid email or password')).toBeVisible();
    });
    
    test('requires email verification', async () => {
      // Create unverified user
      await global.e2e.createUser({
        email: 'unverified@example.com',
        password: '$2b$10$TestHashForPassword123',
        name: 'Unverified User',
        emailVerified: false
      });
      
      await page.goto('/login');
      
      await page.fill('input[name="email"]', 'unverified@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Please verify your email address')).toBeVisible();
      await expect(page.locator('text=Resend verification email')).toBeVisible();
    });
    
    test('implements rate limiting', async () => {
      await page.goto('/login');
      
      // Attempt multiple failed logins
      for (let i = 0; i < 6; i++) {
        await page.fill('input[name="email"]', 'test@example.com');
        await page.fill('input[name="password"]', 'WrongPassword!');
        await page.click('button[type="submit"]');
        
        if (i < 5) {
          await expect(page.locator('text=Invalid email or password')).toBeVisible();
        } else {
          // Should be rate limited after 5 attempts
          await expect(page.locator('text=Too many login attempts')).toBeVisible();
          await expect(page.locator('button[type="submit"]')).toBeDisabled();
        }
        
        // Clear form for next attempt
        await page.fill('input[name="password"]', '');
      }
    });
    
    test('remember me functionality', async () => {
      await page.goto('/login');
      
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.check('input[name="rememberMe"]');
      await page.click('button[type="submit"]');
      
      await page.waitForURL('/dashboard');
      
      // Check for long-lived cookie
      const cookies = await page.context().cookies();
      const rememberCookie = cookies.find(c => c.name === 'remember_token');
      expect(rememberCookie).toBeTruthy();
      expect(rememberCookie.maxAge).toBeGreaterThan(604800); // > 7 days
    });
    
    test('login with social providers', async () => {
      await page.goto('/login');
      
      // Mock OAuth flow
      await global.e2e.interceptRequest('**/auth/google/callback', {
        status: 200,
        body: JSON.stringify({
          success: true,
          token: 'mock_google_token',
          user: {
            id: 'google_user_123',
            email: 'google@example.com',
            name: 'Google User'
          }
        })
      });
      
      // Click Google login button
      await page.click('text=Sign in with Google');
      
      // Should be redirected to Google OAuth
      await page.waitForURL('**/accounts.google.com/**');
      
      // Simulate OAuth callback (in real test, this would require actual OAuth flow)
      // This is simplified for demonstration
      await page.goto('/auth/google/callback?code=mock_code&state=mock_state');
      
      await page.waitForURL('/dashboard');
      await expect(page.locator('[data-testid="user-greeting"]')).toContainText('Google User');
    });
  });
  
  describe('Password Reset', () => {
    beforeEach(async () => {
      await global.e2e.createUser({
        email: 'reset@example.com',
        password: '$2b$10$TestHashForPassword123',
        name: 'Reset User'
      });
    });
    
    test('successful password reset flow', async () => {
      // Request reset
      await page.goto('/forgot-password');
      
      await page.fill('input[name="email"]', 'reset@example.com');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Reset email sent')).toBeVisible();
      
      // Check email was sent
      const emailService = require('../../src/services/EmailService');
      expect(emailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        'reset@example.com',
        expect.any(String)
      );
      
      // Extract reset token from mocked email
      const resetToken = emailService.sendPasswordResetEmail.mock.calls[0][1];
      
      // Navigate to reset page with token
      await page.goto(`/reset-password?token=${resetToken}`);
      
      // Verify token is valid
      await expect(page.locator('text=Reset Your Password')).toBeVisible();
      await expect(page.locator('input[name="email"]')).toHaveValue('reset@example.com');
      
      // Set new password
      await page.fill('input[name="password"]', 'NewPassword456!');
      await page.fill('input[name="confirmPassword"]', 'NewPassword456!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Password reset successful')).toBeVisible();
      
      // Verify can login with new password
      await page.goto('/login');
      await page.fill('input[name="email"]', 'reset@example.com');
      await page.fill('input[name="password"]', 'NewPassword456!');
      await page.click('button[type="submit"]');
      
      await page.waitForURL('/dashboard');
    });
    
    test('invalid or expired reset token', async () => {
      await page.goto('/reset-password?token=invalid_token');
      
      await expect(page.locator('text=Invalid or expired reset token')).toBeVisible();
      await expect(page.locator('button[type="submit"]')).toBeDisabled();
    });
    
    test('password validation on reset', async () => {
      const emailService = require('../../src/services/EmailService');
      const resetToken = 'valid_reset_token';
      
      // Mock token validation
      jest.spyOn(require('../../src/services/AuthService').prototype, 'validateResetToken')
        .mockResolvedValue(true);
      
      await page.goto(`/reset-password?token=${resetToken}`);
      
      // Test weak password
      await page.fill('input[name="password"]', '123');
      await page.fill('input[name="confirmPassword"]', '123');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Password must be at least 8 characters')).toBeVisible();
      
      // Test mismatched passwords
      await page.fill('input[name="password"]', 'Password123!');
      await page.fill('input[name="confirmPassword"]', 'Different456!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Passwords do not match')).toBeVisible();
    });
  });
  
  describe('Email Verification', () => {
    test('verifies email with valid token', async () => {
      const user = await global.e2e.createUser({
        email: 'verify@example.com',
        password: 'hashed_password',
        name: 'Verify User',
        emailVerified: false,
        verificationToken: 'valid_verification_token'
      });
      
      await page.goto(`/verify-email?token=valid_verification_token`);
      
      await expect(page.locator('text=Email verified successfully')).toBeVisible();
      
      // User should now be verified
      const updatedUser = await global.e2e.getUser('verify@example.com');
      expect(updatedUser.emailVerified).toBe(true);
      expect(updatedUser.verificationToken).toBeNull();
    });
    
    test('handles invalid verification token', async () => {
      await page.goto('/verify-email?token=invalid_token');
      
      await expect(page.locator('text=Invalid verification token')).toBeVisible();
      await expect(page.locator('text=Request new verification email')).toBeVisible();
    });
    
    test('resends verification email', async () => {
      await global.e2e.createUser({
        email: 'resend@example.com',
        password: 'hashed_password',
        name: 'Resend User',
        emailVerified: false
      });
      
      await page.goto('/login');
      
      await page.fill('input[name="email"]', 'resend@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      // Should see verification required message
      await expect(page.locator('text=Resend verification email')).toBeVisible();
      
      // Click resend
      await page.click('text=Resend verification email');
      
      await expect(page.locator('text=Verification email sent')).toBeVisible();
      
      // Check email was sent
      const emailService = require('../../src/services/EmailService');
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        'resend@example.com',
        expect.any(String)
      );
    });
  });
  
  describe('Session Management', () => {
    test('maintains session across page navigation', async () => {
      await global.e2e.login();
      
      // Navigate to different pages
      await page.goto('/dashboard');
      await expect(page.locator('[data-testid="user-greeting"]')).toBeVisible();
      
      await page.goto('/profile');
      await expect(page.locator('h1:has-text("Profile")')).toBeVisible();
      
      await page.goto('/settings');
      await expect(page.locator('h1:has-text("Settings")')).toBeVisible();
      
      // Session should persist
      const cookies = await page.context().cookies();
      const authCookie = cookies.find(c => c.name === 'auth_token');
      expect(authCookie).toBeTruthy();
    });
    
    test('session timeout', async () => {
      await global.e2e.login();
      
      // Wait for session to expire (short timeout in test environment)
      await page.waitForTimeout(35000); // 35 seconds (test session timeout is 30s)
      
      // Try to access protected page
      await page.goto('/dashboard');
      
      // Should be redirected to login
      await page.waitForURL('/login');
      await expect(page.locator('text=Session expired')).toBeVisible();
    });
    
    test('logout clears session', async () => {
      await global.e2e.login();
      
      // Verify logged in
      await expect(page.locator('[data-testid="user-greeting"]')).toBeVisible();
      
      // Logout
      await page.click('[data-testid="user-menu"]');
      await page.click('text=Logout');
      
      await page.waitForURL('/login');
      
      // Verify session cleared
      const cookies = await page.context().cookies();
      const authCookie = cookies.find(c => c.name === 'auth_token');
      expect(authCookie).toBeUndefined();
      
      // Verify cannot access protected page
      await page.goto('/dashboard');
      await page.waitForURL('/login');
    });
    
    test('concurrent sessions on different devices', async () => {
      // Login from "device 1" (current browser context)
      await global.e2e.login();
      
      // Create second browser context (simulating different device)
      const context2 = await browser.newContext();
      const page2 = await context2.newPage();
      
      // Login from "device 2"
      await page2.goto('/login');
      await page2.fill('input[name="email"]', 'test@example.com');
      await page2.fill('input[name="password"]', 'Password123!');
      await page2.click('button[type="submit"]');
      await page2.waitForURL('/dashboard');
      
      // Both sessions should be active
      await expect(page.locator('[data-testid="user-greeting"]')).toBeVisible();
      await expect(page2.locator('[data-testid="user-greeting"]')).toBeVisible();
      
      // Logout from device 1
      await page.click('[data-testid="user-menu"]');
      await page.click('text=Logout');
      await page.waitForURL('/login');
      
      // Device 2 should still be logged in
      await page2.goto('/dashboard');
      await expect(page2.locator('[data-testid="user-greeting"]')).toBeVisible();
      
      await context2.close();
    });
  });
  
  describe('Security Tests', () => {
    test('XSS protection in login form', async () => {
      await page.goto('/login');
      
      // Attempt XSS in email field
      const xssPayload = '<script>alert("xss")</script>test@example.com';
      await page.fill('input[name="email"]', xssPayload);
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      // Should sanitize input, not execute script
      const emailValue = await page.inputValue('input[name="email"]');
      expect(emailValue).not.toContain('<script>');
      expect(emailValue).toContain('test@example.com');
    });
    
    test('CSRF protection', async () => {
      // Try to submit login form without CSRF token
      await page.goto('/login');
      
      // Remove CSRF token from page
      await page.evaluate(() => {
        document.querySelector('input[name="_csrf"]').remove();
      });
      
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('text=Invalid CSRF token')).toBeVisible();
    });
    
    test('password visibility toggle', async () => {
      await page.goto('/login');
      
      const passwordInput = page.locator('input[name="password"]');
      
      // Password should be hidden by default
      expect(await passwordInput.getAttribute('type')).toBe('password');
      
      // Click show password toggle
      await page.click('[data-testid="show-password"]');
      
      // Password should be visible
      expect(await passwordInput.getAttribute('type')).toBe('text');
      
      // Click again to hide
      await page.click('[data-testid="show-password"]');
      expect(await passwordInput.getAttribute('type')).toBe('password');
    });
    
    test('secure cookie attributes', async () => {
      await global.e2e.login();
      
      const cookies = await page.context().cookies();
      const authCookie = cookies.find(c => c.name === 'auth_token');
      
      expect(authCookie.httpOnly).toBe(true);
      expect(authCookie.secure).toBe(true); // In production
      expect(authCookie.sameSite).toBe('Strict');
    });
  });
  
  describe('Accessibility Tests', () => {
    test('login page is accessible', async () => {
      await page.goto('/login');
      
      const violations = await global.e2e.checkAccessibility();
      
      // Report violations
      if (violations.length > 0) {
        console.log('Accessibility violations found:', violations);
      }
      
      expect(violations.length).toBe(0);
    });
    
    test('keyboard navigation works', async () => {
      await page.goto('/login');
      
      // Tab through form elements
      await page.keyboard.press('Tab'); // Email field
      await page.fill('test@example.com');
      
      await page.keyboard.press('Tab'); // Password field
      await page.fill('Password123!');
      
      await page.keyboard.press('Tab'); // Remember me checkbox
      await page.keyboard.press('Space'); // Toggle checkbox
      
      await page.keyboard.press('Tab'); // Submit button
      await page.keyboard.press('Enter'); // Submit form
      
      await page.waitForURL('/dashboard');
    });
    
    test('screen reader labels', async () => {
      await page.goto('/login');
      
      // Check form labels
      const emailLabel = await page.getAttribute('input[name="email"]', 'aria-label');
      expect(emailLabel).toContain('Email');
      
      const passwordLabel = await page.getAttribute('input[name="password"]', 'aria-label');
      expect(passwordLabel).toContain('Password');
      
      // Check error messages have proper roles
      await page.click('button[type="submit"]'); // Submit empty form
      const errorMessage = page.locator('[role="alert"]');
      await expect(errorMessage).toBeVisible();
    });
  });
  
  describe('Performance Tests', () => {
    test('login page loads quickly', async () => {
      await page.goto('/login');
      
      const loadTime = await global.e2e.measurePageLoad();
      expect(loadTime).toBeLessThan(2000); // Should load in under 2 seconds
    });
    
    test('login request completes quickly', async () => {
      await page.goto('/login');
      
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', 'Password123!');
      
      const startTime = Date.now();
      await page.click('button[type="submit"]');
      await page.waitForURL('/dashboard');
      const loginTime = Date.now() - startTime;
      
      expect(loginTime).toBeLessThan(3000); // Login should complete in under 3 seconds
    });
  });
});

// tests/e2e/dashboard.test.js
const { page } = require('./setup-e2e');

describe('Dashboard E2E Tests', () => {
  beforeEach(async () => {
    // Login and navigate to dashboard
    await global.e2e.login();
    await page.goto('/dashboard');
  });
  
  describe('Dashboard Layout', () => {
    test('displays user information', async () => {
      await expect(page.locator('[data-testid="user-greeting"]')).toContainText('Test User');
      await expect(page.locator('[data-testid="user-email"]')).toContainText('test@example.com');
      await expect(page.locator('[data-testid="member-since"]')).toBeVisible();
    });
    
    test('shows navigation menu', async () => {
      const navItems = ['Dashboard', 'Profile', 'Settings', 'Billing', 'Help'];
      
      for (const item of navItems) {
        await expect(page.locator(`nav >> text=${item}`)).toBeVisible();
      }
    });
    
    test('responsive design works', async () => {
      // Test mobile view
      await page.setViewportSize({ width: 375, height: 667 });
      
      // Hamburger menu should be visible
      await expect(page.locator('[data-testid="mobile-menu-toggle"]')).toBeVisible();
      
      // Click hamburger menu
      await page.click('[data-testid="mobile-menu-toggle"]');
      
      // Navigation should be visible
      await expect(page.locator('nav')).toBeVisible();
      
      // Restore desktop view
      await page.setViewportSize({ width: 1280, height: 720 });
    });
  });
  
  describe('Dashboard Widgets', () => {
    test('loads and displays statistics', async () => {
      // Mock API response for statistics
      await global.e2e.interceptRequest('**/api/dashboard/stats', {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          totalUsers: 1500,
          activeUsers: 1250,
          revenue: 50000,
          growth: 15.5
        })
      });
      
      // Wait for stats to load
      await page.waitForSelector('[data-testid="stat-total-users"]');
      
      // Verify stats are displayed
      await expect(page.locator('[data-testid="stat-total-users"]')).toContainText('1,500');
      await expect(page.locator('[data-testid="stat-active-users"]')).toContainText('1,250');
      await expect(page.locator('[data-testid="stat-revenue"]')).toContainText('$50,000');
      await expect(page.locator('[data-testid="stat-growth"]')).toContainText('15.5%');
    });
    
    test('shows activity feed', async () => {
      // Mock activity feed
      await global.e2e.interceptRequest('**/api/dashboard/activity', {
        status: 200,
        body: JSON.stringify([
          { id: 1, action: 'User registered', timestamp: '2024-01-01T10:00:00Z' },
          { id: 2, action: 'Payment received', timestamp: '2024-01-01T09:30:00Z' },
          { id: 3, action: 'Support ticket opened', timestamp: '2024-01-01T09:00:00Z' }
        ])
      });
      
      await page.waitForSelector('[data-testid="activity-item"]');
      
      const activityItems = await page.locator('[data-testid="activity-item"]').count();
      expect(activityItems).toBe(3);
    });
    
    test('displays charts and graphs', async () => {
      // Check that chart containers are present
      await expect(page.locator('[data-testid="revenue-chart"]')).toBeVisible();
      await expect(page.locator('[data-testid="user-growth-chart"]')).toBeVisible();
      
      // Verify charts have loaded data
      await page.waitForFunction(() => {
        const chart = document.querySelector('[data-testid="revenue-chart"]');
        return chart && chart.getAttribute('data-loaded') === 'true';
      });
    });
    
    test('handles widget loading errors', async () => {
      // Mock failed API request
      await global.e2e.interceptRequest('**/api/dashboard/stats', {
        status: 500,
        body: JSON.stringify({ error: 'Internal server error' })
      });
      
      // Should show error state
      await expect(page.locator('[data-testid="stats-error"]')).toBeVisible();
      await expect(page.locator('text=Failed to load statistics')).toBeVisible();
      
      // Retry button should work
      await global.e2e.interceptRequest('**/api/dashboard/stats', {
        status: 200,
        body: JSON.stringify({ totalUsers: 1000 })
      });
      
      await page.click('[data-testid="retry-stats"]');
      await expect(page.locator('[data-testid="stat-total-users"]')).toContainText('1,000');
    });
  });
  
  describe('Real-time Updates', () => {
    test('updates dashboard in real-time', async () => {
      // Mock WebSocket connection
      await page.evaluate(() => {
        window.mockWebSocket = {
          send: jest.fn(),
          close: jest.fn(),
          onmessage: null
        };
        
        window.WebSocket = jest.fn(() => window.mockWebSocket);
      });
      
      // Simulate WebSocket message
      await page.evaluate(() => {
        if (window.mockWebSocket.onmessage) {
          window.mockWebSocket.onmessage({
            data: JSON.stringify({
              type: 'stats_update',
              data: { totalUsers: 1600 }
            })
          });
        }
      });
      
      // Dashboard should update
      await page.waitForSelector('[data-testid="stat-total-users"]:has-text("1,600")');
    });
    
    test('handles WebSocket disconnection', async () => {
      await page.evaluate(() => {
        window.WebSocket = class MockWebSocket {
          constructor() {
            setTimeout(() => {
              if (this.onclose) {
                this.onclose({ code: 1006, reason: 'Connection lost' });
              }
            }, 100);
          }
          
          send() {}
          close() {}
        };
      });
      
      // Should show connection status
      await expect(page.locator('[data-testid="connection-status"]')).toContainText('Reconnecting');
      
      // Should attempt to reconnect
      await page.waitForSelector('[data-testid="connection-status"]:has-text("Connected")', {
        timeout: 10000
      });
    });
  });
  
  describe('User Interactions', () => {
    test('search functionality works', async () => {
      const searchInput = page.locator('[data-testid="dashboard-search"]');
      
      // Type search query
      await searchInput.fill('test query');
      await searchInput.press('Enter');
      
      // Should show search results
      await expect(page.locator('[data-testid="search-results"]')).toBeVisible();
      
      // Clear search
      await page.click('[data-testid="clear-search"]');
      await expect(page.locator('[data-testid="search-results"]')).not.toBeVisible();
    });
    
    test('filter and sort controls work', async () => {
      // Open filter dropdown
      await page.click('[data-testid="filter-button"]');
      await expect(page.locator('[data-testid="filter-menu"]')).toBeVisible();
      
      // Apply filter
      await page.click('[data-testid="filter-active"]');
      await page.click('text=Apply Filters');
      
      // Should apply filter and reload data
      await page.waitForRequest('**/api/data?filter=active');
      
      // Test sorting
      await page.selectOption('[data-testid="sort-select"]', 'date_desc');
      await page.waitForRequest('**/api/data?sort=date_desc');
    });
    
    test('pagination works', async () => {
      // Mock paginated data
      await global.e2e.interceptRequest('**/api/data?page=1', {
        status: 200,
        body: JSON.stringify({
          data: Array(10).fill().map((_, i) => ({ id: i + 1 })),
          pagination: { page: 1, totalPages: 5, totalItems: 50 }
        })
      });
      
      // Go to next page
      await page.click('[data-testid="next-page"]');
      await page.waitForRequest('**/api/data?page=2');
      
      // Go to specific page
      await page.click('[data-testid="page-3"]');
      await page.waitForRequest('**/api/data?page=3');
      
      // Previous page
      await page.click('[data-testid="prev-page"]');
      await page.waitForRequest('**/api/data?page=2');
    });
    
    test('bulk actions work', async () => {
      // Select items
      await page.click('[data-testid="select-all"]');
      await expect(page.locator('[data-testid="selected-count"]')).toContainText('10 items selected');
      
      // Perform bulk action
      await page.click('[data-testid="bulk-actions"]');
      await page.click('text=Delete Selected');
      
      // Confirm dialog should appear
      await expect(page.locator('[role="dialog"]')).toBeVisible();
      await expect(page.locator('text=Are you sure?')).toBeVisible();
      
      // Confirm deletion
      await page.click('text=Confirm');
      
      // Should make bulk delete request
      await page.waitForRequest(request => 
        request.url().includes('/api/bulk/delete') && 
        request.method() === 'POST'
      );
    });
  });
  
  describe('Notifications', () => {
    test('displays notification bell', async () => {
      await expect(page.locator('[data-testid="notification-bell"]')).toBeVisible();
      
      // Check notification count
      const count = await page.locator('[data-testid="notification-count"]').textContent();
      expect(parseInt(count)).toBeGreaterThanOrEqual(0);
    });
    
    test('shows notification dropdown', async () => {
      // Click notification bell
      await page.click('[data-testid="notification-bell"]');
      await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();
      
      // Should show notifications
      const notifications = await page.locator('[data-testid="notification-item"]').count();
      expect(notifications).toBeGreaterThan(0);
      
      // Mark as read
      await page.click('[data-testid="mark-all-read"]');
      await expect(page.locator('[data-testid="notification-count"]')).toHaveText('0');
    });
    
    test('handles push notifications', async () => {
      // Mock Notification API
      await page.evaluate(() => {
        window.Notification = class MockNotification {
          constructor(title, options) {
            this.title = title;
            this.options = options;
          }
          
          static requestPermission = () => Promise.resolve('granted');
          static permission = 'granted';
        };
      });
      
      // Enable push notifications
      await page.click('[data-testid="enable-notifications"]');
      
      // Simulate push notification
      await page.evaluate(() => {
        if ('serviceWorker' in navigator) {
          navigator.serviceWorker.ready.then(registration => {
            registration.showNotification('New Message', {
              body: 'You have a new message',
              icon: '/icon.png'
            });
          });
        }
      });
      
      // Should show notification
      await expect(page.locator('[data-testid="notification-bell"]')).toHaveAttribute('data-has-new', 'true');
    });
  });
  
  describe('Performance Monitoring', () => {
    test('tracks dashboard performance metrics', async () => {
      // Navigate through dashboard
      const startTime = Date.now();
      
      await page.goto('/dashboard');
      await page.waitForLoadState('networkidle');
      
      const loadTime = Date.now() - startTime;
      
      // Log performance metrics
      console.log(`Dashboard load time: ${loadTime}ms`);
      
      // Should meet performance budget
      expect(loadTime).toBeLessThan(3000);
      
      // Check Core Web Vitals
      const metrics = await page.evaluate(() => {
        if (window.performance && window.performance.getEntriesByType) {
          const paintEntries = window.performance.getEntriesByType('paint');
          const navigationEntries = window.performance.getEntriesByType('navigation');
          
          return {
            fcp: paintEntries.find(e => e.name === 'first-contentful-paint')?.startTime,
            lcp: window.largestContentfulPaint,
            fid: window.firstInputDelay,
            cls: window.cumulativeLayoutShift
          };
        }
        return {};
      });
      
      console.log('Performance metrics:', metrics);
      
      // Verify metrics are within acceptable ranges
      if (metrics.fcp) expect(metrics.fcp).toBeLessThan(2000);
      if (metrics.lcp) expect(metrics.lcp).toBeLessThan(2500);
      if (metrics.fid) expect(metrics.fid).toBeLessThan(100);
      if (metrics.cls) expect(metrics.cls).toBeLessThan(0.1);
    });
    
    test('monitors memory usage', async () => {
      // Get initial memory usage
      const initialMemory = await page.evaluate(() => {
        return window.performance.memory ? window.performance.memory.usedJSHeapSize : null;
      });
      
      // Perform memory-intensive operation
      await page.click('[data-testid="load-large-data"]');
      await page.waitForTimeout(1000);
      
      // Get memory usage after operation
      const finalMemory = await page.evaluate(() => {
        return window.performance.memory ? window.performance.memory.usedJSHeapSize : null;
      });
      
      if (initialMemory && finalMemory) {
        const memoryIncrease = finalMemory - initialMemory;
        console.log(`Memory increase: ${Math.round(memoryIncrease / 1024 / 1024)}MB`);
        
        // Should not leak memory
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB
      }
    });
  });
  
  describe('Error Handling', () => {
    test('handles network errors gracefully', async () => {
      // Simulate network offline
      await page.context().setOffline(true);
      
      // Try to refresh dashboard
      await page.reload();
      
      // Should show offline message
      await expect(page.locator('text=You are offline')).toBeVisible();
      await expect(page.locator('[data-testid="retry-connection"]')).toBeVisible();
      
      // Go back online
      await page.context().setOffline(false);
      
      // Retry connection
      await page.click('[data-testid="retry-connection"]');
      await page.waitForURL('/dashboard');
    });
    
    test('shows error boundaries for React components', async () => {
      // Force a React component to error
      await page.evaluate(() => {
        const faultyComponent = document.querySelector('[data-testid="faulty-widget"]');
        if (faultyComponent) {
          faultyComponent.dispatchEvent(new CustomEvent('error', {
            detail: { message: 'Component crashed' }
          }));
        }
      });
      
      // Should show error boundary
      await expect(page.locator('[data-testid="error-boundary"]')).toBeVisible();
      await expect(page.locator('text=Something went wrong')).toBeVisible();
      
      // Can recover from error
      await page.click('[data-testid="recover-error"]');
      await expect(page.locator('[data-testid="error-boundary"]')).not.toBeVisible();
    });
    
    test('handles API timeouts', async () => {
      // Mock slow API response
      await global.e2e.interceptRequest('**/api/slow-endpoint', async () => {
        await new Promise(resolve => setTimeout(resolve, 10000)); // 10 second delay
        return { status: 200, body: '{}' };
      });
      
      // Trigger slow request
      await page.click('[data-testid="load-slow-data"]');
      
      // Should show loading indicator
      await expect(page.locator('[data-testid="loading-indicator"]')).toBeVisible();
      
      // Should timeout and show error
      await page.waitForSelector('[data-testid="timeout-error"]', { timeout: 6000 });
      await expect(page.locator('text=Request timed out')).toBeVisible();
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between E2E testing and integration testing? When should you use each?"
2. "How do you handle test data setup and teardown in E2E tests?"
3. "What strategies do you use to make E2E tests reliable and less flaky?"

**Scenario-Based Questions:**
1. "Your E2E tests are taking too long to run. How would you optimize them?"
2. "You need to test a feature that depends on real-time data from third-party APIs. How would you approach E2E testing?"
3. "Your E2E tests are failing randomly due to timing issues. How would you debug and fix them?"

**Real-World Challenge:**
> "Design an E2E testing strategy for an online banking application that: 1) Handles user registration and KYC verification, 2) Processes deposits and withdrawals, 3) Supports bill payments and transfers, 4) Generates account statements, 5) Implements two-factor authentication, 6) Has admin dashboard for fraud monitoring. Include tests for: User flows, security features, performance under load, mobile responsiveness, and accessibility compliance."

---

## 7. Testing Best Practices <a name="testing-best-practices"></a>

### Comprehensive Testing Strategy

```javascript
// tests/best-practices/strategies.test.js
describe('Testing Best Practices and Strategies', () => {
  describe('Test Pyramid Implementation', () => {
    // Unit Tests (Foundation - 70%)
    test('unit tests are fast and isolated', () => {
      // Characteristics of good unit tests:
      // - Run in milliseconds
      // - No external dependencies
      // - Test single unit of code
      // - Mock all external services
      
      const service = {
        calculateTotal: (items) => {
          return items.reduce((sum, item) => sum + item.price * item.quantity, 0);
        }
      };
      
      // Fast: executes in < 1ms
      const start = performance.now();
      const total = service.calculateTotal([
        { price: 10, quantity: 2 },
        { price: 5, quantity: 3 }
      ]);
      const duration = performance.now() - start;
      
      expect(total).toBe(35);
      expect(duration).toBeLessThan(10); // < 10ms
    });
    
    // Integration Tests (Middle Layer - 20%)
    test('integration tests verify component interactions', async () => {
      // Characteristics of good integration tests:
      // - Test interactions between 2-3 components
      // - Use real databases in test environment
      // - Mock external APIs
      // - Run in seconds
      
      const start = Date.now();
      
      // Integration test example (simplified)
      const userService = new UserService();
      const authService = new AuthService();
      
      // Create user
      const user = await userService.createUser({
        email: 'test@example.com',
        password: 'Password123!'
      });
      
      // Authenticate user
      const token = await authService.login({
        email: 'test@example.com',
        password: 'Password123!'
      });
      
      // Verify integration
      expect(user.email).toBe('test@example.com');
      expect(token).toBeTruthy();
      
      const duration = Date.now() - start;
      expect(duration).toBeLessThan(5000); // < 5 seconds
    });
    
    // E2E Tests (Top Layer - 10%)
    test('e2e tests simulate real user scenarios', async () => {
      // Characteristics of good E2E tests:
      // - Test complete user flows
      // - Use real browsers and services
      // - Run in minutes
      // - Focus on critical paths
      
      const start = Date.now();
      
      // Example E2E test steps:
      // 1. User visits website
      // 2. User registers account
      // 3. User completes onboarding
      // 4. User performs main action
      // 5. User receives confirmation
      
      const duration = Date.now() - start;
      expect(duration).toBeLessThan(30000); // < 30 seconds
    });
  });
  
  describe('Test Organization and Structure', () => {
    test('tests follow consistent naming conventions', () => {
      // Good naming patterns:
      // - Unit tests: describe('ClassName', () => { ... })
      // - Method tests: describe('#methodName', () => { ... })
      // - Scenario tests: describe('when [condition]', () => { ... })
      // - Test names: should [expected behavior] when [condition]
      
      describe('UserService', () => {
        describe('#createUser', () => {
          describe('when email is valid', () => {
            test('should create user and return user object', () => {});
            test('should send welcome email', () => {});
          });
          
          describe('when email is invalid', () => {
            test('should throw ValidationError', () => {});
          });
        });
      });
    });
    
    test('tests are organized by feature and type', () => {
      // Recommended project structure:
      /*
      tests/
      ├── unit/                    # Unit tests (70%)
      │   ├── services/           # Service layer tests
      │   ├── controllers/        # Controller tests
      │   ├── models/             # Model tests
      │   └── utils/              # Utility function tests
      │
      ├── integration/            # Integration tests (20%)
      │   ├── api/               # API integration tests
      │   ├── database/          # Database integration tests
      │   └── third-party/       # Third-party service tests
      │
      ├── e2e/                    # End-to-end tests (10%)
      │   ├── auth/              # Authentication flows
      │   ├── dashboard/         # Dashboard flows
      │   └── checkout/          # Checkout flows
      │
      ├── fixtures/               # Test data fixtures
      ├── mocks/                  # Mock implementations
      └── setup/                  # Test setup utilities
      */
    });
  });
  
  describe('Test Data Management', () => {
    test('uses factory functions for test data', () => {
      // Instead of inline test data:
      const badUserData = {
        id: 1,
        email: 'test@example.com',
        name: 'Test User',
        // ... 20 more fields
      };
      
      // Use factory functions:
      const createUser = (overrides = {}) => ({
        id: 1,
        email: 'test@example.com',
        name: 'Test User',
        role: 'user',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        ...overrides
      });
      
      // Usage in tests:
      const activeUser = createUser({ status: 'active' });
      const adminUser = createUser({ role: 'admin' });
      const suspendedUser = createUser({ status: 'suspended' });
    });
    
    test('manages test data lifecycle properly', async () => {
      // Setup: Create test data
      const testUser = await createTestUser();
      const testProduct = await createTestProduct();
      
      // Test: Use test data
      const order = await createOrder(testUser.id, testProduct.id);
      expect(order.userId).toBe(testUser.id);
      
      // Teardown: Clean up test data
      await cleanupTestData();
      
      // Verify cleanup
      const userExists = await userExists(testUser.id);
      expect(userExists).toBe(false);
    });
    
    test('uses data builders for complex objects', () => {
      class UserBuilder {
        constructor() {
          this.user = {
            id: 1,
            email: 'user@example.com',
            name: 'User',
            profile: {
              bio: 'Default bio',
              website: 'https://example.com'
            },
            preferences: {
              emailNotifications: true,
              smsNotifications: false
            }
          };
        }
        
        withEmail(email) {
          this.user.email = email;
          return this;
        }
        
        asAdmin() {
          this.user.role = 'admin';
          this.user.permissions = ['read', 'write', 'delete'];
          return this;
        }
        
        withInactiveStatus() {
          this.user.status = 'inactive';
          this.user.lastActive = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          return this;
        }
        
        build() {
          return this.user;
        }
      }
      
      // Usage:
      const adminUser = new UserBuilder()
        .withEmail('admin@example.com')
        .asAdmin()
        .build();
      
      const inactiveUser = new UserBuilder()
        .withInactiveStatus()
        .build();
    });
  });
  
  describe('Test Performance Optimization', () => {
    test('avoids unnecessary beforeEach/afterEach', () => {
      // Bad: Repeated setup for each test
      describe('Service with expensive setup', () => {
        let expensiveResource;
        
        beforeEach(async () => {
          expensiveResource = await setupExpensiveResource(); // Runs before EACH test
        });
        
        afterEach(async () => {
          await cleanupExpensiveResource(); // Runs after EACH test
        });
        
        test('test 1', () => { /* uses expensiveResource */ });
        test('test 2', () => { /* uses expensiveResource */ });
        test('test 3', () => { /* uses expensiveResource */ });
      });
      
      // Good: Shared setup when possible
      describe('Service with shared setup', () => {
        let expensiveResource;
        
        beforeAll(async () => {
          expensiveResource = await setupExpensiveResource(); // Runs once before ALL tests
        });
        
        afterAll(async () => {
          await cleanupExpensiveResource(); // Runs once after ALL tests
        });
        
        test('test 1', () => { /* uses expensiveResource */ });
        test('test 2', () => { /* uses expensiveResource */ });
        test('test 3', () => { /* uses expensiveResource */ });
      });
    });
    
    test('parallelizes independent tests', () => {
      // Jest runs tests in parallel by default
      // Make sure tests are independent
      
      describe('Independent tests', () => {
        // These can run in parallel
        test('calculates total', () => {
          expect(calculateTotal([1, 2, 3])).toBe(6);
        });
        
        test('formats date', () => {
          expect(formatDate(new Date('2024-01-01'))).toBe('Jan 1, 2024');
        });
        
        test('validates email', () => {
          expect(validateEmail('test@example.com')).toBe(true);
        });
      });
      
      describe('Dependent tests', () => {
        let sharedState;
        
        beforeEach(() => {
          sharedState = initializeState(); // Required for all tests
        });
        
        // These must run sequentially
        test('step 1: initialize', () => {
          sharedState.value = 10;
        });
        
        test('step 2: process', () => {
          // Depends on step 1
          process(sharedState);
        });
        
        test('step 3: verify', () => {
          // Depends on step 2
          verifyResult(sharedState);
        });
      });
    });
    
    test('optimizes slow operations', () => {
      // Bad: Real network calls in unit tests
      test('fetches user from API', async () => {
        const user = await fetchUserFromAPI(123); // Network call!
        expect(user.name).toBe('John');
      });
      
      // Good: Mock network calls
      test('fetches user from API', async () => {
        // Mock the API call
        fetch.mockResolvedValue({
          json: () => Promise.resolve({ id: 123, name: 'John' })
        });
        
        const user = await fetchUser(123);
        expect(user.name).toBe('John');
      });
    });
  });
  
  describe('Test Quality Indicators', () => {
    test('tests are deterministic', () => {
      // Bad: Non-deterministic test
      test('generates random ID', () => {
        const id = generateRandomId();
        expect(id).toHaveLength(10); // May fail randomly
      });
      
      // Good: Deterministic test
      test('generates random ID', () => {
        // Mock Math.random for deterministic results
        const mockRandom = jest.spyOn(Math, 'random');
        mockRandom.mockReturnValue(0.5);
        
        const id = generateRandomId();
        expect(id).toBe('expected_id_based_on_0.5');
        
        mockRandom.mockRestore();
      });
    });
    
    test('tests fail fast with clear messages', () => {
      // Bad: Vague error message
      test('validates user', () => {
        const result = validateUser({});
        expect(result).toBe(false); // What failed?
      });
      
      // Good: Clear error messages
      test('validates user', () => {
        const result = validateUser({});
        
        expect(result).toEqual({
          valid: false,
          errors: [
            { field: 'email', message: 'Email is required' },
            { field: 'password', message: 'Password is required' }
          ]
        });
      });
    });
    
    test('tests avoid implementation details', () => {
      // Bad: Tests implementation details
      test('sorts users', () => {
        const users = sortUsers([...]);
        
        // Testing implementation detail
        expect(sortUsers).toHaveBeenCalledWith(expect.any(Array));
        expect(sortUsers.mock.calls[0][0]).toHaveLength(3);
        
        // Better: Test behavior
        expect(users[0].name).toBe('Alice');
        expect(users[1].name).toBe('Bob');
        expect(users[2].name).toBe('Charlie');
      });
    });
    
    test('tests cover edge cases', () => {
      describe('divide function', () => {
        test('divides positive numbers', () => {
          expect(divide(10, 2)).toBe(5);
        });
        
        test('divides negative numbers', () => {
          expect(divide(-10, 2)).toBe(-5);
        });
        
        test('handles division by zero', () => {
          expect(() => divide(10, 0)).toThrow('Cannot divide by zero');
        });
        
        test('handles very large numbers', () => {
          expect(divide(1e308, 2)).toBe(5e307);
        });
        
        test('handles very small numbers', () => {
          expect(divide(1e-308, 2)).toBe(5e-309);
        });
        
        test('handles decimal numbers', () => {
          expect(divide(1.5, 0.5)).toBe(3);
        });
      });
    });
  });
  
  describe('Test Maintenance', () => {
    test('tests are self-documenting', () => {
      // Use descriptive test names
      describe('ShoppingCart', () => {
        describe('#calculateTotal', () => {
          test('should return sum of item prices multiplied by quantities', () => {});
          
          test('should apply discount when discount code is valid', () => {});
          
          test('should include tax based on shipping address', () => {});
          
          test('should round to two decimal places', () => {});
        });
      });
    });
    
    test('tests avoid duplication with helpers', () => {
      // Bad: Duplicated test logic
      test('admin can delete user', () => {
        const admin = createUser({ role: 'admin' });
        const result = canDeleteUser(admin);
        expect(result).toBe(true);
      });
      
      test('moderator can delete user', () => {
        const moderator = createUser({ role: 'moderator' });
        const result = canDeleteUser(moderator);
        expect(result).toBe(true);
      });
      
      // Good: Use test helpers
      const testCanDeleteUser = (role, expected) => {
        test(`${role} can${expected ? '' : ' not'} delete user`, () => {
          const user = createUser({ role });
          expect(canDeleteUser(user)).toBe(expected);
        });
      };
      
      describe('user deletion permissions', () => {
        testCanDeleteUser('admin', true);
        testCanDeleteUser('moderator', true);
        testCanDeleteUser('user', false);
        testCanDeleteUser('guest', false);
      });
    });
    
    test('tests are regularly reviewed and updated', () => {
      // Establish test review process:
      // 1. Code review should include test review
      // 2. Regularly audit test coverage
      // 3. Remove obsolete tests
      // 4. Update tests when requirements change
      // 5. Monitor test execution times
    });
  });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the test pyramid and why is it important?"
2. "How do you measure test coverage and what metrics are most valuable?"
3. "What's the difference between black-box and white-box testing?"

**Scenario-Based Questions:**
1. "You join a project with no tests. How would you introduce testing and convince the team?"
2. "Your test suite takes 2 hours to run. How would you optimize it?"
3. "You have a flaky test that fails 10% of the time. How would you investigate and fix it?"

**Real-World Challenge:**
> "Design a testing strategy for a startup that: 1) Has limited resources, 2) Needs to move fast, 3) Has critical security requirements, 4) Plans to scale rapidly. Include: What to test first, testing tools and frameworks, CI/CD integration, and metrics to track testing effectiveness."

---

## 8. Testing Infrastructure <a name="testing-infrastructure"></a>

### Comprehensive Testing Infrastructure Setup

```javascript
// .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 0 * * 0' # Weekly full test run

jobs:
  # 1. Unit Tests (Fastest)
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [16.x, 18.x, 20.x]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v3
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run unit tests
      run: |
        npm run test:unit -- --coverage --maxWorkers=4
      env:
        NODE_ENV: test
        CI: true
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage/lcov.info
        flags: unittests
    
    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: unit-test-results-${{ matrix.node-version }}
        path: |
          test-results/
          coverage/
        retention-days: 30
  
  # 2. Integration Tests
  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    
    services:
      mongodb:
        image: mongo:6
        ports:
          - 27017:27017
        options: >-
          --health-cmd "mongosh --eval 'db.runCommand(\"ping\").ok'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js 18.x
      uses: actions/setup-node@v3
      with:
        node-version: 18.x
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Wait for MongoDB
      run: |
        timeout 30 bash -c 'until mongosh --host localhost --port 27017 --eval "db.runCommand(\"ping\").ok" > /dev/null; do sleep 1; done'
    
    - name: Wait for Redis
      run: |
        timeout 30 bash -c 'until redis-cli -h localhost -p 6379 ping | grep PONG; do sleep 1; done'
    
    - name: Run integration tests
      run: |
        npm run test:integration -- --runInBand --detectOpenHandles
      env:
        NODE_ENV: test
        CI: true
        MONGODB_URI: mongodb://localhost:27017/test
        REDIS_URL: redis://localhost:6379/0
    
    - name: Upload integration test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: integration-test-results
        path: test-results/
        retention-days: 30
  
  # 3. E2E Tests
  e2e-tests:
    name: E2E Tests
    runs-on: ubuntu-latest
    needs: integration-tests
    
    services:
      mongodb:
        image: mongo:6
        ports:
          - 27017:27017
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js 18.x
      uses: actions/setup-node@v3
      with:
        node-version: 18.x
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Install Playwright browsers
      run: npx playwright install --with-deps chromium
    
    - name: Build application
      run: npm run build
    
    - name: Start application
      run: |
        npm run start:test &
        sleep 10
        curl --retry 5 --retry-delay 5 --retry-connrefused http://localhost:3000/health
    
    - name: Run E2E tests
      run: |
        npm run test:e2e -- --workers=2
      env:
        NODE_ENV: test
        CI: true
        BASE_URL: http://localhost:3000
        MONGODB_URI: mongodb://localhost:27017/test_e2e
        REDIS_URL: redis://localhost:6379/1
    
    - name: Upload E2E test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: e2e-test-results
        path: |
          test-results/
          videos/
          screenshots/
        retention-days: 30
  
  # 4. Performance Tests
  performance-tests:
    name: Performance Tests
    runs-on: ubuntu-latest
    needs: e2e-tests
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js 18.x
      uses: actions/setup-node@v3
      with:
        node-version: 18.x
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Build application
      run: npm run build
    
    - name: Start application
      run: |
        npm run start:test &
        sleep 10
    
    - name: Run performance tests
      run: |
        npm run test:performance
      env:
        NODE_ENV: test
        CI: true
    
    - name: Upload performance test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: performance-test-results
        path: performance-results/
        retention-days: 30
  
  # 5. Security Tests
  security-tests:
    name: Security Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js 18.x
      uses: actions/setup-node@v3
      with:
        node-version: 18.x
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run security audit
      run: |
        npm audit --audit-level=high
        npx snyk test --severity-threshold=high
    
    - name: Run dependency check
      run: |
        npx depcheck
        npx npm-check-updates --doctor
    
    - name: Run static security analysis
      run: |
        npx eslint --config .eslintrc.security.js src/
        npx nodejsscan --directory src/
  
  # 6. Final Report
  test-report:
    name: Test Report
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests, e2e-tests, performance-tests, security-tests]
    if: always()
    
    steps:
    - name: Download all test results
      uses: actions/download-artifact@v3
    
    - name: Generate test report
      run: |
        # Generate HTML report from test results
        npx jest-html-reporter
        
        # Generate coverage report
        npx nyc report --reporter=html
        
        # Combine reports
        cat unit-test-results-*/summary.json integration-test-results/summary.json e2e-test-results/summary.json > combined-results.json
    
    - name: Upload test report
      uses: actions/upload-artifact@v3
      with:
        name: comprehensive-test-report
        path: |
          test-report.html
          coverage/
          combined-results.json
        retention-days: 90
    
    - name: Send notification
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#ci-cd'
        username: 'Test Bot'
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Testing Configuration Files

```javascript
// package.json testing scripts
{
  "scripts": {
    // Development
    "test": "npm run test:unit",
    "test:watch": "jest --watch",
    "test:debug": "node --inspect-brk node_modules/.bin/jest --runInBand",
    
    // Unit Tests
    "test:unit": "jest tests/unit --passWithNoTests",
    "test:unit:coverage": "jest tests/unit --coverage",
    "test:unit:watch": "jest tests/unit --watch",
    
    // Integration Tests
    "test:integration": "jest tests/integration --runInBand --detectOpenHandles",
    "test:integration:db": "jest tests/integration/database.test.js",
    "test:integration:api": "jest tests/integration/api.test.js",
    
    // E2E Tests
    "test:e2e": "jest tests/e2e --config=jest.e2e.config.js",
    "test:e2e:auth": "jest tests/e2e/authentication.test.js",
    "test:e2e:dashboard": "jest tests/e2e/dashboard.test.js",
    "test:e2e:ci": "jest tests/e2e --config=jest.e2e.config.js --maxWorkers=2 --retryTimes=3",
    
    // Performance Tests
    "test:performance": "artillery run tests/performance/scenarios.yml",
    "test:load": "k6 run tests/performance/load-test.js",
    "test:stress": "artillery run tests/performance/stress-test.yml",
    
    // Security Tests
    "test:security": "npm run test:security:audit && npm run test:security:scan",
    "test:security:audit": "npm audit --audit-level=high",
    "test:security:scan": "npx snyk test --severity-threshold=high",
    
    // Mutation Testing
    "test:mutation": "stryker run",
    
    // Code Quality
    "lint": "eslint src/ tests/",
    "lint:fix": "eslint src/ tests/ --fix",
    "type-check": "tsc --noEmit",
    
    // Build and Start
    "build": "npm run clean && tsc",
    "start": "node dist/index.js",
    "start:dev": "nodemon src/index.js",
    "start:test": "NODE_ENV=test node src/index.js",
    
    // Cleanup
    "clean": "rimraf dist coverage .nyc_output",
    "clean:all": "npm run clean && rimraf node_modules"
  }
}

// jest.config.js
module.exports = {
  projects: [
    {
      displayName: 'unit',
      testMatch: ['**/tests/unit/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/tests/setup-unit.js'],
      testEnvironment: 'node',
      coverageDirectory: 'coverage/unit',
      collectCoverageFrom: ['src/**/*.js', '!src/**/*.test.js']
    },
    {
      displayName: 'integration',
      testMatch: ['**/tests/integration/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/tests/setup-integration.js'],
      testEnvironment: 'node',
      globalSetup: '<rootDir>/tests/setup-integration-global.js',
      globalTeardown: '<rootDir>/tests/teardown-integration-global.js',
      testTimeout: 30000,
      coverageDirectory: 'coverage/integration'
    }
  ],
  
  // Common configuration
  verbose: true,
  testTimeout: 10000,
  bail: false,
  maxConcurrency: 5,
  maxWorkers: '50%',
  
  // Reporting
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'test-results',
      outputName: 'junit.xml'
    }],
    ['jest-html-reporter', {
      pageTitle: 'Test Report',
      outputPath: 'test-report.html',
      includeFailureMsg: true,
      includeConsoleLog: true
    }]
  ],
  
  // Watch mode
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname'
  ],
  
  // Module handling
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@test/(.*)$': '<rootDir>/tests/$1'
  }
};

// jest.e2e.config.js
module.exports = {
  displayName: 'E2E',
  testMatch: ['**/tests/e2e/**/*.test.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup-e2e.js'],
  globalSetup: '<rootDir>/tests/setup-e2e-global.js',
  globalTeardown: '<rootDir>/tests/teardown-e2e-global.js',
  testEnvironment: '<rootDir>/tests/e2e-environment.js',
  
  // E2E specific settings
  testTimeout: 60000,
  maxConcurrency: 2,
  maxWorkers: 2,
  retryTimes: process.env.CI ? 3 : 0,
  
  // Reporting
  reporters: [
    'default',
    ['jest-html-reporter', {
      outputPath: 'e2e-test-report.html',
      pageTitle: 'E2E Test Report',
      includeFailureMsg: true,
      includeConsoleLog: true,
      includeSuiteFailure: true
    }]
  ],
  
  // Visual testing
  snapshotSerializers: ['jest-serializer-html']
};

// tests/setup-unit.js
// Unit test setup
const jestExtended = require('jest-extended');
expect.extend(jestExtended);

// Custom matchers
expect.extend({
  toBeValidEmail(received) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const pass = emailRegex.test(received);
    
    return {
      message: () => `expected ${received} ${pass ? 'not to be' : 'to be'} a valid email`,
      pass
    };
  },
  
  async toResolveWith(received, expected) {
    try {
      const result = await received;
      const pass = this.equals(result, expected);
      
      return {
        message: () => `expected promise to ${pass ? 'not resolve' : 'resolve'} with ${expected}`,
        pass
      };
    } catch (error) {
      return {
        message: () => `expected promise to resolve but it rejected with ${error.message}`,
        pass: false
      };
    }
  }
});

// Global test utilities
global.createTestUser = (overrides = {}) => ({
  id: 'test_user_id',
  email: 'test@example.com',
  name: 'Test User',
  role: 'user',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides
});

global.createTestProduct = (overrides = {}) => ({
  id: 'test_product_id',
  name: 'Test Product',
  price: 100,
  stock: 10,
  category: 'electronics',
  ...overrides
});

// Mock console methods in tests
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn()
};

// tests/setup-integration-global.js
// Global integration test setup
module.exports = async () => {
  console.log('🚀 Starting integration test environment...');
  
  // Start test databases
  const { MongoMemoryServer } = require('mongodb-memory-server');
  const Redis = require('ioredis');
  
  // MongoDB
  global.__MONGOD__ = await MongoMemoryServer.create();
  process.env.MONGODB_URI = global.__MONGOD__.getUri();
  
  // Redis
  global.__REDIS__ = new Redis({
    host: 'localhost',
    port: 6379,
    db: 15, // Use high DB number for tests
    lazyConnect: true
  });
  
  await global.__REDIS__.connect();
  
  // Wait for connections
  await Promise.all([
    waitForMongo(),
    waitForRedis()
  ]);
  
  console.log('✅ Integration test environment ready');
};

async function waitForMongo() {
  const mongoose = require('mongoose');
  let attempts = 0;
  
  while (attempts < 10) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 1000
      });
      return;
    } catch (error) {
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  throw new Error('Failed to connect to MongoDB');
}

async function waitForRedis() {
  let attempts = 0;
  
  while (attempts < 10) {
    try {
      await global.__REDIS__.ping();
      return;
    } catch (error) {
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  throw new Error('Failed to connect to Redis');
}

// tests/teardown-integration-global.js
module.exports = async () => {
  console.log('🧹 Cleaning up integration test environment...');
  
  // Close database connections
  const mongoose = require('mongoose');
  
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  
  // Stop MongoDB memory server
  if (global.__MONGOD__) {
    await global.__MONGOD__.stop();
  }
  
  // Close Redis connection
  if (global.__REDIS__) {
    await global.__REDIS__.quit();
  }
  
  console.log('✅ Integration test environment cleaned up');
};

// tests/e2e-environment.js
// Custom Playwright test environment
const NodeEnvironment = require('jest-environment-node');
const { chromium } = require('playwright');

class PlaywrightEnvironment extends NodeEnvironment {
  constructor(config, context) {
    super(config, context);
    this.testPath = context.testPath;
  }
  
  async setup() {
    await super.setup();
    
    // Launch browser
    this.browser = await chromium.launch({
      headless: process.env.CI ? true : false,
      slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    // Create context
    this.context = await this.browser.newContext({
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true,
      recordVideo: process.env.RECORD_VIDEO ? { dir: 'videos/' } : undefined
    });
    
    // Create page
    this.page = await this.context.newPage();
    
    // Expose to global scope
    this.global.browser = this.browser;
    this.global.context = this.context;
    this.global.page = this.page;
    
    // Custom utilities
    this.global.$ = (selector) => this.page.locator(selector);
    this.global.$$ = (selector) => this.page.locator(selector);
    
    // Navigation helper
    this.global.navigate = async (path) => {
      const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
      await this.page.goto(`${baseUrl}${path}`);
    };
  }
  
  async teardown() {
    // Take screenshot on failure
    if (this.currentTest && this.currentTest.status === 'failed') {
      const testName = this.currentTest.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
      await this.page.screenshot({
        path: `screenshots/failed-${testName}.png`,
        fullPage: true
      });
    }
    
    // Close browser
    if (this.browser) {
      await this.browser.close();
    }
    
    await super.teardown();
  }
  
  getVmContext() {
    return super.getVmContext();
  }
}

module.exports = PlaywrightEnvironment;
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How would you set up a CI/CD pipeline for a Node.js application with comprehensive testing?"
2. "What tools would you use for test reporting and monitoring in a large codebase?"
3. "How do you handle database migrations in your test environments?"

**Scenario-Based Questions:**
1. "You need to run tests for multiple microservices. How would you orchestrate the test infrastructure?"
2. "Your tests are failing randomly in CI but work locally. How would you debug this?"
3. "You have a monolith that you're breaking into microservices. How would you evolve your testing strategy?"

**Real-World Challenge:**
> "Design a testing infrastructure for a fintech startup that: 1) Has 10+ microservices, 2) Needs to pass security audits, 3) Must have 99.99% uptime, 4) Processes millions of transactions daily. Include: CI/CD pipeline design, test environment management, monitoring and alerting, disaster recovery testing, and compliance testing."

---

## 📊 Testing Metrics Dashboard

| Metric | Target | Measurement | Tool |
|--------|---------|-------------|------|
| Unit Test Coverage | > 80% | Lines, branches, functions | Jest, Istanbul |
| Integration Test Coverage | > 70% | API endpoints, DB operations | Supertest, Coverage |
| E2E Test Pass Rate | > 95% | Critical user journeys | Playwright, Cypress |
| Test Execution Time | < 10 min | Full test suite | CI/CD pipeline |
| Flaky Test Rate | < 1% | Tests failing intermittently | Test analytics |
| Code Quality | A Grade | Static analysis | ESLint, SonarQube |
| Security Vulnerabilities | 0 High | Dependency scanning | Snyk, npm audit |
| Performance Benchmarks | < 2s | Page load, API response | Lighthouse, k6 |

---

## 🎓 Interview Preparation Tips

1. **Understand testing fundamentals**: Know the differences between unit, integration, and E2E testing
2. **Practice test writing**: Write tests for different scenarios and edge cases
3. **Learn testing tools**: Master Jest, Supertest, Playwright/Cypress
4. **Study testing patterns**: Learn about test doubles, test data management, and test organization
5. **Know CI/CD integration**: Understand how to integrate tests into deployment pipelines
6. **Focus on quality**: Learn about test metrics, coverage analysis, and quality gates

---

*Last updated: December 2025*  
*Remember: Testing is not about finding bugs, but about preventing them. A well-tested application is a reliable application.*